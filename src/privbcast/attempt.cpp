// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/attempt.h>

#include <compat/compat.h>
#include <logging.h>
#include <net_transport.h>
#include <netbase.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <random.h>
#include <tinyformat.h>
#include <util/sock.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <deque>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <utility>

namespace privbcast {

using namespace std::chrono_literals;

namespace {

bool IsTransientSocketError(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEMSGSIZE || err == WSAEINTR || err == WSAEINPROGRESS;
}

} // namespace

Connector TorConnector(const Proxy& tor, const Candidate& candidate, Socks5Params socks)
{
    return [tor, candidate, socks = std::move(socks)](bool& proxy_failed) mutable {
        socks.auth = FreshIsolationCredentials();
        return ConnectThroughProxy(tor, candidate.addr.ToStringAddr(), candidate.addr.GetPort(), proxy_failed,
                                   /*require_auth=*/true, socks);
    };
}

void RunSession(Sock& sock, Transport& transport, Session& session, AttemptResult& result,
                SteadyClock::time_point hard_deadline, const std::function<bool()>& interrupted)
{
    std::deque<CSerializedNetMsg> queue;
    uint8_t buf[0x4000];

    // Send whatever the session has queued and the transport can currently emit. Reports each
    // message's handover to the transport and its completion to the session. Never blocks.
    // Every handover and send is gated on the same termination conditions as message dispatch:
    // the session's phase deadline, the attempt's hard deadline and interruption. Returns
    // false once the session has been finished here, so the caller stops dispatching.
    const auto pump_send = [&]() -> bool {
        while (!session.Finished()) {
            const auto now{SteadyClock::now()};
            if (now >= hard_deadline) {
                session.Fail("attempt deadline");
                return false;
            }
            if (interrupted()) {
                session.Fail("interrupted");
                return false;
            }
            session.OnTick(now); // an expired phase deadline ends the attempt before any handover
            if (session.Finished()) return false;
            for (auto& msg : session.TakeOutbound()) queue.push_back(std::move(msg));
            if (!queue.empty()) {
                const std::string type{queue.front().m_type};
                if (transport.SetMessageToSend(queue.front())) {
                    queue.pop_front();
                    session.OnMessageHandedToTransport(type, SteadyClock::now()); // the moment of acceptance
                    if (session.Finished()) return false;
                }
            }
            const auto [data, more, type_ref] = transport.GetBytesToSend(/*have_next_message=*/!queue.empty());
            if (data.empty()) return true;
            const std::string type{type_ref};
            const ssize_t n{sock.Send(data.data(), data.size(), MSG_NOSIGNAL | MSG_DONTWAIT)};
            if (n > 0) {
                result.bytes_sent += n;
                const bool span_done{static_cast<size_t>(n) == data.size()};
                transport.MarkBytesSent(n);
                if (span_done && !type.empty()) {
                    // A message is complete when the transport has no more bytes for it: v1 hands
                    // out the header and the payload as separate spans of the same type.
                    const auto [next, next_more, next_type] = transport.GetBytesToSend(!queue.empty());
                    if (next.empty() || std::string{next_type} != type) {
                        session.OnMessageWritten(type, SteadyClock::now());
                    }
                }
                if (!span_done) return true; // socket buffer full for now
            } else {
                if (n < 0 && !IsTransientSocketError(WSAGetLastError())) {
                    session.Fail(strprintf("send: %s", NetworkErrorString(WSAGetLastError())));
                    return false;
                }
                return true;
            }
        }
        return true;
    };

    // Poll the socket non-blocking rather than Sock::Wait(): the mock socket used in tests
    // implements Wait() in a way that is unsafe for a caller-owned socket, and the poll cost
    // over one attempt's lifetime is negligible.
    while (!session.Finished()) {
        const auto now{SteadyClock::now()};
        if (now >= hard_deadline) {
            session.Fail("attempt deadline");
            break;
        }
        if (interrupted()) {
            session.Fail("interrupted");
            break;
        }
        session.OnTick(now);
        if (session.Finished()) break;
        if (!pump_send() || session.Finished()) break;

        const ssize_t n{sock.Recv(buf, sizeof(buf), MSG_DONTWAIT)};
        if (n > 0) {
            result.bytes_recv += n;
            if (result.bytes_recv > wire::MAX_RECV_BYTES) {
                session.Fail("receive cap");
                break;
            }
            std::span<const uint8_t> bytes{buf, static_cast<size_t>(n)};
            bool fatal{false};
            while (!bytes.empty() && !session.Finished()) {
                if (!transport.ReceivedBytes(bytes)) {
                    session.Fail("transport error");
                    fatal = true;
                    break;
                }
                if (transport.ReceivedMessageComplete()) {
                    bool reject{false};
                    CNetMessage msg{transport.GetReceivedMessage(NodeClock::now(), reject)};
                    // The same termination gate as for sending, immediately before dispatch: a
                    // message decoded after the hard deadline or a cancellation is not acted on.
                    const auto dispatch_now{SteadyClock::now()};
                    if (dispatch_now >= hard_deadline) {
                        session.Fail("attempt deadline");
                        fatal = true;
                        break;
                    }
                    if (interrupted()) {
                        session.Fail("interrupted");
                        fatal = true;
                        break;
                    }
                    if (!reject) session.OnMessage(msg.m_type, msg.m_recv, dispatch_now);
                    // Send any reply now so message order does not depend on how the peer batches bytes.
                    if (!pump_send()) {
                        fatal = true;
                        break;
                    }
                }
            }
            if (fatal) break;
        } else if (n == 0) {
            session.Fail("peer closed");
            break;
        } else if (!IsTransientSocketError(WSAGetLastError())) {
            session.Fail(strprintf("recv: %s", NetworkErrorString(WSAGetLastError())));
            break;
        } else {
            std::this_thread::sleep_for(10ms);
        }
    }
    // Nothing is flushed after the attempt has ended: a finished session sends no more bytes.
}

std::optional<AttemptResult> RunAttempt(const Connector& connect, const Candidate& candidate, const CTransactionRef& tx,
                                        SteadyClock::time_point scheduled_start, SteadyClock::time_point dial_deadline,
                                        SteadyClock::time_point hard_deadline, const std::function<bool()>& interrupted,
                                        CTransactionRef parent)
{
    AttemptResult result;
    result.candidate = candidate;
    result.scheduled_start = scheduled_start;

    FastRandomContext rng;
    Session session{tx, scheduled_start, rng, std::move(parent)};
    const auto handshake_deadline{session.Deadline()};

    // Everything is prepared. The last step before the dial: not if the job is cancelled, not if
    // the opportunity's grace has passed. `started` is the very timestamp that decides it.
    result.started = SteadyClock::now();
    if (interrupted() || result.started > dial_deadline) return std::nullopt;

    bool proxy_failed{false};
    std::unique_ptr<Sock> sock{connect(proxy_failed)};
    if (!sock) {
        session.Fail(proxy_failed ? "proxy unreachable" : "socks connect failed");
    } else {
        result.connected = SteadyClock::now();
        if (*result.connected >= handshake_deadline) {
            // The proxy took the whole handshake budget; the schedule does not stretch for it.
            session.OnTick(*result.connected);
        } else if (interrupted()) {
            session.Fail("interrupted");
        } else {
            V2Transport transport{NodeId{0}, /*initiating=*/true};
            RunSession(*sock, transport, session, result, hard_deadline, interrupted);
        }
        sock.reset();
    }
    if (result.outcome == Outcome::PENDING) {
        result.outcome = session.GetOutcome();
        result.reason = session.Reason();
    }
    result.evidence = session.GetEvidence();
    result.ended = SteadyClock::now();
    LogDebug(BCLog::PRIVBROADCAST, "attempt to %s (%s): %s%s, sent=%u recv=%u\n",
             candidate.addr.ToStringAddrPort(), candidate.provenance, OutcomeName(result.outcome), result.reason.empty() ? "" : strprintf(" (%s)", result.reason),
             result.bytes_sent, result.bytes_recv);
    return result;
}

} // namespace privbcast
