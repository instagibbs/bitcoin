// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <crypto/common.h>
#include <key.h>
#include <net_transport.h>
#include <netaddress.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/params.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/privbcast.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace privbcast;
using std::chrono::milliseconds;

namespace {

CTransactionRef g_tx;

void initialize_privbcast_attempt()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{7}), 1});
    tx.vin[0].scriptWitness.stack.push_back({1, 2, 3});
    tx.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    g_tx = MakeTransactionRef(std::move(tx));
}

/** The recipient's transport, with its key and garbage drawn from rng. */
V2Transport MakeResponder(FastRandomContext& rng)
{
    CKey key;
    do {
        const uint256 secret{rng.rand256()};
        key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
    } while (!key.IsValid());
    const uint256 ent{rng.rand256()};
    std::vector<uint8_t> garbage{rng.randbytes(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1))};
    return V2Transport{NodeId{1}, /*initiating=*/false, key, MakeByteSpan(ent), std::move(garbage)};
}

/** Whether the attempt acts on messages of this type in some state (E2, E5, E6). It ignores any
 *  other in every state. */
bool ActedOn(const std::string& type)
{
    return type == NetMsgType::VERSION || type == NetMsgType::WTXIDRELAY || type == NetMsgType::VERACK ||
           type == NetMsgType::GETDATA || type == NetMsgType::PONG;
}

/** A VERSION from the peer, with these fields and null addresses. */
CSerializedNetMsg MakeVersion(int32_t version, uint64_t services, uint64_t nonce, const std::string& user_agent,
                              int32_t start_height, bool relay)
{
    return NetMsg::Make(NetMsgType::VERSION, version, services, int64_t{0},
                        uint64_t{NODE_NONE}, CNetAddr::V1(CService{}), services, CNetAddr::V1(CService{}),
                        nonce, user_agent, start_height, relay);
}

/** A message from the peer: the handshake, requests and PONGs, well formed or not, and others. */
CSerializedNetMsg ConsumeMessage(FuzzedDataProvider& provider, std::optional<uint64_t> ping_nonce)
{
    const uint256 wtxid{g_tx->GetWitnessHash().ToUint256()};
    CSerializedNetMsg msg;
    CallOneOf(
        provider,
        [&] {
            const int32_t version{provider.ConsumeBool() ? 70016 : provider.ConsumeIntegral<int32_t>()};
            const uint64_t services{provider.ConsumeBool() ? uint64_t{NODE_NETWORK | NODE_WITNESS} : provider.ConsumeIntegral<uint64_t>()};
            const uint64_t nonce{provider.ConsumeIntegral<uint64_t>()};
            const std::string user_agent{provider.ConsumeRandomLengthString(300)};
            const int32_t start_height{provider.ConsumeIntegral<int32_t>()};
            const bool relay{provider.ConsumeBool()};
            msg = MakeVersion(version, services, nonce, user_agent, start_height, relay);
            if (provider.ConsumeBool()) msg.data.resize(provider.ConsumeIntegralInRange<size_t>(0, msg.data.size()));
        },
        [&] { msg = NetMsg::Make(NetMsgType::WTXIDRELAY); },
        [&] { msg = NetMsg::Make(NetMsgType::VERACK); },
        [&] { msg = NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, wtxid}}); },
        [&] {
            std::vector<CInv> request;
            LIMITED_WHILE(provider.ConsumeBool(), 3) {
                const GetDataMsg type{provider.PickValueInArray({MSG_TX, MSG_WTX, MSG_WITNESS_TX, MSG_BLOCK})};
                request.emplace_back(type, provider.ConsumeBool() ? wtxid : ConsumeUInt256(provider));
            }
            msg = NetMsg::Make(NetMsgType::GETDATA, request);
        },
        [&] {
            msg = NetMsg::Make(NetMsgType::PONG, ping_nonce && !provider.ConsumeBool() ? *ping_nonce : provider.ConsumeIntegral<uint64_t>());
        },
        [&] {
            // At most 12 characters: the length of a message type.
            msg.m_type = provider.ConsumeBool() ? provider.PickValueInArray(ALL_NET_MESSAGE_TYPES) : provider.ConsumeRandomLengthString(12);
            msg.data = ConsumeRandomLengthByteVector(provider, 200);
        });
    return msg;
}

/** Check that a VERSION is the release profile's, field by field: only its nonce is free (E1). */
void CheckVersion(DataStream& payload)
{
    int32_t version{0};
    uint64_t services{0}, recv_services{0}, from_services{0}, nonce{0};
    int64_t time{0};
    CService recv, from;
    std::string user_agent;
    int32_t start_height{0};
    bool relay{false};
    payload >> version >> services >> time >> recv_services >> CNetAddr::V1(recv) >> from_services >> CNetAddr::V1(from) >> nonce >>
        LIMITED_STRING(user_agent, 256) >> start_height >> relay;
    assert(version == PROFILE_VERSION);
    assert(services == uint64_t{PROFILE_SERVICES});
    assert(time == 0);
    assert(recv_services == uint64_t{NODE_NONE} && recv == CService{});
    assert(from_services == uint64_t{PROFILE_SERVICES} && from == CService{});
    assert(user_agent == PROFILE_USER_AGENT);
    assert(start_height == 0 && !relay);
    assert(payload.empty());
}

/** The twins are alike in everything they offer, record and report, but for what the twin alone
 *  read. */
void CheckTwins(const Attempt& attempt, const Attempt& twin, uint64_t extra)
{
    assert(std::ranges::equal(attempt.BytesToSend(), twin.BytesToSend()));
    assert(attempt.BytesSent() == twin.BytesSent());
    assert(attempt.BytesRecv() + extra == twin.BytesRecv());
    assert(attempt.Ended() == twin.Ended());
    assert(attempt.GetOutcome() == twin.GetOutcome());
    assert(attempt.Reason() == twin.Reason());
    assert(attempt.Times() == twin.Times());
    assert(attempt.PeerVersion() == twin.PeerVersion());
    assert(attempt.PeerUserAgent() == twin.PeerUserAgent());
    assert(attempt.ExtraRequests() == twin.ExtraRequests());
    assert(attempt.NextDeadline() == twin.NextDeadline());
}

} // namespace

FUZZ_TARGET(privbcast_attempt, .init = initialize_privbcast_attempt)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    // A seed of eight bytes, so that a short input gets past the header.
    uint256 seed;
    WriteLE64(seed.begin(), provider.ConsumeIntegral<uint64_t>());
    const Timing timing{provider.ConsumeIntegralInRange<int>(1, MAX_TIME_DIVISOR)};
    milliseconds now{provider.ConsumeIntegralInRange<int64_t>(0, 600'000)};
    const milliseconds scheduled_start{now + milliseconds{provider.ConsumeIntegralInRange<int64_t>(-1'000, 1'000)}};
    // A2: twins, each with a generator of its own, seeded alike, and a key source that draws from
    // it. They get the same calls, with the same bytes at the same times, but for messages of types
    // the attempt acts on in no state, which the twin alone gets.
    FastRandomContext rng{seed}, twin_rng{seed};
    Attempt attempt{g_tx, scheduled_start, timing, rng, KeysFrom(rng), NodeId{0}};
    Attempt twin{g_tx, scheduled_start, timing, twin_rng, KeysFrom(twin_rng), NodeId{0}};
    // Their recipients, alike too.
    V2Transport peer(MakeResponder(rng));
    V2Transport twin_peer(MakeResponder(twin_rng));
    // What the recipients send next, and the requests among what they were given to send.
    std::deque<CSerializedNetMsg> peer_queue;
    std::vector<std::vector<CInv>> requests;
    // Bytes from elsewhere reached the attempts, so the recipients' transports may not share their
    // sessions.
    bool foreign_bytes{false};
    bool peer_failed{false};
    // What the twin read of the messages only it got. They count toward its receive cap (D3): past
    // it, the twin ends on its own.
    uint64_t extra{0};
    bool twin_capped{false};

    // What the recipient decoded of the attempt's bytes.
    const std::set<std::string> allowed{NetMsgType::VERSION, NetMsgType::WTXIDRELAY, NetMsgType::VERACK,
                                        NetMsgType::INV, NetMsgType::TX, NetMsgType::PING};
    std::map<std::string, int> count;
    std::optional<uint64_t> ping_nonce;
    std::optional<uint64_t> sent_at_end;

    // The attempt takes bytes only once the proxy connected it.
    const auto can_receive{[&] { return attempt.Times().connected || attempt.Ended(); }};

    // Only these messages, each at most once and in this order (E1-E7). Each is the release profile
    // byte for byte, but for the nonces of the VERSION and the PING.
    const auto check_message{[&](CNetMessage& msg) {
        const std::string& type{msg.m_type};
        assert(allowed.contains(type));
        assert(++count[type] == 1);
        const std::span<const uint8_t> payload{MakeUCharSpan(msg.m_recv)};
        if (type == NetMsgType::VERSION) CheckVersion(msg.m_recv);
        if (type == NetMsgType::WTXIDRELAY) assert(count[NetMsgType::VERSION] == 1 && payload.empty());
        if (type == NetMsgType::VERACK) assert(count[NetMsgType::WTXIDRELAY] == 1 && payload.empty());
        if (type == NetMsgType::INV) {
            assert(count[NetMsgType::VERACK] == 1);
            assert(std::ranges::equal(payload, NetMsg::Make(NetMsgType::INV, std::vector<CInv>{CInv{MSG_WTX, g_tx->GetWitnessHash().ToUint256()}}).data));
        }
        // No TX before the INV (E4), and only in answer to a request for it: a single-entry MSG_WTX
        // for the transaction (E5). The PING after the TX (E6).
        if (type == NetMsgType::TX) {
            assert(count[NetMsgType::INV] == 1);
            assert(std::ranges::equal(payload, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*g_tx)).data));
            assert(std::ranges::any_of(requests, [](const std::vector<CInv>& request) {
                return request.size() == 1 && request[0].IsMsgWtx() && request[0].hash == g_tx->GetWitnessHash().ToUint256();
            }));
        }
        if (type == NetMsgType::PING) {
            assert(count[NetMsgType::TX] == 1);
            assert(payload.size() == sizeof(uint64_t));
            uint64_t nonce{0};
            msg.m_recv >> nonce;
            ping_nonce = nonce;
        }
    }};
    // The recipient checks what it decoded. Unless the input opts out, it answers the attempt's
    // VERSION with a well-formed VERSION, WTXIDRELAY and VERACK (E2), so that little input gets past
    // the handshake. Everything else it sends comes from the input, and so does the handshake when
    // the input opts out.
    const auto recipient_reads{[&](CNetMessage& msg) {
        check_message(msg);
        if (msg.m_type != NetMsgType::VERSION || provider.ConsumeBool()) return;
        peer_queue.push_back(MakeVersion(MIN_PEER_PROTOCOL_VERSION, NODE_NETWORK | NODE_WITNESS, /*nonce=*/0, "/fuzz:0.1/",
                                         /*start_height=*/0, /*relay=*/true));
        peer_queue.push_back(NetMsg::Make(NetMsgType::WTXIDRELAY));
        peer_queue.push_back(NetMsg::Make(NetMsgType::VERACK));
    }};

    // A recipient decodes what its attempt wrote. False if it cannot.
    const auto decode{[](V2Transport& transport, std::span<const uint8_t> bytes, const auto& handle) {
        while (!bytes.empty()) {
            if (!transport.ReceivedBytes(bytes)) return false;
            if (!transport.ReceivedMessageComplete()) continue;
            bool reject{false};
            CNetMessage msg{transport.GetReceivedMessage({}, reject)};
            assert(!reject);
            handle(msg);
        }
        return true;
    }};

    // The attempts write up to budget bytes, message after message, as a socket takes them, and the
    // recipients decode them. Returns how many bytes were written.
    const auto attempts_write{[&](size_t budget) {
        size_t total{0};
        while (total < budget) {
            const std::span<const uint8_t> offered{attempt.BytesToSend()};
            if (!twin_capped) assert(std::ranges::equal(offered, twin.BytesToSend()));
            if (offered.empty()) break;
            const std::vector<uint8_t> written{offered.begin(), offered.begin() + std::min(budget - total, offered.size())};
            total += written.size();
            attempt.MarkSent(written.size(), now);
            if (!twin_capped) twin.MarkSent(written.size(), now);
            if (peer_failed) continue;
            const bool decoded{decode(peer, written, recipient_reads)};
            // The twin wrote the same bytes.
            assert(decode(twin_peer, written, [](const CNetMessage&) {}) == decoded);
            if (decoded) continue;
            // Only a session the recipient does not share can fail it.
            assert(foreign_bytes);
            peer_failed = true;
        }
        return total;
    }};
    // The recipients write up to budget bytes, message after message. Returns how many bytes were
    // written.
    const auto recipients_write{[&](size_t budget) {
        size_t total{0};
        if (peer_failed || !can_receive()) return total;
        while (total < budget) {
            if (!peer_queue.empty()) {
                CSerializedNetMsg copy{peer_queue.front().Copy()};
                const bool taken{peer.SetMessageToSend(peer_queue.front())};
                assert(twin_peer.SetMessageToSend(copy) == taken);
                if (taken) peer_queue.pop_front();
            }
            const auto& [bytes, _more, _type]{peer.GetBytesToSend(/*have_next_message=*/!peer_queue.empty())};
            const auto& [twin_bytes, _twin_more, _twin_type]{twin_peer.GetBytesToSend(/*have_next_message=*/!peer_queue.empty())};
            // Message for message, the twin's recipient is where the attempt's is.
            assert(twin_bytes.size() == bytes.size());
            if (bytes.empty()) break;
            const size_t n{std::min(budget - total, bytes.size())};
            const std::vector<uint8_t> chunk{bytes.begin(), bytes.begin() + n}, twin_chunk{twin_bytes.begin(), twin_bytes.begin() + n};
            total += n;
            peer.MarkBytesSent(n);
            twin_peer.MarkBytesSent(n);
            attempt.Received(chunk, now);
            twin.Received(twin_chunk, now);
        }
        return total;
    }};

    LIMITED_WHILE(provider.remaining_bytes() > 0, 2'000) {
        CallOneOf(
            provider,
            [&] { now += milliseconds{provider.ConsumeIntegralInRange<int64_t>(-1'000, 60'000)}; },
            [&] {
                attempt.Tick(now);
                twin.Tick(now);
            },
            [&] {
                attempt.Connected(now);
                twin.Connected(now);
            },
            [&] { attempts_write(provider.ConsumeIntegralInRange<size_t>(0, 4'096)); },
            [&] { recipients_write(provider.ConsumeIntegralInRange<size_t>(0, 4'096)); },
            [&] {
                // Both sides write all they have, back and forth, until neither has more.
                while (true) {
                    const size_t written{attempts_write(std::numeric_limits<size_t>::max())};
                    if (written + recipients_write(std::numeric_limits<size_t>::max()) == 0) break;
                }
            },
            [&] {
                CSerializedNetMsg msg{ConsumeMessage(provider, ping_nonce)};
                if (msg.m_type == NetMsgType::GETDATA) {
                    // The request, as the attempt reads it.
                    DataStream payload{msg.data};
                    std::vector<CInv> request;
                    try {
                        payload >> request;
                        requests.push_back(std::move(request));
                    } catch (const std::ios_base::failure&) {
                    }
                }
                peer_queue.push_back(std::move(msg));
            },
            [&] {
                // Bytes that are not the recipient's transport: a v1 node, a broken or hostile one.
                // Not once the twin has read a message of its own: its session then reads them
                // otherwise than the attempt's.
                if (!can_receive() || extra > 0) return;
                foreign_bytes = true;
                const std::vector<uint8_t> bytes{ConsumeRandomLengthByteVector(provider, 300)};
                attempt.Received(bytes, now);
                twin.Received(bytes, now);
            },
            [&] {
                // A message of a type the attempt acts on in no state, to the twin alone, between
                // two of the recipient's messages: it changes nothing the peer can see (A2).
                if (foreign_bytes || peer_failed || twin_capped || !can_receive()) return;
                CSerializedNetMsg msg;
                msg.m_type = provider.ConsumeBool() ? provider.PickValueInArray(ALL_NET_MESSAGE_TYPES) : provider.ConsumeRandomLengthString(12);
                // The type, up to its first NUL, is what the transport decodes.
                if (ActedOn(msg.m_type.substr(0, msg.m_type.find('\0')))) msg.m_type = NetMsgType::ADDR;
                msg.data = ConsumeRandomLengthByteVector(provider, 300);
                // At the same time as the attempt's, so that only the message sets the twin apart.
                attempt.Tick(now);
                twin.Tick(now);
                if (!twin_peer.SetMessageToSend(msg)) return;
                const uint64_t before{twin.BytesRecv()};
                while (true) {
                    const auto& [bytes, _more, _type]{twin_peer.GetBytesToSend(/*have_next_message=*/false)};
                    if (bytes.empty()) break;
                    const std::vector<uint8_t> chunk{bytes.begin(), bytes.end()};
                    twin_peer.MarkBytesSent(chunk.size());
                    twin.Received(chunk, now);
                }
                extra += twin.BytesRecv() - before;
            },
            [&] {
                attempt.PeerClosed(now);
                twin.PeerClosed(now);
            },
            [&] {
                attempt.SocketError(now, "fuzz");
                twin.SocketError(now, "fuzz");
            },
            [&] {
                attempt.Interrupt(now, "fuzz");
                twin.Interrupt(now, "fuzz");
            });
        if (extra > 0 && twin.BytesRecv() > MAX_RECV_BYTES) twin_capped = true;
        if (!twin_capped) CheckTwins(attempt, twin, extra);

        const AttemptTimes& times{attempt.Times()};
        if (times.inv_written || times.getdata) assert(times.inv_handed);
        if (times.tx_written) assert(times.inv_written && times.getdata);
        if (times.ping_written) assert(times.tx_written);
        if (times.pong) assert(times.ping_written);
        if (!attempt.Ended()) {
            // The receive cap (D3), and the attempt's end bounds every deadline (D2).
            assert(attempt.BytesRecv() <= MAX_RECV_BYTES);
            assert(attempt.NextDeadline() && *attempt.NextDeadline() <= scheduled_start + timing.Scale(ATTEMPT_MAX));
            continue;
        }
        // Once ended, nothing more is written, not even the rest of a message (E7).
        assert(attempt.BytesToSend().empty());
        assert(!attempt.NextDeadline());
        if (!sent_at_end) sent_at_end = attempt.BytesSent();
        assert(attempt.BytesSent() == *sent_at_end);
        switch (attempt.GetOutcome()) {
        case Outcome::NotAnnounced: assert(!times.inv_handed); break;
        case Outcome::AnnouncedNotRequested: assert(times.inv_handed && !times.getdata); break;
        case Outcome::TxWrittenNoPong: assert(times.tx_written && !times.pong); break;
        case Outcome::PongReceived: assert(times.pong); break;
        case Outcome::PostAnnouncementFailure: assert(times.inv_handed && !times.pong); break;
        } // no default case, so the compiler can warn about missing cases
    }
}
