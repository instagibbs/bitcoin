// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/session.h>
#include <privbcast/timing.h>

#include <logging.h>
#include <netaddress.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <serialize.h>
#include <streams.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <ios>
#include <utility>

namespace privbcast {

std::string_view OutcomeName(Outcome outcome)
{
    switch (outcome) {
    case Outcome::PENDING: return "pending";
    case Outcome::NOT_ANNOUNCED: return "not_announced";
    case Outcome::ANNOUNCED_NOT_REQUESTED: return "announced_not_requested";
    case Outcome::TX_WRITTEN_NO_PONG: return "tx_written_no_pong";
    case Outcome::PONG_RECEIVED: return "pong_received";
    case Outcome::POST_ANNOUNCEMENT_FAILURE: return "post_announcement_failure";
    }
    return "unknown";
}

bool IsPostAnnouncement(Outcome outcome)
{
    switch (outcome) {
    case Outcome::ANNOUNCED_NOT_REQUESTED:
    case Outcome::TX_WRITTEN_NO_PONG:
    case Outcome::PONG_RECEIVED:
    case Outcome::POST_ANNOUNCEMENT_FAILURE:
        return true;
    case Outcome::PENDING:
    case Outcome::NOT_ANNOUNCED:
        return false;
    }
    return false;
}

Session::Session(CTransactionRef tx, Clock::time_point scheduled_start, FastRandomContext& rng)
    : m_tx{std::move(tx)},
      m_version_nonce{rng.rand64()},
      m_ping_nonce{rng.rand64()},
      m_deadline{scheduled_start + Scaled(wire::HANDSHAKE_TIMEOUT)}
{
    // The whole profile is constant: nothing here comes from the host, the node or the user.
    m_outbound.push_back(NetMsg::Make(NetMsgType::VERSION,
                                      wire::PROTOCOL_VERSION,
                                      wire::SERVICES,
                                      int64_t{0},
                                      uint64_t{0}, CNetAddr::V1(CService{}),        // addrRecv: unknown services, null address
                                      wire::SERVICES, CNetAddr::V1(CService{}),      // addrFrom: null address
                                      m_version_nonce,
                                      std::string{wire::USER_AGENT},
                                      int{0},
                                      /*relay=*/false));
}

std::vector<CSerializedNetMsg> Session::TakeOutbound()
{
    std::vector<CSerializedNetMsg> out;
    out.swap(m_outbound);
    return out;
}

void Session::Finish(Outcome outcome, std::string_view reason)
{
    if (Finished()) return;
    m_outcome = outcome;
    m_reason = std::string{reason};
    m_state = State::FINISHED;
    m_outbound.clear(); // Nothing is sent once the attempt has ended.
    LogDebug(BCLog::PRIVBROADCAST, "session: %s%s\n", OutcomeName(outcome), reason.empty() ? "" : strprintf(" (%s)", reason));
}

void Session::Fail(std::string_view reason)
{
    Finish(Announced() ? Outcome::POST_ANNOUNCEMENT_FAILURE : Outcome::NOT_ANNOUNCED, reason);
}

void Session::OnTick(Clock::time_point now)
{
    if (Finished() || now < m_deadline) return;
    // Deadlines are strict: anything arriving at or after the deadline is not processed.
    switch (m_state) {
    case State::AWAIT_VERSION:
    case State::AWAIT_VERACK:
        Finish(Outcome::NOT_ANNOUNCED, "handshake timeout");
        break;
    case State::ANNOUNCED:
        // INV queued but the transport never took it within the handshake budget: nothing
        // was announced, so the slot may still use its next opportunity.
        if (!Announced()) {
            Finish(Outcome::NOT_ANNOUNCED, "inv not handed to transport");
        } else {
            Finish(Outcome::ANNOUNCED_NOT_REQUESTED, "");
        }
        break;
    case State::TX_SENT:
        if (!m_evidence.ping_written) {
            Finish(Outcome::POST_ANNOUNCEMENT_FAILURE, m_evidence.tx_written ? "ping not written in time" : "tx not written in time");
        } else {
            Finish(Outcome::TX_WRITTEN_NO_PONG, "");
        }
        break;
    case State::FINISHED:
        break;
    }
}

void Session::OnMessageHandedToTransport(const std::string& type, Clock::time_point now)
{
    OnTick(now); // a handover cannot revive an expired phase
    if (Finished()) return;
    if (type == NetMsgType::INV && !m_evidence.inv_handed) {
        // The announcement point. From here on nothing about this attempt is replaceable.
        m_evidence.inv_handed = now;
        m_deadline = now + Scaled(wire::REQUEST_WINDOW);
    }
}

void Session::OnMessageWritten(const std::string& type, Clock::time_point now)
{
    OnTick(now); // a completion cannot revive an expired phase
    if (Finished()) return;
    if (type == NetMsgType::INV) {
        if (!m_evidence.inv_written) m_evidence.inv_written = now;
    } else if (type == NetMsgType::TX) {
        if (!m_evidence.tx_written) m_evidence.tx_written = now;
    } else if (type == NetMsgType::PING) {
        if (!m_evidence.ping_written) {
            m_evidence.ping_written = now;
            m_deadline = now + Scaled(wire::PONG_WAIT);
        }
    }
}

void Session::OnMessage(const std::string& type, DataStream& payload, Clock::time_point now)
{
    OnTick(now);
    if (Finished()) return;
    // Act only on what our profile makes possible; everything else is ignored, never answered.
    switch (m_state) {
    case State::AWAIT_VERSION:
        if (type == NetMsgType::VERSION) HandleVersion(payload, now);
        break;
    case State::AWAIT_VERACK:
        if (type == NetMsgType::VERACK) {
            HandleVerack(now);
        } else if (type == NetMsgType::WTXIDRELAY) {
            m_peer_wtxidrelay = true; // BIP339: only counts before VERACK
        }
        break;
    case State::ANNOUNCED:
        // Serve only once the transport has taken our INV. A peer that already knows the txid
        // from elsewhere can pipeline VERSION, VERACK and GETDATA while our queued INV is still
        // held back by transport backpressure; serving then would make a replaceable attempt
        // behave like an announced one. Until Announced() such a request is ignored.
        if (type == NetMsgType::GETDATA && Announced()) HandleGetData(payload, now);
        break;
    case State::TX_SENT:
        if (type == NetMsgType::PONG) {
            HandlePong(payload, now);
        } else if (type == NetMsgType::GETDATA) {
            ++m_evidence.extra_requests;
        }
        break;
    case State::FINISHED:
        break;
    }
}

void Session::HandleVersion(DataStream& payload, Clock::time_point now)
{
    int version;
    uint64_t services;
    int64_t time;
    CService addr_recv;
    uint64_t nonce;
    std::string user_agent;
    int32_t height;
    bool relay;
    try {
        // Strict: every field a MIN_PEER_PROTOCOL_VERSION peer must send is required.
        payload >> version >> Using<CustomUintFormatter<8>>(services) >> time;
        payload.ignore(8); // addrRecv services
        payload >> CNetAddr::V1(addr_recv);
        payload.ignore(26); // addrFrom
        payload >> nonce;
        payload >> LIMITED_STRING(user_agent, wire::MAX_SUBVERSION_LENGTH);
        payload >> height >> relay;
    } catch (const std::ios_base::failure&) {
        Fail("malformed version");
        return;
    }
    m_evidence.version_received = now;
    m_evidence.peer_version = version;
    m_evidence.peer_user_agent = SanitizeString(user_agent);
    if (version < wire::MIN_PEER_PROTOCOL_VERSION) {
        Fail("protocol version too old");
        return;
    }
    if (!(services & NODE_WITNESS)) {
        Fail("no NODE_WITNESS");
        return;
    }
    if (!relay) {
        Fail("relay=false");
        return;
    }
    // BIP339, between the peer's VERSION and our VERACK. Every accepted peer is at least 70016.
    m_outbound.push_back(NetMsg::Make(NetMsgType::WTXIDRELAY));
    m_outbound.push_back(NetMsg::Make(NetMsgType::VERACK));
    m_state = State::AWAIT_VERACK;
}

void Session::HandleVerack(Clock::time_point now)
{
    // Queue the announcement. It counts as announced only once the transport has taken it
    // (OnMessageHandedToTransport); until then the handshake deadline still applies.
    if (!m_peer_wtxidrelay) {
        // Wtxid relay is required; ending here is before the announcement, so the slot moves on.
        Fail("no wtxid relay");
        return;
    }
    m_outbound.push_back(NetMsg::Make(NetMsgType::INV, std::vector<CInv>{CInv{MSG_WTX, m_tx->GetWitnessHash().ToUint256()}}));
    m_state = State::ANNOUNCED;
}

void Session::HandleGetData(DataStream& payload, Clock::time_point now)
{
    std::vector<CInv> inv;
    try {
        payload >> inv;
    } catch (const std::ios_base::failure&) {
        Fail("malformed getdata");
        return;
    }
    // Wtxid relay (BIP339): the request for our transaction is MSG_WTX by wtxid, which always carries
    // the witness. Anything else is not a request our profile makes possible and gets no reply.
    if (inv.size() != 1 || inv[0].type != MSG_WTX || inv[0].hash != m_tx->GetWitnessHash().ToUint256()) {
        ++m_evidence.extra_requests;
        return;
    }
    m_evidence.getdata_received = now;
    m_outbound.push_back(NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*m_tx)));
    m_outbound.push_back(NetMsg::Make(NetMsgType::PING, m_ping_nonce));
    // The PONG wait starts once PING has been fully written; until then the request-window
    // deadline remains the bound.
    m_state = State::TX_SENT;
}

void Session::HandlePong(DataStream& payload, Clock::time_point now)
{
    // Before our PING has been written no PONG can be an answer to it; whatever its shape it is
    // not a message our profile made possible yet, so it is ignored, not judged.
    if (!m_evidence.ping_written) return;
    uint64_t nonce;
    if (payload.size() != sizeof(nonce)) {
        Fail("malformed pong");
        return;
    }
    payload >> nonce;
    if (nonce != m_ping_nonce) return; // Not ours; keep waiting.
    m_evidence.pong_received = now;
    Finish(Outcome::PONG_RECEIVED, "");
}

} // namespace privbcast
