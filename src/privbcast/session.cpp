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

#include <algorithm>
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

Session::Session(CTransactionRef tx, Clock::time_point scheduled_start, FastRandomContext& rng, CTransactionRef parent)
    : m_tx{std::move(tx)},
      m_parent{std::move(parent)},
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
    if (Finished()) return;
    if (m_state == State::PARENT_WAIT && m_hold_end && now >= *m_hold_end) {
        // No request for the parent within the hold; the tool cannot tell whether the peer already has
        // it, is still waiting on another peer, or will not take the package. PING now so the attempt
        // still ends on an acknowledgement, and give the PING PONG_WAIT to be written even if the hold
        // ran to the end of the request window. The deadline only ever moves later here.
        m_evidence.hold_expired = now;
        m_outbound.push_back(NetMsg::Make(NetMsgType::PING, m_ping_nonce));
        m_state = State::TX_SENT;
        m_deadline = std::max(m_deadline, now + Scaled(wire::PONG_WAIT));
    }
    if (now < m_deadline) return;
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
    case State::PARENT_WAIT:
        // Only reachable here if the child was never written: the hold ends no later than this deadline.
        Finish(Outcome::POST_ANNOUNCEMENT_FAILURE, "tx not written in time");
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
        if (m_evidence.getdata_received && !m_evidence.tx_written) {
            m_evidence.tx_written = now;
            // The hold runs from here but reserves the last PONG_WAIT of the request window for the PING
            // and its ack, so even a late child still gets a PING (a very late one gets little parent-fetch
            // time). The window itself is unchanged until the PING is written.
            if (m_state == State::PARENT_WAIT) m_hold_end = std::min(now + Scaled(wire::PARENT_HOLD), m_deadline - Scaled(wire::PONG_WAIT));
        } else if (m_evidence.parent_requested && !m_evidence.parent_written) {
            m_evidence.parent_written = now;
        }
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
    case State::PARENT_WAIT:
        if (type == NetMsgType::GETDATA) HandleGetData(payload, now);
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
    // Wtxid relay (BIP339): the announced transaction is asked for as MSG_WTX by wtxid. A parent is
    // asked for as MSG_WITNESS_TX by txid: the peer's orphan resolution knows only the txid. The
    // announced transaction is served from ANNOUNCED, the parent (if any) afterwards from PARENT_WAIT,
    // each once.
    if (m_state == State::ANNOUNCED && inv.size() == 1 && inv[0].type == MSG_WTX && inv[0].hash == m_tx->GetWitnessHash().ToUint256()) {
        m_evidence.getdata_received = now;
        m_outbound.push_back(NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*m_tx)));
        if (m_parent) {
            // Hold the PING until the peer has had its chance to ask for the parent; the hold starts
            // once the child has been fully written (OnMessageWritten).
            m_state = State::PARENT_WAIT;
            return;
        }
        m_outbound.push_back(NetMsg::Make(NetMsgType::PING, m_ping_nonce));
        // The PONG wait starts once PING has been fully written; until then the request-window
        // deadline remains the bound.
        m_state = State::TX_SENT;
        return;
    }
    if (!m_parent) {
        ++m_evidence.extra_requests;
        return;
    }
    const uint256 parent_hash{m_parent->GetHash().ToUint256()};
    const bool asks_for_parent{std::ranges::any_of(inv, [&](const CInv& e) { return e.type == MSG_WITNESS_TX && e.hash == parent_hash; })};
    // A peer that already holds the child as an orphan, learned from another peer, adds us as an
    // announcer on our wtxid INV and asks only for the parent (it will not fetch the child again).
    // That parent-only request is answered as in PARENT_WAIT: the parent once, after our announcement.
    // A peer we have not served the child cannot have learned its inputs from us, so a request that
    // names the child alongside the parent is not one our announcement made possible: ignored.
    const bool names_child{std::ranges::any_of(inv, [&](const CInv& e) { return e.hash == m_tx->GetHash().ToUint256() || e.hash == m_tx->GetWitnessHash().ToUint256(); })};
    const bool parent_only{m_state == State::ANNOUNCED && asks_for_parent && !names_child};
    if (m_state != State::PARENT_WAIT && !parent_only) {
        ++m_evidence.extra_requests;
        return;
    }
    // The peer's orphan resolution asks for every parent it does not already recognise, so one
    // request can batch our parent with unrelated inputs (a coin confirmed longer ago than the
    // peer's rolling filter remembers). Serve the parent once and, like any node, answer the
    // entries we cannot supply with NOTFOUND; never say that about our own two transactions.
    const auto ours = [&](const uint256& h) { // either id of either transaction
        return h == m_tx->GetHash().ToUint256() || h == m_tx->GetWitnessHash().ToUint256() ||
               h == parent_hash || h == m_parent->GetWitnessHash().ToUint256();
    };
    std::vector<CInv> notfound;
    bool serve_parent{false};
    for (const CInv& entry : inv) {
        if (!entry.IsGenTxMsg()) continue; // not a transaction request: nothing to say, as in the node
        if (!serve_parent && !m_evidence.parent_requested && entry.type == MSG_WITNESS_TX && entry.hash == parent_hash) {
            serve_parent = true;
        } else if (!ours(entry.hash)) {
            notfound.push_back(entry);
        }
    }
    if (serve_parent) {
        m_evidence.parent_requested = now;
        m_outbound.push_back(NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*m_parent)));
    }
    if (!notfound.empty()) m_outbound.push_back(NetMsg::Make(NetMsgType::NOTFOUND, notfound));
    if (serve_parent) {
        m_outbound.push_back(NetMsg::Make(NetMsgType::PING, m_ping_nonce));
        m_state = State::TX_SENT;
    } else if (notfound.empty()) {
        ++m_evidence.extra_requests; // only our own txids repeated, or nothing recognisable
    }
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
