// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_SESSION_H
#define BITCOIN_PRIVBCAST_SESSION_H

#include <privbcast/timing.h>
#include <net_transport.h>
#include <node/protocol_version.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <random.h>
#include <streams.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace privbcast {

using namespace std::chrono_literals;

/** Wire profile and session constants. Visible to recipients, so identical for every user. */
namespace wire {
/** Protocol version we advertise: the current one (BIP434 feature negotiation), so the profile tracks the release. */
inline constexpr int PROTOCOL_VERSION{70017};
/** Lowest peer protocol version accepted: BIP339 wtxid relay, which is required, needs 70016. */
inline constexpr int MIN_PEER_PROTOCOL_VERSION{WTXID_RELAY_VERSION};
/** Service bits we advertise: only what BIP144 needs to send witness data. */
inline constexpr uint64_t SERVICES{NODE_WITNESS};
/**
 * Fixed and never versioned. The node's -privatebroadcast runs this same code, so every user of a
 * release presents one profile; being recognised as it is accepted.
 */
inline constexpr std::string_view USER_AGENT{"/pynode:0.0.1/"};
/** Maximum user agent length accepted from the peer, as in net.h. */
inline constexpr unsigned int MAX_SUBVERSION_LENGTH{256};
/** From the scheduled opportunity start until INV has been handed to the transport. */
inline constexpr auto HANDSHAKE_TIMEOUT{45s};
/** After INV is handed to the transport, how long to wait for the peer's request. */
inline constexpr auto REQUEST_WINDOW{75s};
/** After PING has been fully written, how long to wait for the PONG. */
inline constexpr auto PONG_WAIT{10s};
/**
 * Package only: after the child has been fully written, how long to wait for the peer's request for
 * the parent before PING goes out anyway. A recipient that lacks the parent asks after its
 * orphan-resolution delay (non-preferred, txid-relay and overloaded delays, up to a few seconds
 * each) plus a Tor round trip; this holds comfortably longer. One that already has it never asks.
 */
inline constexpr auto PARENT_HOLD{30s};
/** Longest an attempt can run, from its scheduled start. */
inline constexpr auto ATTEMPT_MAX{HANDSHAKE_TIMEOUT + REQUEST_WINDOW + PONG_WAIT};
/** Raw transport bytes accepted per attempt before it is ended. */
inline constexpr size_t MAX_RECV_BYTES{64 * 1024};
static_assert(PARENT_HOLD + PONG_WAIT <= REQUEST_WINDOW); // a promptly written child gets its full hold and the reserved pong budget
} // namespace wire

enum class Outcome : uint8_t {
    PENDING,
    /**
     * Ended before INV was handed to the transport (connect or transport failure, handshake
     * timeout, an unsuitable or malformed VERSION; the reason says which): the slot's next
     * opportunity may be used.
     */
    NOT_ANNOUNCED,
    // After announcement: terminal for the slot.
    ANNOUNCED_NOT_REQUESTED,
    TX_WRITTEN_NO_PONG,
    PONG_RECEIVED,
    POST_ANNOUNCEMENT_FAILURE,
};

std::string_view OutcomeName(Outcome outcome);
/** Whether the outcome was reached after INV was handed to the transport. */
bool IsPostAnnouncement(Outcome outcome);

/**
 * The per-connection state machine. Pure: it consumes complete messages, transport events and
 * clock ticks, and produces messages to send. It acts only on what the advertised profile makes
 * possible (VERSION, WTXIDRELAY, VERACK, one matching GETDATA per transaction it carries, one
 * matching PONG) and ignores everything else. With a parent it announces the child only, serves it
 * on request, then holds PARENT_HOLD for the peer's request for the parent before PING; the parent
 * is served once, after the child, or alone to a peer that already holds the child. The
 * attempt runner owns the socket, the transport and the byte cap, and reports back when a message
 * is handed to the transport and when it has been fully written.
 */
class Session
{
public:
    struct Evidence {
        std::optional<Clock::time_point> version_received;
        std::optional<int> peer_version; //!< From the peer's VERSION; for diagnostics only
        std::string peer_user_agent;     //!< From the peer's VERSION, sanitized; for diagnostics only
        std::optional<Clock::time_point> inv_handed;   //!< INV accepted by the transport: the announcement point
        std::optional<Clock::time_point> inv_written;  //!< INV bytes fully written
        std::optional<Clock::time_point> getdata_received;
        std::optional<Clock::time_point> tx_written;
        std::optional<Clock::time_point> ping_written;
        std::optional<Clock::time_point> pong_received;
        std::optional<Clock::time_point> parent_requested; //!< package only: the peer asked for the parent
        std::optional<Clock::time_point> parent_written;   //!< package only: parent TX bytes fully written
        std::optional<Clock::time_point> hold_expired;     //!< package only: the hold ended with no parent request; PING sent without it
        uint32_t extra_requests{0}; //!< GETDATA messages received that were not the one served
    };

    /**
     * @param[in] tx The transaction bound to this attempt.
     * @param[in] scheduled_start The opportunity's scheduled start; the handshake deadline counts from here.
     * @param[in] rng Source of the VERSION and PING nonces.
     * @param[in] parent Optional unconfirmed parent of `tx`, served once if the peer asks for it after `tx`.
     */
    Session(CTransactionRef tx, Clock::time_point scheduled_start, FastRandomContext& rng, CTransactionRef parent = nullptr);

    /** Messages to send, in order. Draining transfers ownership. */
    std::vector<CSerializedNetMsg> TakeOutbound();
    /** Feed one complete message received from the transport. */
    void OnMessage(const std::string& type, DataStream& payload, Clock::time_point now);
    /** Advance the deadlines. */
    void OnTick(Clock::time_point now);
    /** The transport has accepted a message of this type for sending. */
    void OnMessageHandedToTransport(const std::string& type, Clock::time_point now);
    /** The transport has fully written a message of this type. */
    void OnMessageWritten(const std::string& type, Clock::time_point now);
    /**
     * End the attempt as a failure (connection refused, lost or unusable, deadline, cancellation):
     * NOT_ANNOUNCED before INV was handed to the transport, POST_ANNOUNCEMENT_FAILURE after.
     */
    void Fail(std::string_view reason);

    bool Finished() const { return m_outcome != Outcome::PENDING; }
    Outcome GetOutcome() const { return m_outcome; }
    /** Whether INV has been handed to the transport. Nothing after this point is replaceable. */
    bool Announced() const { return m_evidence.inv_handed.has_value(); }
    const std::string& Reason() const { return m_reason; }
    const Evidence& GetEvidence() const { return m_evidence; }
    uint64_t PingNonce() const { return m_ping_nonce; }
    Clock::time_point Deadline() const { return m_deadline; }
    /** The next moment OnTick() can change anything: the phase deadline, or the parent hold's end if that comes first. */
    Clock::time_point NextDeadline() const { return m_hold_end ? std::min(*m_hold_end, m_deadline) : m_deadline; }
    /** Package only: when the wait for the parent request ends and PING goes out regardless. */
    std::optional<Clock::time_point> HoldEnd() const { return m_hold_end; }

private:
    enum class State { AWAIT_VERSION, AWAIT_VERACK, ANNOUNCED, PARENT_WAIT, TX_SENT, FINISHED };

    void Finish(Outcome outcome, std::string_view reason);
    void HandleVersion(DataStream& payload, Clock::time_point now);
    void HandleVerack(Clock::time_point now);
    void HandleGetData(DataStream& payload, Clock::time_point now);
    void HandlePong(DataStream& payload, Clock::time_point now);

    const CTransactionRef m_tx;
    const CTransactionRef m_parent; //!< null unless a package was given
    const uint64_t m_version_nonce;
    const uint64_t m_ping_nonce;
    bool m_peer_wtxidrelay{false}; //!< the peer sent WTXIDRELAY before its VERACK
    State m_state{State::AWAIT_VERSION};
    Outcome m_outcome{Outcome::PENDING};
    std::string m_reason;
    Clock::time_point m_deadline;
    std::optional<Clock::time_point> m_hold_end;
    std::vector<CSerializedNetMsg> m_outbound;
    Evidence m_evidence;
};

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_SESSION_H
