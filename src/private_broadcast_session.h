// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIVATE_BROADCAST_SESSION_H
#define BITCOIN_PRIVATE_BROADCAST_SESSION_H

#include <netaddress.h>
#include <net.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <string_view>
#include <vector>

class PrivateBroadcast;
class CInv;

/**
 * Per-connection state machine for ConnectionType::PRIVATE_BROADCAST peers.
 *
 * Lifecycle:
 *   AwaitingVerack  -- conn opened, our VERSION sent, peer's VERSION received,
 *                      we sent VERACK; now waiting for peer's VERACK back.
 *   AwaitingGetData -- picked a tx from the shared PrivateBroadcast queue and
 *                      sent its INV; now waiting for GETDATA.
 *   AwaitingPong    -- sent TX, queued a PING; now waiting for the matching
 *                      PONG which confirms reception.
 *   Done            -- terminal state; either confirmed reception or the
 *                      session was aborted via Disconnect.
 *
 * The session does not own any P2P plumbing. Effects on the connection
 * (sending messages, queuing a ping, disconnecting, requesting a replacement
 * conn) are routed through the Sink interface so the session can be unit-
 * tested in isolation.
 */
class PrivateBroadcastSession
{
public:
    enum class State {
        AwaitingVerack,
        AwaitingGetData,
        AwaitingPong,
        Done,
    };

    /**
     * Effects the session can have on its connection. The owner of the session
     * (PeerManagerImpl) implements this against the underlying CNode/Peer.
     */
    struct Sink {
        virtual void SendInv(const uint256& txid) = 0;
        virtual void SendTx(const CTransaction& tx) = 0;
        virtual void QueuePing() = 0;
        virtual void Disconnect(std::string_view reason) = 0;
        virtual ~Sink() = default;
    };

    PrivateBroadcastSession(NodeId nodeid, CService addr, PrivateBroadcast& store);

    /// Peer acknowledged our VERSION. Pick a tx and INV it.
    void OnVerack(Sink& sink);

    /// Peer asked for the tx we INVed. Validate, send TX, queue a PING.
    void OnGetData(Sink& sink, const std::vector<CInv>& inv);

    /// Peer responded to our PING. Mark confirmed and disconnect.
    void OnPong(Sink& sink);

    /// Connection is being torn down. Returns true if the caller should open a
    /// replacement private broadcast conn (i.e. this session never confirmed
    /// reception and the shared queue still has pending work).
    [[nodiscard]] bool OnFinalize();

    State state() const { return m_state; }

private:
    const NodeId m_nodeid;
    const CService m_addr;
    PrivateBroadcast& m_store;
    State m_state{State::AwaitingVerack};
    CTransactionRef m_picked_tx;
};

#endif // BITCOIN_PRIVATE_BROADCAST_SESSION_H
