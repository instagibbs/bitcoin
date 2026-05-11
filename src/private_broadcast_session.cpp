// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <private_broadcast_session.h>

#include <logging.h>
#include <private_broadcast.h>
#include <protocol.h>
#include <util/check.h>

PrivateBroadcastSession::PrivateBroadcastSession(NodeId nodeid, CService addr, PrivateBroadcast& store)
    : m_nodeid{nodeid}, m_addr{std::move(addr)}, m_store{store}
{
}

void PrivateBroadcastSession::OnVerack(Sink& sink)
{
    if (m_state != State::AwaitingVerack) {
        // Caller delegates here under the same conditions as the legacy
        // PushPrivateBroadcastTx() call: post-VERACK on a private broadcast
        // conn. If the state is anything else, fall through silently — the
        // legacy code had no double-VERACK guard at this layer either; the
        // higher-level handler already rejects redundant VERACK.
        return;
    }

    const auto opt_tx{m_store.PickTxForSend(m_nodeid, m_addr)};
    if (!opt_tx) {
        sink.Disconnect("no more transactions for private broadcast (connected in vain)");
        m_state = State::Done;
        return;
    }
    m_picked_tx = *opt_tx;

    LogDebug(BCLog::PRIVBROADCAST, "P2P handshake completed, sending INV for txid=%s%s, peer=%d",
             m_picked_tx->GetHash().ToString(),
             m_picked_tx->HasWitness() ? strprintf(", wtxid=%s", m_picked_tx->GetWitnessHash().ToString()) : "",
             m_nodeid);

    sink.SendInv(m_picked_tx->GetHash().ToUint256());
    m_state = State::AwaitingGetData;
}

void PrivateBroadcastSession::OnGetData(Sink& sink, const std::vector<CInv>& inv)
{
    if (m_state != State::AwaitingGetData || !m_picked_tx) {
        sink.Disconnect("got GETDATA without sending an INV");
        m_state = State::Done;
        return;
    }

    // The GETDATA request must contain exactly one inv and it must be for the
    // transaction we INVed to the peer earlier.
    if (inv.size() != 1 || !inv[0].IsMsgTx() ||
        inv[0].hash != m_picked_tx->GetHash().ToUint256()) {
        sink.Disconnect("got an unexpected GETDATA message");
        m_state = State::Done;
        return;
    }

    // Re-serving on a repeated GETDATA matches what normal tx relay does and
    // leaks nothing the original INV did not: the peer is asking for a tx we
    // already told them we have. State stays AwaitingGetData; the eventual
    // PONG (whose nonce was queued by the first served GETDATA) drives the
    // transition to Done.
    sink.SendTx(*m_picked_tx);
    sink.QueuePing();
}

void PrivateBroadcastSession::OnPong(Sink& sink)
{
    if (m_state != State::AwaitingGetData) {
        // Defensive: ignore PONGs in any other state. The caller only invokes
        // OnPong after ProcessPong's nonce/ping_time validation has passed, so
        // this is only reachable if a PONG arrives before we ever served a TX
        // (no PING was queued, so the nonce check should already have failed).
        return;
    }
    m_store.NodeConfirmedReception(m_nodeid);
    LogDebug(BCLog::PRIVBROADCAST, "Got a PONG (the transaction will probably reach the network), marking for disconnect, peer=%d",
             m_nodeid);
    sink.Disconnect("transaction successfully relayed");
    m_state = State::Done;
}

bool PrivateBroadcastSession::OnFinalize()
{
    // Request a replacement conn iff we never confirmed reception and the
    // shared queue still has pending work.
    return !m_store.DidNodeConfirmReception(m_nodeid) && m_store.HavePendingTransactions();
}
