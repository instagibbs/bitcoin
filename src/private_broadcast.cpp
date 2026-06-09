// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <private_broadcast.h>
#include <util/check.h>

#include <algorithm>


bool PrivateBroadcast::Add(const CTransactionRef& tx)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    return m_transactions.try_emplace(tx).second;
}

std::optional<size_t> PrivateBroadcast::Remove(const CTransactionRef& tx)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto it{m_transactions.find(tx)};
    if (it == m_transactions.end()) return std::nullopt;
    // Drop the reverse-index entries for any still-connected recipients.
    for (const auto& [nodeid, _] : it->second.in_flight) {
        m_node_to_tx.erase(nodeid);
    }
    const size_t num_confirmed{it->second.priority.num_confirmed};
    m_transactions.erase(it);
    return num_confirmed;
}

std::optional<CTransactionRef> PrivateBroadcast::PickTxForSend(const NodeId& will_send_to_nodeid, const CService& will_send_to_address)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);

    // Pick the highest-priority transaction. The Priority is maintained
    // incrementally, so this is a single O(N) scan with no per-element work.
    const auto it{std::ranges::max_element(
            m_transactions,
            [](const auto& a, const auto& b) { return a < b; },
            [](const auto& el) { return el.second.priority; })};

    if (it == m_transactions.end()) return std::nullopt;

    auto& [tx, state]{*it};
    const auto now{NodeClock::now()};
    ++state.priority.num_picked;
    state.priority.last_picked = now;
    state.in_flight.insert_or_assign(will_send_to_nodeid, InFlight{.address = will_send_to_address, .picked = now, .confirmed = std::nullopt});
    m_node_to_tx.insert_or_assign(will_send_to_nodeid, tx);
    return tx;
}

std::optional<CTransactionRef> PrivateBroadcast::GetTxForNode(const NodeId& nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto it{m_node_to_tx.find(nodeid)};
    if (it == m_node_to_tx.end()) return std::nullopt;
    return it->second;
}

void PrivateBroadcast::NodeConfirmedReception(const NodeId& nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto in_flight{GetInFlightByNode(nodeid)};
    if (!in_flight.has_value()) return;
    auto& [priority, send]{in_flight.value()};
    // Fold the confirmation into the persistent Priority once. Guarding on the
    // existing timestamp keeps num_confirmed a count of distinct confirming
    // nodes even if a PONG is somehow processed twice.
    if (send.confirmed.has_value()) return;
    const auto now{NodeClock::now()};
    send.confirmed = now;
    ++priority.num_confirmed;
    priority.last_confirmed = now;
}

bool PrivateBroadcast::DidNodeConfirmReception(const NodeId& nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto in_flight{GetInFlightByNode(nodeid)};
    return in_flight.has_value() && in_flight.value().send.confirmed.has_value();
}

void PrivateBroadcast::NodeDisconnected(const NodeId& nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto nit{m_node_to_tx.find(nodeid)};
    if (nit == m_node_to_tx.end()) return;
    // Drop only the transient per-recipient record; the transaction's
    // cumulative Priority (num_picked/num_confirmed/...) is left untouched.
    if (const auto it{m_transactions.find(nit->second)}; it != m_transactions.end()) {
        it->second.in_flight.erase(nodeid);
    }
    m_node_to_tx.erase(nit);
}

bool PrivateBroadcast::HavePendingTransactions()
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    return !m_transactions.empty();
}

std::vector<CTransactionRef> PrivateBroadcast::GetStale() const
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    const auto now{NodeClock::now()};
    std::vector<CTransactionRef> stale;
    for (const auto& [tx, state] : m_transactions) {
        const Priority& p{state.priority};
        if (p.num_confirmed == 0) {
            if (state.time_added < now - INITIAL_STALE_DURATION) stale.push_back(tx);
        } else {
            if (p.last_confirmed < now - STALE_DURATION) stale.push_back(tx);
        }
    }
    return stale;
}

std::vector<PrivateBroadcast::TxBroadcastInfo> PrivateBroadcast::GetBroadcastInfo() const
    EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
{
    LOCK(m_mutex);
    std::vector<TxBroadcastInfo> entries;
    entries.reserve(m_transactions.size());

    for (const auto& [tx, state] : m_transactions) {
        // Only currently-connected recipients are reported; records for
        // disconnected peers are pruned by NodeDisconnected().
        std::vector<PeerSendInfo> peers;
        peers.reserve(state.in_flight.size());
        for (const auto& [nodeid, send] : state.in_flight) {
            peers.emplace_back(PeerSendInfo{.address = send.address, .sent = send.picked, .received = send.confirmed});
        }
        entries.emplace_back(TxBroadcastInfo{.tx = tx,
                                             .time_added = state.time_added,
                                             .num_broadcasts = state.priority.num_picked,
                                             .num_acks = state.priority.num_confirmed,
                                             .peers = std::move(peers)});
    }

    return entries;
}

std::optional<PrivateBroadcast::PriorityAndSend> PrivateBroadcast::GetInFlightByNode(const NodeId& nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
{
    AssertLockHeld(m_mutex);
    const auto nit{m_node_to_tx.find(nodeid)};
    if (nit == m_node_to_tx.end()) return std::nullopt;
    const auto it{m_transactions.find(nit->second)};
    if (it == m_transactions.end()) return std::nullopt;
    const auto fit{it->second.in_flight.find(nodeid)};
    if (fit == it->second.in_flight.end()) return std::nullopt;
    return PriorityAndSend{.priority = it->second.priority, .send = fit->second};
}
