// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIVATE_BROADCAST_H
#define BITCOIN_PRIVATE_BROADCAST_H

#include <net.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <sync.h>
#include <util/time.h>

#include <optional>
#include <tuple>
#include <unordered_map>
#include <vector>

/**
 * Store a list of transactions to be broadcast privately. Supports the following operations:
 * - Add a new transaction
 * - Remove a transaction
 * - Pick a transaction for sending to one recipient
 * - Query which transaction has been picked for sending to a given recipient node
 * - Mark that a given recipient node has confirmed receipt of a transaction
 * - Query whether a given recipient node has confirmed reception
 * - Query whether any transactions that need sending are currently on the list
 */
class PrivateBroadcast
{
public:

    /// If a transaction is not sent to any peer for this duration,
    /// then we consider it stale / for rebroadcasting.
    static constexpr auto INITIAL_STALE_DURATION{5min};

    /// If a transaction is not received back from the network for this duration
    /// after it is broadcast, then we consider it stale / for rebroadcasting.
    static constexpr auto STALE_DURATION{1min};

    struct PeerSendInfo {
        CService address;
        NodeClock::time_point sent;
        std::optional<NodeClock::time_point> received;
    };

    struct TxBroadcastInfo {
        CTransactionRef tx;
        NodeClock::time_point time_added;
        //! Total number of times this transaction was picked for sending,
        //! including to peers that have since disconnected. Cumulative over the
        //! transaction's lifetime (not just the currently-connected `peers`).
        size_t num_broadcasts;
        //! Total number of recipients that acknowledged reception (by PONG),
        //! including those that have since disconnected.
        size_t num_acks;
        //! Per-peer info for the recipients that are still connected. Records
        //! for disconnected peers are pruned, so this is a subset of the
        //! `num_broadcasts` send attempts.
        std::vector<PeerSendInfo> peers;
    };

    /**
     * Add a transaction to the storage.
     * @param[in] tx The transaction to add.
     * @retval true The transaction was added.
     * @retval false The transaction was already present.
     */
    bool Add(const CTransactionRef& tx)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Forget a transaction.
     * @param[in] tx Transaction to forget.
     * @retval !nullopt The number of times the transaction was sent and confirmed
     * by the recipient (if the transaction existed and was removed).
     * @retval nullopt The transaction was not in the storage.
     */
    std::optional<size_t> Remove(const CTransactionRef& tx)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Pick the transaction with the fewest send attempts, and confirmations,
     * and oldest send/confirm times.
     * @param[in] will_send_to_nodeid Will remember that the returned transaction
     * was picked for sending to this node.
     * @param[in] will_send_to_address Address of the peer to which this transaction
     * will be sent.
     * @return Most urgent transaction or nullopt if there are no transactions.
     */
    std::optional<CTransactionRef> PickTxForSend(const NodeId& will_send_to_nodeid, const CService& will_send_to_address)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Get the transaction that was picked for sending to a given node by PickTxForSend().
     * @param[in] nodeid Node to which a transaction is being (or was) sent.
     * @return Transaction or nullopt if the nodeid is unknown.
     */
    std::optional<CTransactionRef> GetTxForNode(const NodeId& nodeid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Mark that the node has confirmed reception of the transaction we sent it by
     * responding with `PONG` to our `PING` message.
     * @param[in] nodeid Node that we sent a transaction to.
     */
    void NodeConfirmedReception(const NodeId& nodeid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Check if the node has confirmed reception of the transaction.
     * @retval true Node has confirmed, `NodeConfirmedReception()` has been called.
     * @retval false Node has not confirmed, `NodeConfirmedReception()` has not been called.
     */
    bool DidNodeConfirmReception(const NodeId& nodeid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Forget the transient per-recipient send record for a disconnected peer.
     * The transaction's cumulative sending stats (used for prioritization and
     * staleness) are unaffected. Call this when a private-broadcast peer
     * disconnects, so per-recipient state does not accumulate for the lifetime
     * of a transaction.
     * @param[in] nodeid The disconnected node.
     */
    void NodeDisconnected(const NodeId& nodeid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Check if there are transactions that need to be broadcast.
     */
    bool HavePendingTransactions()
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Get the transactions that have not been broadcast recently.
     */
    std::vector<CTransactionRef> GetStale() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Get stats about all transactions currently being privately broadcast.
     */
    std::vector<TxBroadcastInfo> GetBroadcastInfo() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    /// Cumulative stats from all the send attempts for a transaction. Used to
    /// prioritize transactions and to decide staleness. Maintained
    /// incrementally (updated by PickTxForSend()/NodeConfirmedReception()) so
    /// it persists for the transaction's whole lifetime, independent of which
    /// recipients are still connected.
    struct Priority {
        size_t num_picked{0}; ///< Number of times the transaction was picked for sending.
        NodeClock::time_point last_picked{}; ///< The most recent time when the transaction was picked for sending.
        size_t num_confirmed{0}; ///< Number of nodes that have confirmed reception of a transaction (by PONG).
        NodeClock::time_point last_confirmed{}; ///< The most recent time when the transaction was confirmed.

        auto operator<=>(const Priority& other) const
        {
            // Invert `other` and `this` in the comparison because smaller num_picked, num_confirmed or
            // earlier times mean greater priority. In other words, if this.num_picked < other.num_picked
            // then this > other.
            return std::tie(other.num_picked, other.num_confirmed, other.last_picked, other.last_confirmed) <=>
                   std::tie(num_picked, num_confirmed, last_picked, last_confirmed);
        }
    };

    /// Per-recipient send record for a transaction. Transient: an entry exists
    /// only while the recipient peer is connected, and is pruned when it
    /// disconnects (NodeDisconnected()). Keyed by NodeId in TxState::in_flight.
    struct InFlight {
        CService address; ///< Address of the recipient node.
        NodeClock::time_point picked; ///< When the transaction was picked for sending to the node.
        std::optional<NodeClock::time_point> confirmed; ///< When the node confirmed reception (by PONG), if it did.
    };

    /// A transaction's persistent priority together with the (mutable) send
    /// record of one recipient. Convenience return type of GetInFlightByNode().
    struct PriorityAndSend {
        Priority& priority;
        InFlight& send;
    };

    // No need for salted hasher because we are going to store just a bunch of locally originating transactions.

    struct CTransactionRefHash {
        size_t operator()(const CTransactionRef& tx) const
        {
            return static_cast<size_t>(tx->GetWitnessHash().ToUint256().GetUint64(0));
        }
    };

    struct CTransactionRefComp {
        bool operator()(const CTransactionRef& a, const CTransactionRef& b) const
        {
            return a->GetWitnessHash() == b->GetWitnessHash(); // If wtxid equals, then txid also equals.
        }
    };

    /**
     * Find the priority and per-recipient send record for a given node.
     * @return The transaction's Priority together with this node's send record,
     * or nullopt if we are not currently tracking a send to the given node.
     */
    std::optional<PriorityAndSend> GetInFlightByNode(const NodeId& nodeid)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    struct TxState {
        const NodeClock::time_point time_added{NodeClock::now()};
        Priority priority;
        /// Currently-connected recipients we have sent (or are sending) this
        /// transaction to, keyed by NodeId. Pruned on disconnect.
        std::unordered_map<NodeId, InFlight> in_flight;
    };
    mutable Mutex m_mutex;
    std::unordered_map<CTransactionRef, TxState, CTransactionRefHash, CTransactionRefComp>
        m_transactions GUARDED_BY(m_mutex);
    /// Reverse index from a recipient NodeId to the transaction currently sent
    /// to it. An entry exists iff that NodeId is present in the corresponding
    /// transaction's TxState::in_flight. Kept in sync by PickTxForSend(),
    /// NodeDisconnected() and Remove() to give O(1) per-node lookups.
    std::unordered_map<NodeId, CTransactionRef> m_node_to_tx GUARDED_BY(m_mutex);
};

#endif // BITCOIN_PRIVATE_BROADCAST_H
