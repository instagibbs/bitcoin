// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <map>
#include <set>

/** Maximum total size of orphan transactions stored, in bytes. */
static constexpr unsigned int DEFAULT_MAX_ORPHAN_TOTAL_SIZE{100 * MAX_STANDARD_TX_WEIGHT};

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 */
class TxOrphanage {
public:
    /** Add a new orphan transaction. If the tx already exists, add this peer to its list of announcers.
     * parent_txids should contain a (de-duplicated) list of txids of this transaction's missing parents.
      @returns true if the transaction was added as a new orphan. */
    bool AddTx(const CTransactionRef& tx, NodeId peer, const std::vector<uint256>& parent_txids) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add an additional announcer to an orphan if it exists. Otherwise, do nothing. */
    bool AddAnnouncer(const uint256& wtxid, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get orphan transaction by wtxid. Returns nullptr if we don't have it anymore. */
    CTransactionRef GetTx(const uint256& wtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool HaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if a {tx, peer} exists in the orphanage (by txid or wtxid).*/
    bool HaveTxAndPeer(const GenTxid& gtxid, NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase an orphan by wtxid */
    int EraseTx(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Maybe erase all orphans announced by a peer (eg, after that peer disconnects). If an orphan
     * has been announced by another peer, don't erase, just remove this peer from the list of announcers. */
    void EraseForPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans included in or invalidated by a new block. Returns wtxids of erased txns. */
    std::vector<uint256> EraseForBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Limit the orphanage to the given maximum. Returns all expired entries. */
    std::vector<uint256> LimitOrphans(unsigned int max_orphans, unsigned int max_total_size = DEFAULT_MAX_ORPHAN_TOTAL_SIZE)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

    /** Erase this peer as an announcer of this orphan. If there are no more announcers, delete the orphan. */
    void EraseOrphanOfPeer(const uint256& wtxid, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Return how many entries exist in the orphange */
    size_t Size() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_orphans.size();
    }

    /** Return total memory usage of the transactions stored. Does not include overhead of
     * m_orphans, m_peer_work_set, etc. */
    unsigned int TotalOrphanBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_total_orphan_bytes;
    }
    /** Return total amount of orphans stored by this peer, in bytes.  Since an orphan can have
     * multiple announcers, the aggregate BytesFromPeer() for all peers may exceed
     * TotalOrphanBytes(). */
    unsigned int BytesFromPeer(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        auto peer_bytes_it = m_peer_bytes_used.find(peer);
        return peer_bytes_it == m_peer_bytes_used.end() ? 0 : peer_bytes_it->second;
    }

    /** Get an orphan's parent_txids, or std::nullopt if the orphan is not present. */
    std::optional<std::vector<uint256>> GetParentTxids(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

protected:
    /** Total bytes of all transactions. */
    unsigned int m_total_orphan_bytes{0};

    /** Guards orphan transactions */
    mutable Mutex m_mutex;

    struct OrphanTx {
        CTransactionRef tx;
        int64_t nTimeExpire;
        size_t list_pos;
        std::set<NodeId> announcers;
        /** Txids of the missing parents to request. Determined by peerman. */
        std::vector<uint256> parent_txids;
    };

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<uint256, OrphanTx> m_orphans GUARDED_BY(m_mutex);

    /** Which peer provided the orphans that need to be reconsidered */
    std::map<NodeId, std::set<uint256>> m_peer_work_set GUARDED_BY(m_mutex);

    using OrphanMap = decltype(m_orphans);

    struct IteratorComparator
    {
        template<typename I>
        bool operator()(const I& a, const I& b) const
        {
            return &(*a) < &(*b);
        }
    };

    /** Index from the parents' COutPoint into the m_orphans. Used
     *  to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it GUARDED_BY(m_mutex);

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list GUARDED_BY(m_mutex);

    /** Index from wtxid into the m_orphans to lookup orphan
     *  transactions using their witness ids. */
    std::map<uint256, OrphanMap::iterator> m_wtxid_to_orphan_it GUARDED_BY(m_mutex);

    /** Map from nodeid to the amount of orphans provided by this peer, in bytes. */
    std::map<NodeId, unsigned int> m_peer_bytes_used GUARDED_BY(m_mutex);

    /** Erase an orphan by wtxid */
    int EraseTxNoLock(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    /** Add bytes to this peer's entry in m_peer_bytes_used, adding a new entry if it doesn't
     * already exist. */
    void AddOrphanBytes(unsigned int size, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    /** Subtract bytes from this peer's entry in m_peer_bytes_used, removing the peer's entry from
     * the map if its value becomes 0. */
    void SubtractOrphanBytes(unsigned int size, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

#endif // BITCOIN_TXORPHANAGE_H
