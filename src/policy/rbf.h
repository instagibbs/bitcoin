// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_RBF_H
#define BITCOIN_POLICY_RBF_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <txmempool.h>
#include <util/feefrac.h>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CFeeRate;
class uint256;

/** Maximum number of unique clusters that can be affected by an RBF (Rule #5);
 * see GetEntriesForConflicts() */
inline constexpr uint32_t MAX_REPLACEMENT_CANDIDATES{100};

/** The rbf state of unconfirmed transactions */
enum class RBFTransactionState {
    /** Unconfirmed tx that does not signal rbf and is not in the mempool */
    UNKNOWN,
    /** Either this tx or a mempool ancestor signals rbf */
    REPLACEABLE_BIP125,
    /** Neither this tx nor a mempool ancestor signals rbf */
    FINAL,
};

enum class DiagramCheckError {
    /** Unable to calculate due to topology or other reason */
    UNCALCULABLE,
    /** New diagram wasn't strictly superior  */
    FAILURE,
};

/**
 * Determine whether an unconfirmed transaction is signaling opt-in to RBF
 * according to BIP 125
 * This involves checking sequence numbers of the transaction, as well
 * as the sequence numbers of all in-mempool ancestors.
 *
 * @param tx   The unconfirmed transaction
 * @param pool The mempool, which may contain the tx
 *
 * @return     The rbf state
 */
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool) EXCLUSIVE_LOCKS_REQUIRED(pool.cs);
RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx);

/** Get all descendants of iters_conflicting. Checks that there are no more than
 * MAX_REPLACEMENT_CANDIDATES distinct clusters affected.
 *
 * @param[in]   iters_conflicting   The set of iterators to mempool entries.
 * @param[out]  all_conflicts       Populated with all the mempool entries that would be replaced,
 *                                  which includes iters_conflicting and all entries' descendants.
 *                                  Not cleared at the start; any existing mempool entries will
 *                                  remain in the set.
 * @returns an error message if the number of affected clusters would exceed MAX_REPLACEMENT_CANDIDATES, std::nullopt otherwise
 */
std::optional<std::string> GetEntriesForConflicts(const CTransaction& tx, CTxMemPool& pool,
                                                  const CTxMemPool::setEntries& iters_conflicting,
                                                  CTxMemPool::setEntries& all_conflicts)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Choose which transactions to evict so that replacement fits within cluster limits.
 *
 * The replacement and its in-mempool ancestors are pinned. Every other transaction remaining
 * (after removals) in the parents' clusters that stays connected to the pinned set is a candidate.
 * Candidates are grouped into chunks of their own linearization, then kept greedily in decreasing
 * feerate order while they fit the remaining count and weight budget, provided their parents are
 * kept or pinned. Everything not kept is returned for eviction. Material that the removals
 * disconnect from the pinned set is neither budgeted nor evicted.
 *
 * The kept set is ancestor-closed, so the returned set is descendant-closed and the replacement's
 * resulting cluster is a subset of the pinned and kept transactions, which fit by construction.
 *
 * @param[in]  ancestors  In-mempool ancestors of replacement (main graph).
 * @param[in]  removals   Transactions already staged for removal (direct conflicts and their
 *                        descendants); excluded from candidates and never returned.
 * @param[in]  max_count  Cluster count limit.
 * @param[in]  max_weight Cluster sigop-adjusted weight limit, in weight units.
 * @return the entries to evict, or nullopt if the pinned set alone exceeds a limit or overlaps
 *         removals. Does not check the cluster work bound, fees, or the feerate diagram. The main
 *         graph must not be oversized.
 */
std::optional<CTxMemPool::setEntries> GetEntriesForSiblingEviction(const CTxMemPool& pool,
                                                                  const CTxMemPoolEntry& replacement,
                                                                  const std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& parents,
                                                                  const CTxMemPool::setEntries& ancestors,
                                                                  const CTxMemPool::setEntries& removals,
                                                                  int64_t max_count,
                                                                  int64_t max_weight)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Check the intersection between two sets of transactions (a set of mempool entries and a set of
 * txids) to make sure they are disjoint.
 * @param[in]   ancestors           Set of mempool entries corresponding to ancestors of the
 *                                  replacement transactions.
 * @param[in]   direct_conflicts    Set of txids corresponding to the mempool conflicts
 *                                  (candidates to be replaced).
 * @param[in]   txid                Transaction ID, included in the error message if violation occurs.
 * @returns error message if the sets intersect, std::nullopt if they are disjoint.
 */
std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<Txid>& direct_conflicts,
                                                   const Txid& txid);

/** The replacement transaction must pay more fees than the original transactions. The additional
 * fees must pay for the replacement's bandwidth at or above the incremental relay feerate.
 * @param[in]   original_fees       Total modified fees of original transaction(s).
 * @param[in]   replacement_fees    Total modified fees of replacement transaction(s).
 * @param[in]   replacement_vsize   Total virtual size of replacement transaction(s).
 * @param[in]   relay_fee           The node's minimum feerate for transaction relay.
 * @param[in]   txid                Transaction ID, included in the error message if violation occurs.
 * @returns error string if fees are insufficient, otherwise std::nullopt.
 */
std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const Txid& txid);

/**
 * The replacement transaction must improve the feerate diagram of the mempool.
 * @param[in]   changeset           The changeset containing proposed additions/removals
 * @returns error type and string if mempool diagram doesn't improve, otherwise std::nullopt.
 */
std::optional<std::pair<DiagramCheckError, std::string>> ImprovesFeerateDiagram(CTxMemPool::ChangeSet& changeset);

#endif // BITCOIN_POLICY_RBF_H
