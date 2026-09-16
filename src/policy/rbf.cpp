// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/rbf.h>

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <unordered_set>
#include <utility>
#include <vector>

#include <compare>

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(tx.GetHash())) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    const auto& entry{*Assert(pool.GetEntry(tx.GetHash()))};
    auto ancestors{pool.CalculateMemPoolAncestors(entry)};

    for (CTxMemPool::txiter it : ancestors) {
        if (SignalsOptInRBF(it->GetTx())) {
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }
    return RBFTransactionState::FINAL;
}

RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx)
{
    // If we don't have a local mempool we can only check the transaction itself.
    return SignalsOptInRBF(tx) ? RBFTransactionState::REPLACEABLE_BIP125 : RBFTransactionState::UNKNOWN;
}

std::optional<std::string> GetEntriesForConflicts(const CTransaction& tx,
                                                  CTxMemPool& pool,
                                                  const CTxMemPool::setEntries& iters_conflicting,
                                                  CTxMemPool::setEntries& all_conflicts)
{
    AssertLockHeld(pool.cs);
    // Rule #5: don't consider replacements that conflict directly with more
    // than MAX_REPLACEMENT_CANDIDATES distinct clusters. This implies a bound
    // on how many mempool clusters might need to be re-sorted in order to
    // process the replacement (though the actual number of clusters we
    // relinearize may be greater than this number, due to cluster splitting).
    auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
    if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
        return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)",
                tx.GetHash().ToString(),
                num_clusters,
                MAX_REPLACEMENT_CANDIDATES);
    }
    // Calculate the set of all transactions that would have to be evicted.
    for (CTxMemPool::txiter it : iters_conflicting) {
        // The cluster count limit ensures that we won't do too much work on a
        // single invocation of this function.
        pool.CalculateDescendants(it, all_conflicts);
    }
    return std::nullopt;
}

std::optional<CTxMemPool::setEntries> GetEntriesForSiblingEviction(const CTxMemPool& pool,
                                                                  const CTxMemPoolEntry& replacement,
                                                                  const std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef>& parents,
                                                                  const CTxMemPool::setEntries& ancestors,
                                                                  const CTxMemPool::setEntries& removals,
                                                                  int64_t max_count,
                                                                  int64_t max_weight)
{
    AssertLockHeld(pool.cs);

    // Nothing can be evicted to make room for the pinned set, so reject before touching any cluster
    // if it does not fit on its own. An ancestor staged for removal would make the replacement
    // spend an output it removes.
    std::unordered_set<const CTxMemPoolEntry*> pinned;
    int64_t budget_count{max_count - 1};
    int64_t budget_weight{max_weight - replacement.GetAdjustedWeight()};
    for (const auto it : ancestors) {
        if (removals.contains(it)) return std::nullopt;
        pinned.insert(&*it);
        --budget_count;
        budget_weight -= it->GetAdjustedWeight();
    }
    if (budget_count < 0 || budget_weight < 0) return std::nullopt;

    std::unordered_set<const CTxMemPoolEntry*> removed;
    for (const auto it : removals) removed.insert(&*it);

    // A unit is a chunk of the candidates' own linearization: kept or evicted as a whole.
    struct Unit {
        FeeFrac feerate;
        std::vector<const CTxMemPoolEntry*> members;
        std::vector<size_t> children;
        size_t deps_left{0};
        bool kept{false};
    };
    // Units are appended in cluster enumeration order, then linearization order, so a unit's index
    // is a deterministic tie-breaker for a given graph.
    std::vector<Unit> units;
    std::unordered_set<const CTxMemPoolEntry*> seen;

    for (const auto& parent : parents) {
        if (seen.contains(&parent.get())) continue;
        // In linearization order. Members already staged for removal are gone.
        std::vector<const CTxMemPoolEntry*> remaining;
        for (const auto* entry : pool.GetCluster(parent.get().GetTx().GetHash())) {
            seen.insert(entry);
            if (!removed.contains(entry)) remaining.push_back(entry);
        }
        // Sorted (entry, position) pairs: a cluster is small, so binary search beats hashing.
        std::vector<std::pair<const CTxMemPoolEntry*, size_t>> index;
        index.reserve(remaining.size());
        for (size_t i{0}; i < remaining.size(); ++i) index.emplace_back(remaining[i], i);
        // Sort and search with the same projected comparator: std::ranges::less gives pointers a
        // total order, which the built-in comparison does not guarantee for unrelated objects.
        std::ranges::sort(index, {}, &std::pair<const CTxMemPoolEntry*, size_t>::first);
        auto position = [&](const CTxMemPoolEntry* entry) -> std::optional<size_t> {
            const auto it = std::ranges::lower_bound(index, entry, {}, &std::pair<const CTxMemPoolEntry*, size_t>::first);
            if (it == index.end() || it->first != entry) return std::nullopt;
            return it->second;
        };

        // Union-find over what remains, to separate material the removals disconnect from the pinned
        // set. Ancestors' ancestors are ancestors, so only candidates contribute edges. Ancestors are
        // used rather than parents: they are bounded by the cluster size, not by input counts, and
        // give the same connectivity and, since kept sets are ancestor-closed, the same eligibility.
        std::vector<size_t> uf(remaining.size());
        std::iota(uf.begin(), uf.end(), size_t{0});
        auto find = [&](size_t x) {
            while (uf[x] != x) {
                uf[x] = uf[uf[x]];
                x = uf[x];
            }
            return x;
        };
        std::vector<std::vector<size_t>> ancestor_index(remaining.size());
        for (size_t i{0}; i < remaining.size(); ++i) {
            if (pinned.contains(remaining[i])) continue;
            for (const auto* ancestor : pool.GetAncestors(*remaining[i])) {
                if (ancestor == remaining[i]) continue;
                // Removals are descendant-closed, so a candidate's ancestor is never removed. The
                // closure argument needs every edge, so fail closed if one is somehow missing.
                const auto pos = position(ancestor);
                if (!Assume(pos)) return std::nullopt;
                ancestor_index[i].push_back(*pos);
                uf[find(i)] = find(*pos);
            }
        }
        std::unordered_set<size_t> attached_roots;
        for (size_t i{0}; i < remaining.size(); ++i) {
            if (pinned.contains(remaining[i])) attached_roots.insert(find(i));
        }

        // Chunk the attached candidates by the usual rule: merge into the previous chunk while the
        // feerate is higher. Pinned and detached entries are skipped, so a chunk's feerate is what
        // its members are worth on their own now that the replacement carries the pinned ancestors.
        const size_t first_unit{units.size()};
        constexpr size_t NONE{std::numeric_limits<size_t>::max()};
        std::vector<size_t> unit_of(remaining.size(), NONE);
        for (size_t i{0}; i < remaining.size(); ++i) {
            if (pinned.contains(remaining[i]) || !attached_roots.contains(find(i))) continue;
            Unit unit;
            unit.feerate = FeeFrac{remaining[i]->GetModifiedFee(), remaining[i]->GetAdjustedWeight()};
            unit.members.push_back(remaining[i]);
            while (units.size() > first_unit && ByRatio{unit.feerate} > ByRatio{units.back().feerate}) {
                auto& prev = units.back();
                unit.feerate += prev.feerate;
                prev.members.insert(prev.members.end(), unit.members.begin(), unit.members.end());
                unit.members = std::move(prev.members);
                units.pop_back();
            }
            units.push_back(std::move(unit));
        }
        for (size_t u{first_unit}; u < units.size(); ++u) {
            for (const auto* member : units[u].members) unit_of[*position(member)] = u;
        }
        // Dependencies between units, each distinct pair counted once. Marks are per cluster since
        // all of a cluster's units are in [first_unit, units.size()).
        std::vector<size_t> last_marked(units.size() - first_unit, NONE);
        for (size_t i{0}; i < remaining.size(); ++i) {
            const size_t u{unit_of[i]};
            if (u == NONE) continue;
            for (const size_t a : ancestor_index[i]) {
                const size_t au{unit_of[a]};
                if (au == NONE || au == u || last_marked[au - first_unit] == u) continue; // pinned, same unit, or seen
                last_marked[au - first_unit] = u;
                units[au].children.push_back(u);
                ++units[u].deps_left;
            }
        }
    }

    // Keep the most valuable eligible unit that fits; a unit whose parents were not kept is never
    // eligible. Lower feerate, then later position, is popped later.
    auto worse = [&](size_t a, size_t b) {
        const auto cmp = ByRatio{units[a].feerate} <=> ByRatio{units[b].feerate};
        return cmp != 0 ? cmp < 0 : a > b;
    };
    std::vector<size_t> heap;
    for (size_t u{0}; u < units.size(); ++u) {
        if (units[u].deps_left == 0) heap.push_back(u);
    }
    std::make_heap(heap.begin(), heap.end(), worse);
    while (!heap.empty()) {
        std::pop_heap(heap.begin(), heap.end(), worse);
        auto& unit = units[heap.back()];
        heap.pop_back();
        if (std::cmp_greater(unit.members.size(), budget_count) || unit.feerate.size > budget_weight) continue;
        unit.kept = true;
        budget_count -= unit.members.size();
        budget_weight -= unit.feerate.size;
        for (const size_t child : unit.children) {
            if (--units[child].deps_left == 0) {
                heap.push_back(child);
                std::push_heap(heap.begin(), heap.end(), worse);
            }
        }
    }

    CTxMemPool::setEntries evictions;
    for (const auto& unit : units) {
        if (unit.kept) continue;
        for (const auto* member : unit.members) evictions.insert(pool.GetIter(*member));
    }
    return evictions;
}

std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<Txid>& direct_conflicts,
                                                   const Txid& txid)
{
    for (CTxMemPool::txiter ancestorIt : ancestors) {
        const Txid& hashAncestor = ancestorIt->GetTx().GetHash();
        if (direct_conflicts.contains(hashAncestor)) {
            return strprintf("%s spends conflicting transaction %s",
                             txid.ToString(),
                             hashAncestor.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const Txid& txid)
{
    // Rule #3: The replacement fees must be greater than or equal to fees of the
    // transactions it replaces, otherwise the bandwidth used by those conflicting transactions
    // would not be paid for.
    if (replacement_fees < original_fees) {
        return strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                         txid.ToString(), FormatMoney(replacement_fees), FormatMoney(original_fees));
    }

    // Rule #4: The new transaction must pay for its own bandwidth. Otherwise, we have a DoS
    // vector where attackers can cause a transaction to be replaced (and relayed) repeatedly by
    // increasing the fee by tiny amounts.
    CAmount additional_fees = replacement_fees - original_fees;
    if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
        return strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                         txid.ToString(),
                         FormatMoney(additional_fees),
                         FormatMoney(relay_fee.GetFee(replacement_vsize)));
    }
    return std::nullopt;
}

std::optional<std::pair<DiagramCheckError, std::string>> ImprovesFeerateDiagram(CTxMemPool::ChangeSet& changeset)
{
    // Require that the replacement strictly improves the mempool's feerate diagram.
    const auto chunk_results{changeset.CalculateChunksForRBF()};

    if (!chunk_results.has_value()) {
        return std::make_pair(DiagramCheckError::UNCALCULABLE, util::ErrorString(chunk_results).original);
    }

    if (!std::is_gt(CompareChunks(chunk_results.value().second, chunk_results.value().first))) {
        return std::make_pair(DiagramCheckError::FAILURE, "insufficient feerate: does not improve feerate diagram");
    }
    return std::nullopt;
}
