// Copyright (c) 2016-2022 The Bitcoin Core developers
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

#include <limits>
#include <vector>

RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(GenTxid::Txid(tx.GetHash()))) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    const auto& entry{*Assert(pool.GetEntry(tx.GetHash()))};
    auto ancestors{pool.AssumeCalculateMemPoolAncestors(__func__, entry, CTxMemPool::Limits::NoLimits(),
                                                        /*fSearchForParents=*/false)};

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
    const uint256 txid = tx.GetHash();
    uint64_t nConflictingCount = 0;
    for (const auto& mi : iters_conflicting) {
        nConflictingCount += mi->GetCountWithDescendants();
        // Rule #5: don't consider replacing more than MAX_REPLACEMENT_CANDIDATES
        // entries from the mempool. This potentially overestimates the number of actual
        // descendants (i.e. if multiple conflicts share a descendant, it will be counted multiple
        // times), but we just want to be conservative to avoid doing too much work.
        if (nConflictingCount > MAX_REPLACEMENT_CANDIDATES) {
            return strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                             txid.ToString(),
                             nConflictingCount,
                             MAX_REPLACEMENT_CANDIDATES);
        }
    }
    // Calculate the set of all transactions that would have to be evicted.
    for (CTxMemPool::txiter it : iters_conflicting) {
        pool.CalculateDescendants(it, all_conflicts);
    }
    return std::nullopt;
}

std::optional<std::string> HasNoNewUnconfirmed(const CTransaction& tx,
                                               const CTxMemPool& pool,
                                               const CTxMemPool::setEntries& iters_conflicting)
{
    AssertLockHeld(pool.cs);
    std::set<uint256> parents_of_conflicts;
    for (const auto& mi : iters_conflicting) {
        for (const CTxIn& txin : mi->GetTx().vin) {
            parents_of_conflicts.insert(txin.prevout.hash);
        }
    }

    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        // Rule #2: We don't want to accept replacements that require low feerate junk to be
        // mined first.  Ideally we'd keep track of the ancestor feerates and make the decision
        // based on that, but for now requiring all new inputs to be confirmed works.
        //
        // Note that if you relax this to make RBF a little more useful, this may break the
        // CalculateMempoolAncestors RBF relaxation which subtracts the conflict count/size from the
        // descendant limit.
        if (!parents_of_conflicts.count(tx.vin[j].prevout.hash)) {
            // Rather than check the UTXO set - potentially expensive - it's cheaper to just check
            // if the new input refers to a tx that's in the mempool.
            if (pool.exists(GenTxid::Txid(tx.vin[j].prevout.hash))) {
                return strprintf("replacement %s adds unconfirmed input, idx %d",
                                 tx.GetHash().ToString(), j);
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<uint256>& direct_conflicts,
                                                   const uint256& txid)
{
    for (CTxMemPool::txiter ancestorIt : ancestors) {
        const uint256& hashAncestor = ancestorIt->GetTx().GetHash();
        if (direct_conflicts.count(hashAncestor)) {
            return strprintf("%s spends conflicting transaction %s",
                             txid.ToString(),
                             hashAncestor.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysMoreThanConflicts(const CTxMemPool::setEntries& iters_conflicting,
                                                 CFeeRate replacement_feerate,
                                                 const uint256& txid)
{
    for (const auto& mi : iters_conflicting) {
        // Don't allow the replacement to reduce the feerate of the mempool.
        //
        // We usually don't want to accept replacements with lower feerates than what they replaced
        // as that would lower the feerate of the next block. Requiring that the feerate always be
        // increased is also an easy-to-reason about way to prevent DoS attacks via replacements.
        //
        // We only consider the feerates of transactions being directly replaced, not their indirect
        // descendants. While that does mean high feerate children are ignored when deciding whether
        // or not to replace, we do require the replacement to pay more overall fees too, mitigating
        // most cases.
        CFeeRate original_feerate(mi->GetModifiedFee(), mi->GetTxSize());
        if (replacement_feerate <= original_feerate) {
            return strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                             txid.ToString(),
                             replacement_feerate.ToString(),
                             original_feerate.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const uint256& txid)
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

// Compare two feerate points, where one of the points is interpolated from
// existing points in a feerate diagram.
// Return 1 if the interpolated point is greater than fee_compare; 0 if they
// are equal; -1 otherwise.
int InterpolateValueAndCompare(int64_t eval_size, const FeeFrac& p1, const FeeFrac& p2, CAmount fee_compare)
{
    // Interpolate between two points using the formula:
    // y = y1 + (x - x1) * (y2 - y1) / (x2 - x1)
    // i.e.
    // y = p1.fee + (eval_size - p1.size) * (p2.fee - p1.fee) / (p2.size - p2.size)
    // fee_compare = fee value we want to compare against the interpolated y
    //
    // Then evaluating y > fee_compare is equivalent to checking if y*(x2-x1) > fee_compare*(x2-x1),
    // or y1*(x2-x1) + (x - x1) * (y2 - y1) > fee_compare*(x2-x1).
    int64_t fee_compare_scaled = fee_compare * (p2.size - p1.size); // 1100* 300
    int64_t y_scaled = p1.fee * (p2.size - p1.size) + (eval_size - p1.size) * (p2.fee - p1.fee);
    if (y_scaled > fee_compare_scaled) {
        return 1;
    } else if (y_scaled == fee_compare_scaled) {
        return 0;
    } else {
        return -1;
    }
}

// returns true if the new_diagram is strictly better than the old one; false
// otherwise.
bool CompareFeerateDiagram(std::vector<FeeFrac>& old_diagram, std::vector<FeeFrac>& new_diagram)
{
    size_t old_index=0;
    size_t new_index=0;

    // whether the new diagram has at least one point better than old_diagram
    bool new_better = false;

    // whether the old diagram has at least one point better than new_diagram
    bool old_better = false;

    // Diagrams should be non-empty, and first elements zero in size and fee
    Assert(!old_diagram.empty() && !new_diagram.empty());
    Assert(old_diagram[0].fee == 0 && old_diagram[0].size == 0);
    Assert(new_diagram[0].fee == 0 && new_diagram[0].size == 0);

    // Start by padding the smaller diagram with a transaction that pays the
    // tail feerate up to the size of the larger diagram.
    // For now, use an implicit tail feerate of 0, but we can change this if
    // there's an argument to be made that the true tail feerate is higher.
    // Also, if we end up needing to transform the feerates (eg to avoid
    // negative numbers or overflow in the calculations?), then the tail
    // feerate would need to be transformed as well.
    if (old_diagram.back().size < new_diagram.back().size) {
        old_diagram.push_back({old_diagram.back().fee, new_diagram.back().size});
    } else if (old_diagram.back().size > new_diagram.back().size) {
        new_diagram.push_back({new_diagram.back().fee, old_diagram.back().size});
    }

    while (old_index < old_diagram.size() && new_index < new_diagram.size()) {
        int cmp = 0;
        if (old_diagram[old_index].size < new_diagram[new_index].size) {
            cmp = InterpolateValueAndCompare(old_diagram[old_index].size, new_diagram[new_index-1], new_diagram[new_index], old_diagram[old_index].fee);
            old_better |= (cmp == -1);
            new_better |= (cmp == 1);
            old_index++;
        } else if (old_diagram[old_index].size > new_diagram[new_index].size) {
            cmp = InterpolateValueAndCompare(new_diagram[new_index].size, old_diagram[old_index-1], old_diagram[old_index], new_diagram[new_index].fee);
            old_better |= (cmp == 1);
            new_better |= (cmp == -1);
            new_index++;
        } else {
            if (old_diagram[old_index].fee > new_diagram[new_index].fee) {
                old_better = true;
            } else if (old_diagram[old_index].fee < new_diagram[new_index].fee) {
                new_better = true;
            }
            old_index++;
            new_index++;
        }
    }

    // New is strictly better at all points; we'll take it
    return new_better && !old_better;
}

std::optional<std::string> ImprovesFeerateDiagram(CTxMemPool& pool,
                                                const CTxMemPool::setEntries& direct_conflicts,
                                                const CTxMemPool::setEntries& all_conflicts,
                                                int64_t replacement_vsize,
                                                CAmount replacement_fees)
{
    // Require that the replacement strictly improve the mempool's fee vs. size diagram.
    std::vector<FeeFrac> old_diagram, new_diagram;

    // ok!
    const auto err_string{pool.CalculateFeerateDiagramsForRBF(replacement_fees, replacement_vsize, direct_conflicts, all_conflicts, old_diagram, new_diagram)};

    if (err_string.has_value()) {
        return strprintf("unable to compute mining score");
    }

    if (!CompareFeerateDiagram(old_diagram, new_diagram)) {
        return strprintf("insufficient feerate");
    }
    return std::nullopt;
}
