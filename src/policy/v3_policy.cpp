// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <vector>

std::optional<std::string> PackageV3SanityChecks(const Package& package)
{
    // This should only be called in scenarios where the topo of the package
    // is restricted to a connected component of specific shape.
    Assume(IsChildWithParents(package));

    const bool all_v3{std::all_of(package.cbegin(), package.cend(), [](const auto& tx){ return tx->nVersion == 3; })};
    // Check inheritance rules within package.
    if (!all_v3) {
        // We already checked there was one at least
        Assume(std::any_of(package.cbegin(), package.cend(), [](const auto& tx){ return tx->nVersion == 3; }));
        return strprintf("txs in package are not all v3");
    }

    // Sanity check that package itself obeys ancestor/descendant limits. Assumes that this is
    // ancestor package-shaped. This check is not complete as we have not seen in-mempool ancestors yet.
    if (package.size() > V3_ANCESTOR_LIMIT) {
        const auto& child_wtxid = package.back()->GetWitnessHash();
        return strprintf("tx %s would have too many ancestors", child_wtxid.ToString());
    }

    // Sanity check that a v3 transaction with unconfirmed ancestors is within V3_CHILD_MAX_VSIZE.
    // Again, this assumes that all transactions are part of the last transaction's ancestor set.
    // Sigops adjusted size can only make this value larger once inputs are pulled in.
    if (package.size() > 1) {
        const int64_t vsize = GetVirtualTransactionSize(*package.back(), /*nSigOpCost=*/0, /*bytes_per_sigop=*/0);
        if (vsize > V3_CHILD_MAX_VSIZE) {
            return strprintf("v3 child tx is too big: %u > %u virtual bytes", vsize, V3_CHILD_MAX_VSIZE);
        }
    }

    return std::nullopt;
}

std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors,
                                        unsigned int num_other_ancestors,
                                        unsigned int num_non_v3_in_package_ancestors,
                                        const std::set<Txid>& direct_conflicts,
                                        int64_t vsize)
{
    // Check v3 and non-v3 inheritance.
    for (const auto& entry : ancestors) {
        if (ptx->nVersion != 3 && entry->GetTx().nVersion == 3) {
            return strprintf("non-v3 tx %s cannot spend from v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        } else if (ptx->nVersion == 3 && entry->GetTx().nVersion != 3) {
            return strprintf("v3 tx %s cannot spend from non-v3 tx %s",
                             ptx->GetWitnessHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString());
        }
    }

    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(V3_ANCESTOR_LIMIT == 2);
    static_assert(V3_DESCENDANT_LIMIT == 2);

    if (ptx->nVersion != 3) {
        if (num_other_ancestors - num_non_v3_in_package_ancestors > 0) {
            return strprintf("non-v3 tx %s has a v3 in-package ancestor", ptx->GetWitnessHash().ToString());
        }
        // The rest of the rules only apply to transactions with nVersion=3.
        return std::nullopt;
    }

    // If this is V3, it cannot have in-package ancestors that are non-V3
    if (num_non_v3_in_package_ancestors > 0) {
        return strprintf("tx %s has a non-v3 in-package ancestor", ptx->GetWitnessHash().ToString());
    }

    // Check that V3_ANCESTOR_LIMIT would not be violated, including both in-package and in-mempool.
    if (ancestors.size() + num_other_ancestors + 1 > V3_ANCESTOR_LIMIT) {
        return strprintf("tx %s would have too many ancestors", ptx->GetWitnessHash().ToString());
    }

    // Remaining checks only pertain to transactions with unconfirmed ancestors.
    if (ancestors.size() + num_other_ancestors > 0) {
        // If this transaction spends V3 parents, it cannot be too large.
        if (vsize > V3_CHILD_MAX_VSIZE) {
            return strprintf("v3 child tx is too big: %u > %u virtual bytes", vsize, V3_CHILD_MAX_VSIZE);
        }

        // Check the descendant counts of in-mempool ancestors.
        if (!ancestors.empty()) {
            const auto& parent_entry = *ancestors.begin();
            // If there are any ancestors, this is the only child allowed. The parent cannot have any
            // other descendants.
            const auto& children = parent_entry->GetMemPoolChildrenConst();
            // Don't double-count a transaction that is going to be replaced. This logic assumes that
            // any descendant of the V3 transaction is a direct child, which makes sense because a V3
            // transaction can only have 1 descendant.
            const bool child_will_be_replaced = !children.empty() &&
                std::any_of(children.cbegin(), children.cend(),
                    [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
            if (parent_entry->GetCountWithDescendants() + 1 > V3_DESCENDANT_LIMIT && !child_will_be_replaced) {
                return strprintf("tx %u would exceed descendant count limit", parent_entry->GetTx().GetHash().ToString());
            }
        }
    }
    return std::nullopt;
}
