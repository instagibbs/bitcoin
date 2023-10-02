// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <numeric>

/** IsTopoSortedPackage where a set of txids has been pre-populated. The set is assumed to be correct and
 * is mutated within this function (even if return value is false). */
bool IsTopoSortedPackage(const Package& txns, std::unordered_set<uint256, SaltedTxidHasher>& later_txids)
{
    // Avoid misusing this function: later_txids should contain the txids of txns.
    Assume(txns.size() == later_txids.size());

    // later_txids always contains the txids of this transaction and the ones that come later in
    // txns. If any transaction's input spends a tx in that set, we've found a parent placed later
    // than its child.
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            if (later_txids.find(input.prevout.hash) != later_txids.end()) {
                // The parent is a subsequent transaction in the package.
                return false;
            }
        }
        // Avoid misusing this function: later_txids must contain every tx.
        Assume(later_txids.erase(tx->GetHash()) == 1);
    }

    // Avoid misusing this function: later_txids should have contained the txids of txns.
    Assume(later_txids.empty());
    return true;
}

bool IsTopoSortedPackage(const Package& txns)
{
    std::unordered_set<uint256, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    return IsTopoSortedPackage(txns, later_txids);
}

bool IsConsistentPackage(const Package& txns)
{
    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
    for (const auto& tx : txns) {
        if (tx->vin.empty()) {
            // This function checks consistency based on inputs, and we can't do that if there are
            // no inputs. Duplicate empty transactions are also not consistent with one another.
            // This doesn't create false negatives, as unconfirmed transactions are not allowed to
            // have no inputs.
            return false;
        }
        for (const auto& input : tx->vin) {
            if (inputs_seen.find(input.prevout) != inputs_seen.end()) {
                // This input is also present in another tx in the package.
                return false;
            }
        }
        // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
        // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
        // and we want to report that from CheckTransaction instead.
        std::transform(tx->vin.cbegin(), tx->vin.cend(), std::inserter(inputs_seen, inputs_seen.end()),
                       [](const auto& input) { return input.prevout; });
    }
    return true;
}

bool IsWellFormedPackage(const Package& txns, PackageValidationState& state, bool require_sorted)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-many-transactions");
    }

    const int64_t total_weight = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetTransactionWeight(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx weight.
    if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
    }

    std::unordered_set<uint256, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    // Package must not contain any duplicate transactions, which is checked by txid. This also
    // includes transactions with duplicate wtxids and same-txid-different-witness transactions.
    if (later_txids.size() != txns.size()) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-contains-duplicates");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    if (require_sorted && !IsTopoSortedPackage(txns, later_txids)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
    }

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    if (!IsConsistentPackage(txns)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
    }
    return true;
}

bool IsChildWithParents(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    if (package.size() < 2) return false;

    // The package is expected to be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> input_txids;
    std::transform(child->vin.cbegin(), child->vin.cend(),
                   std::inserter(input_txids, input_txids.end()),
                   [](const auto& input) { return input.prevout.hash; });

    // Every transaction must be a parent of the last transaction in the package.
    return std::all_of(package.cbegin(), package.cend() - 1,
                       [&input_txids](const auto& ptx) { return input_txids.count(ptx->GetHash()) > 0; });
}

bool IsChildWithParentsTree(const Package& package)
{
    if (!IsChildWithParents(package)) return false;
    std::unordered_set<uint256, SaltedTxidHasher> parent_txids;
    std::transform(package.cbegin(), package.cend() - 1, std::inserter(parent_txids, parent_txids.end()),
                   [](const auto& ptx) { return ptx->GetHash(); });
    // Each parent must not have an input who is one of the other parents.
    return std::all_of(package.cbegin(), package.cend() - 1, [&](const auto& ptx) {
        for (const auto& input : ptx->vin) {
            if (parent_txids.count(input.prevout.hash) > 0) return false;
        }
        return true;
    });
}

// Calculates curr_tx's in-package ancestor set. If the tx spends another tx in the package, calls
// visit() for that transaction first, since any transaction's ancestor set includes its parents'
// ancestor sets. Transaction dependency cycles are not possible without breaking sha256 and
// duplicate transactions were already checked, so this won't recurse infinitely.  After this
// function returns, curr_tx's entry in ancestor_set_map is guaranteed to contain a non-empty
// ancestor_subset.
void visit(const CTransactionRef& curr_tx,
           const std::map<Txid, CTransactionRef>& txid_to_tx,
           std::map<Txid, std::set<Txid>>& ancestor_set_map)
{
    const Txid& curr_txid = curr_tx->GetHash();
    // Already visited? Return now.
    auto curr_result_iter = ancestor_set_map.find(curr_txid);
    if (curr_result_iter == ancestor_set_map.end()) return;

    std::set<Txid> my_ancestors;
    my_ancestors.insert(curr_txid);

    // Look up in-package parents via prevouts.
    for (const auto& input : curr_tx->vin) {
        const auto& parent_txid = Txid::FromUint256(input.prevout.hash);

        // Not a package tx? Skip.
        auto iter_parent_in_map = ancestor_set_map.find(parent_txid);
        if (iter_parent_in_map == ancestor_set_map.end()) continue;

        // Recursively populate the parent first.
        if (iter_parent_in_map->second.empty()) {
            visit(txid_to_tx.at(parent_txid), txid_to_tx, ancestor_set_map);
        }

        // The ancestors of my parents are also my ancestors.
        const auto& parent_ancestor_set = ancestor_set_map.at(parent_txid);
        Assume(!parent_ancestor_set.empty());
        // This recursive call should not have included ourselves; it should be impossible for this
        // tx to be both an ancestor and a descendant of us.
        Assume(ancestor_set_map.at(curr_txid).empty());
        my_ancestors.insert(parent_ancestor_set.cbegin(), parent_ancestor_set.cend());
    }
    curr_result_iter->second = std::move(my_ancestors);
}

std::map<Txid, std::set<Txid>> CalculateInPackageAncestors(const Package& package)
{
    // Txid to tx for quick lookup
    std::map<Txid, CTransactionRef> txid_to_tx;
    // Results we will return
    std::map<Txid, std::set<Txid>> result;

    // We cannot deal with duplicates and conflicts. Return an empty map.
    if (!IsConsistentPackage(package)) return result;

    // Populate m_txid_to_entry for quick lookup.
    for (const auto& tx : package) {
        // If duplicate Txids exist, we cannot continue. Just return an empty map.
        if (!Assume(txid_to_tx.emplace(tx->GetHash(), tx).second)) return result;
    }

    // Add an empty set for each transaction to the results map.
    for (const auto& tx : package) {
        std::set<Txid> empty;
        result.emplace(tx->GetHash(), empty);
    }

    // For each tx from beginning to end, populate the ancestor set map. This does a recursive DFS
    // by tracing input prevouts; best-case runtime is when the list is already sorted.
    for (const auto& tx : package) {
        if (result.at(tx->GetHash()).empty()) {
            visit(tx, txid_to_tx, result);
        }
    }

    return result;
}
