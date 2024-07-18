// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/truc_policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/check.h>

#include <algorithm>
#include <numeric>
#include <vector>

/** Helper for PackageTRUCChecks: Returns a vector containing the indices of transactions (within
 * package) that are direct parents of ptx. */
std::vector<size_t> FindInPackageParents(const Package& package, const CTransactionRef& ptx)
{
    std::vector<size_t> in_package_parents;

    std::set<Txid> possible_parents;
    for (auto &input : ptx->vin) {
        possible_parents.insert(input.prevout.hash);
    }

    for (size_t i{0}; i < package.size(); ++i) {
        const auto& tx = package.at(i);
        // We assume the package is sorted, so that we don't need to continue
        // looking past the transaction itself.
        if (&(*tx) == &(*ptx)) break;
        if (possible_parents.count(tx->GetHash())) {
            in_package_parents.push_back(i);
        }
    }
    return in_package_parents;
}

/** Helper for PackageTRUCChecks, storing info for a mempool or package parent. */
struct ParentInfo {
    /** Txid used to identify this parent by prevout */
    const Txid& m_txid;
    /** Wtxid used for debug string */
    const Wtxid& m_wtxid;
    /** version used to check inheritance of TRUC and non-TRUC */
    decltype(CTransaction::version) m_version;
    /** If parent is in mempool, whether it has any descendants in mempool. */
    bool m_has_mempool_descendant;

    ParentInfo() = delete;
    ParentInfo(const Txid& txid, const Wtxid& wtxid, decltype(CTransaction::version) version, bool has_mempool_descendant) :
        m_txid{txid}, m_wtxid{wtxid}, m_version{version},
        m_has_mempool_descendant{has_mempool_descendant}
    {}
};

std::optional<std::string> PackageTRUCChecks(const CTransactionRef& ptx, int64_t vsize,
                                           const Package& package,
                                           const CTxMemPool::setEntries& mempool_ancestors)
{
    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(TRUC_ANCESTOR_LIMIT == 2);
    static_assert(TRUC_DESCENDANT_LIMIT == 2);

    const auto in_package_parents{FindInPackageParents(package, ptx)};

    // Now we have all ancestors, so we can start checking TRUC rules.
    if (ptx->version == TRUC_VERSION) {
        // SingleTRUCChecks should have checked this already.
        if (!Assume(vsize <= TRUC_MAX_VSIZE)) {
            return strprintf("version=3 tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
                             ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(), vsize, TRUC_MAX_VSIZE);
        }

        if (mempool_ancestors.size() + in_package_parents.size() + 1 > TRUC_ANCESTOR_LIMIT) {
            return strprintf("tx %s (wtxid=%s) would have too many ancestors",
                             ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString());
        }

        const bool has_parent{mempool_ancestors.size() + in_package_parents.size() > 0};
        if (has_parent) {
            // A TRUC child cannot be too large.
            if (vsize > TRUC_CHILD_MAX_VSIZE) {
                return strprintf("version=3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
                                 ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(),
                                 vsize, TRUC_CHILD_MAX_VSIZE);
            }

            // Exactly 1 parent exists, either in mempool or package. Find it.
            const auto parent_info = [&] {
                if (mempool_ancestors.size() > 0) {
                    auto& mempool_parent = *mempool_ancestors.begin();
                    return ParentInfo{mempool_parent->GetTx().GetHash(),
                                      mempool_parent->GetTx().GetWitnessHash(),
                                      mempool_parent->GetTx().version,
                                      /*has_mempool_descendant=*/mempool_parent->GetCountWithDescendants() > 1};
                } else {
                    auto& parent_index = in_package_parents.front();
                    auto& package_parent = package.at(parent_index);
                    return ParentInfo{package_parent->GetHash(),
                                      package_parent->GetWitnessHash(),
                                      package_parent->version,
                                      /*has_mempool_descendant=*/false};
                }
            }();

            // If there is a parent, it must have the right version.
            if (parent_info.m_version != TRUC_VERSION) {
                return strprintf("version=3 tx %s (wtxid=%s) cannot spend from non-version=3 tx %s (wtxid=%s)",
                                 ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(),
                                 parent_info.m_txid.ToString(), parent_info.m_wtxid.ToString());
            }

            for (const auto& package_tx : package) {
                // Skip same tx.
                if (&(*package_tx) == &(*ptx)) continue;

                for (auto& input : package_tx->vin) {
                    // Fail if we find another tx with the same parent. We don't check whether the
                    // sibling is to-be-replaced (done in SingleTRUCChecks) because these transactions
                    // are within the same package.
                    if (input.prevout.hash == parent_info.m_txid) {
                        return strprintf("tx %s (wtxid=%s) would exceed descendant count limit",
                                         parent_info.m_txid.ToString(),
                                         parent_info.m_wtxid.ToString());
                    }

                    // This tx can't have both a parent and an in-package child.
                    if (input.prevout.hash == ptx->GetHash()) {
                        return strprintf("tx %s (wtxid=%s) would have too many ancestors",
                                         package_tx->GetHash().ToString(), package_tx->GetWitnessHash().ToString());
                    }
                }
            }

            if (parent_info.m_has_mempool_descendant) {
                return strprintf("tx %s (wtxid=%s) would exceed descendant count limit",
                                parent_info.m_txid.ToString(), parent_info.m_wtxid.ToString());
            }
        }
    } else {
        // Non-TRUC transactions cannot have TRUC parents.
        for (auto it : mempool_ancestors) {
            if (it->GetTx().version == TRUC_VERSION) {
                return strprintf("non-version=3 tx %s (wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)",
                                 ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(),
                                 it->GetSharedTx()->GetHash().ToString(), it->GetSharedTx()->GetWitnessHash().ToString());
            }
        }
        for (const auto& index: in_package_parents) {
            if (package.at(index)->version == TRUC_VERSION) {
                return strprintf("non-version=3 tx %s (wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)",
                                 ptx->GetHash().ToString(),
                                 ptx->GetWitnessHash().ToString(),
                                 package.at(index)->GetHash().ToString(),
                                 package.at(index)->GetWitnessHash().ToString());
            }
        }
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, CTransactionRef>> SingleTRUCChecks(const CTransactionRef& ptx,
                                          const CTxMemPool::setEntries& mempool_ancestors,
                                          const std::set<Txid>& direct_conflicts,
                                          int64_t vsize)
{
    // Check TRUC and non-TRUC inheritance.
    for (const auto& entry : mempool_ancestors) {
        if (ptx->version != TRUC_VERSION && entry->GetTx().version == TRUC_VERSION) {
            return std::make_pair(strprintf("non-version=3 tx %s (wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)",
                             ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(),
                             entry->GetSharedTx()->GetHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString()),
                nullptr);
        } else if (ptx->version == TRUC_VERSION && entry->GetTx().version != TRUC_VERSION) {
            return std::make_pair(strprintf("version=3 tx %s (wtxid=%s) cannot spend from non-version=3 tx %s (wtxid=%s)",
                             ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(),
                             entry->GetSharedTx()->GetHash().ToString(), entry->GetSharedTx()->GetWitnessHash().ToString()),
                nullptr);
        }
    }

    // This function is specialized for these limits, and must be reimplemented if they ever change.
    static_assert(TRUC_ANCESTOR_LIMIT == 2);
    static_assert(TRUC_DESCENDANT_LIMIT == 2);

    // The rest of the rules only apply to transactions with version=3.
    if (ptx->version != TRUC_VERSION) return std::nullopt;

    if (vsize > TRUC_MAX_VSIZE) {
        return std::make_pair(strprintf("version=3 tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
                         ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(), vsize, TRUC_MAX_VSIZE),
            nullptr);
    }

    // Check that TRUC_ANCESTOR_LIMIT would not be violated.
    if (mempool_ancestors.size() + 1 > TRUC_ANCESTOR_LIMIT) {
        return std::make_pair(strprintf("tx %s (wtxid=%s) would have too many ancestors",
                         ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString()),
            nullptr);
    }

    // Remaining checks only pertain to transactions with unconfirmed ancestors.
    if (mempool_ancestors.size() > 0) {
        // If this transaction spends TRUC parents, it cannot be too large.
        if (vsize > TRUC_CHILD_MAX_VSIZE) {
            return std::make_pair(strprintf("version=3 child tx %s (wtxid=%s) is too big: %u > %u virtual bytes",
                             ptx->GetHash().ToString(), ptx->GetWitnessHash().ToString(), vsize, TRUC_CHILD_MAX_VSIZE),
                nullptr);
        }

        // Check the descendant counts of in-mempool ancestors.
        const auto& parent_entry = *mempool_ancestors.begin();
        // If there are any ancestors, this is the only child allowed. The parent cannot have any
        // other descendants. We handle the possibility of multiple children as that case is
        // possible through a reorg.
        const auto& children = parent_entry->GetMemPoolChildrenConst();
        // Don't double-count a transaction that is going to be replaced. This logic assumes that
        // any descendant of the TRUC transaction is a direct child, which makes sense because a
        // TRUC transaction can only have 1 descendant.
        const bool child_will_be_replaced = !children.empty() &&
            std::any_of(children.cbegin(), children.cend(),
                [&direct_conflicts](const CTxMemPoolEntry& child){return direct_conflicts.count(child.GetTx().GetHash()) > 0;});
        if (parent_entry->GetCountWithDescendants() + 1 > TRUC_DESCENDANT_LIMIT && !child_will_be_replaced) {
            // Allow sibling eviction for TRUC transaction: if another child already exists, even if
            // we don't conflict inputs with it, consider evicting it under RBF rules. We rely on TRUC rules
            // only permitting 1 descendant, as otherwise we would need to have logic for deciding
            // which descendant to evict. Skip if this isn't true, e.g. if the transaction has
            // multiple children or the sibling also has descendants due to a reorg.
            const bool consider_sibling_eviction{parent_entry->GetCountWithDescendants() == 2 &&
                children.begin()->get().GetCountWithAncestors() == 2};

            // Return the sibling if its eviction can be considered. Provide the "descendant count
            // limit" string either way, as the caller may decide not to do sibling eviction.
            return std::make_pair(strprintf("tx %u (wtxid=%s) would exceed descendant count limit",
                                            parent_entry->GetSharedTx()->GetHash().ToString(),
                                            parent_entry->GetSharedTx()->GetWitnessHash().ToString()),
                                  consider_sibling_eviction ?  children.begin()->get().GetSharedTx() : nullptr);
        }
    }
    return std::nullopt;
}

bool CheckValidEphemeralTx(const CTransaction& tx, CFeeRate dust_relay_fee, CAmount txfee, TxValidationState& state)
{
    bool has_dust = false;
    for (const CTxOut& txout : tx.vout) {
        if (IsDust(txout, dust_relay_fee)) {
            // We only allow a single dusty output
            if (has_dust) {
                return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "dust");
            }
            has_dust = true;
         }
    }

    // No dust; it's complete standard already
    if (!has_dust) return true;

    // Makes spending checks inference simple via topology restrictions,
    // can be relaxed if spending checks can be done easier in future.
    if (tx.version != TRUC_VERSION) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "dust");
    }

    // We never want to give incentives to mine this alone
    if (txfee != 0) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "dust");
    }

    return true;
}

std::optional<uint256> CheckEphemeralSpends(const Package& package, CFeeRate dust_relay_rate)
{
    // Package is topologically sorted, and PreChecks ensures that
    // there is up to one dust output per tx.

    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));

    // Running tally of unspent dust
    std::unordered_set<COutPoint, SaltedOutpointHasher> unspent_dust;

    // If a parent tx has dust, we have to check for the spend
    // Single dust per tx possible
    std::map<Txid, uint32_t> map_tx_dust;

    for (const auto& tx : package) {
        std::unordered_set<Txid, SaltedTxidHasher> child_unspent_dust;
        for (const auto& tx_input : tx->vin) {
            // Parent tx had dust, child MUST be sweeping it
            // if it's spending any output from parent
            if (map_tx_dust.count(tx_input.prevout.hash)) {
                child_unspent_dust.insert(tx_input.prevout.hash);
            }
        }

        // Now that we've built a list of parent txids
        // that have dust, make sure that all parent's
        // dust are swept by this same tx
        for (const auto& tx_input : tx->vin) {
            const auto& prevout = tx_input.prevout;
            // Parent tx had dust, child MUST be sweeping it
            // if it's spending any output from parent
            if (map_tx_dust.count(prevout.hash) &&
                map_tx_dust[prevout.hash] == prevout.n) {
                 child_unspent_dust.erase(prevout.hash);
            }

            // We want to detect dangling dust too
            unspent_dust.erase(tx_input.prevout);
        }

        if (!child_unspent_dust.empty()) {
            return tx->GetHash();
        }

        // Process new dust
        for (uint32_t i=0; i<tx->vout.size(); i++) {
            if (IsDust(tx->vout[i], dust_relay_rate)) {
                // CheckValidEphemeralTx should disallow multiples
                Assume(map_tx_dust.count(tx->GetHash()) == 0);
                map_tx_dust[tx->GetHash()] = i;
                unspent_dust.insert(COutPoint(tx->GetHash(), i));
            }
        }

    }

    if (!unspent_dust.empty()) {
        // Return something useful
        return unspent_dust.begin()->hash;
    }

    return std::nullopt;
}

std::optional<std::string> CheckEphemeralSpends(const CTransactionRef& ptx,
                                                const CTxMemPool::setEntries& ancestors,
                                                CFeeRate dust_relay_feerate)
{
    std::unordered_set<COutPoint, SaltedOutpointHasher> unspent_dust;

    std::unordered_set<Txid, SaltedTxidHasher> parents;
    for (const auto& tx_input : ptx->vin) {
        parents.insert(tx_input.prevout.hash);
    }

    for (const auto& entry : ancestors) {
        const auto& tx = entry->GetTx();
        // Only deal with direct parents
        if (parents.count(tx.GetHash()) == 0) continue;
        for (uint32_t i=0; i<tx.vout.size(); i++) {
            if (IsDust(tx.vout[i], dust_relay_feerate)) {
                unspent_dust.insert(COutPoint(tx.GetHash(), i));
            }
        }
    }

    for (const auto& input : ptx->vin) {
        unspent_dust.erase(input.prevout);
    }

    if (!unspent_dust.empty()) {
        return strprintf("tx does not spend parent ephemeral dust");
    }

    return std::nullopt;
}
