// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include<policy/ephemeral_policy.h>
#include<policy/policy.h>

bool CheckValidEphemeralTx(const CTransactionRef& tx, CFeeRate dust_relay_fee, CAmount base_fee, CAmount mod_fee, std::vector<uint32_t>& dust_indexes, TxValidationState& state)
{
    dust_indexes.clear();
    for (size_t i = 0; i < tx->vout.size(); ++i) {
        const auto& output = tx->vout[i];
        if (IsDust(output, dust_relay_fee)) dust_indexes.push_back(i);
    }

    // We never want to give incentives to mine this transaction alone
    if ((base_fee != 0 || mod_fee != 0) &&
        !dust_indexes.empty()) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "dust", "tx with dust output must be 0-fee");
    }

    return true;
}

std::optional<Txid> CheckEphemeralSpends(const std::vector<CTxMemPoolEntry*>& package_entries, CFeeRate dust_relay_rate, const CTxMemPool& tx_pool)
{
    std::map<Txid, CTxMemPoolEntry*> map_txid_ref;
    for (const auto& entry : package_entries) {
        const auto& tx = entry->GetSharedTx();
        map_txid_ref[tx->GetHash()] = entry;
    }

    for (const auto& entry : package_entries) {
        const auto& tx = entry->GetSharedTx();

        Txid txid = tx->GetHash();
        std::unordered_set<Txid, SaltedTxidHasher> processed_parent_set;
        std::unordered_set<COutPoint, SaltedOutpointHasher> unspent_parent_dust;

        for (const auto& tx_input : tx->vin) {
            const Txid& parent_txid{tx_input.prevout.hash};
            // Skip parents we've already checked dust for
            if (processed_parent_set.contains(parent_txid)) continue;

            // We look for an in-package or in-mempool dependency
            const CTxMemPoolEntry* parent_entry = map_txid_ref.contains(parent_txid) ? map_txid_ref[parent_txid] : tx_pool.GetEntry(parent_txid);

            // Accumulate dust from parents
            if (parent_entry) {
                for (const auto& dust_index : parent_entry->GetDustIndexes()) {
                    unspent_parent_dust.insert(COutPoint(parent_txid, dust_index));
                }                
            }

            processed_parent_set.insert(parent_txid);
        }

        // Now that we have gathered parents' dust, make sure it's spent
        // by the child
        for (const auto& tx_input : tx->vin) {
            unspent_parent_dust.erase(tx_input.prevout);
        }

        if (!unspent_parent_dust.empty()) {
            return txid;
        }
    }

    return std::nullopt;
}
