// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pkgrelay.h>

#include <kernel/mempool_entry.h>
#include <util/feefrac.h>

#include <algorithm>
#include <set>

namespace node {
const CTxMemPoolEntry* GetPackageRelayParent(const CTxMemPool& pool, const CTxMemPoolEntry& child, const CFeeRate& filterrate)
{
    const auto parents{pool.GetParents(child)};
    if (parents.size() != 1) return nullptr;
    const CTxMemPoolEntry& parent{parents.front().get()};
    if (!pool.GetParents(parent).empty() || pool.GetChildren(parent).size() != 1) return nullptr;

    FeeFrac chunk{child.GetFee(), child.GetTxSize()};
    const FeeFrac parent_feefrac{parent.GetFee(), parent.GetTxSize()};
    if (ByRatio{chunk} > ByRatio{parent_feefrac}) chunk += parent_feefrac;
    if (chunk.fee < filterrate.GetFee(chunk.size)) return nullptr;
    return &parent;
}

InventoryToSend SelectInventory(const CTxMemPool& pool, const std::vector<CTxMemPool::txiter>& txs,
                                const std::vector<Wtxid>& fallback, const CFeeRate& filterrate,
                                bool pkgrelay, const CRollingBloomFilter& known)
{
    InventoryToSend res;
    res.txs.reserve(txs.size() + fallback.size());
    // Parents announced in a package, not to be announced on their own.
    std::set<Wtxid> paired_parents;
    for (const auto& txiter : txs) {
        if (pkgrelay) {
            if (const auto* parent{GetPackageRelayParent(pool, *txiter, filterrate)}) {
                const PkgInv pkg{parent->GetTx().GetWitnessHash(), txiter->GetTx().GetWitnessHash()};
                // The package id is known if we announced the package before and the child is being
                // relayed again.
                if (!known.contains(pkg.child.ToUint256()) && !known.contains(pkg.GetId().ToUint256())) {
                    res.pkgs.push_back(pkg);
                    paired_parents.insert(pkg.parent);
                }
                continue;
            }
        }
        if (txiter->GetFee() < filterrate.GetFee(txiter->GetTxSize())) {
            continue; // higher feerate CPFP txs may follow, so just skip, don't stop
        }
        res.txs.push_back(txiter->GetSharedTx());
    }
    std::erase_if(res.txs, [&](const auto& tx) { return paired_parents.contains(tx->GetWitnessHash()); });
    // Not paired again: their package could not be served to this peer.
    for (const Wtxid& wtxid : fallback) {
        const auto txiter{pool.GetIter(wtxid)};
        if (!txiter || (*txiter)->GetFee() < filterrate.GetFee((*txiter)->GetTxSize())) continue;
        res.txs.push_back((*txiter)->GetSharedTx());
    }
    return res;
}

void PackageFallback::Add(const PkgInv& pkg, const CTxMemPool& pool, const CRollingBloomFilter& known)
{
    for (const Wtxid& wtxid : {pkg.parent, pkg.child}) {
        if (m_wtxids.size() >= MAX_PKG_FALLBACK) return;
        if (!pool.exists(wtxid) || known.contains(wtxid.ToUint256()) || std::ranges::find(m_wtxids, wtxid) != m_wtxids.end()) continue;
        m_wtxids.push_back(wtxid);
    }
}
} // namespace node
