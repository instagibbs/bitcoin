// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/anticycle.h>

#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <txmempool.h>

#include <set>
#include <utility>

namespace node {

AntiCycle::AntiCycle(CTxMemPool& mempool, int64_t max_park_weight)
    : m_mempool{mempool}, m_buffer{max_park_weight} {}

std::vector<CTransactionRef> AntiCycle::Build1P1C(const CTransactionRef& evicted) const
{
    std::vector<CTransactionRef> pkg{evicted};
    std::set<Txid> parent_ids;
    CTransactionRef parent;
    for (const auto& in : evicted->vin) {
        if (auto p = m_mempool.get(in.prevout.hash)) {
            parent_ids.insert(p->GetHash());
            parent = p;
        }
    }
    // Bounded to 1P1C: include the parent only if there is exactly one distinct mempool parent.
    if (parent_ids.size() == 1) pkg.insert(pkg.begin(), parent);
    return pkg;
}

void AntiCycle::MempoolTransactionsReplaced(const MempoolReplacementInfo& info)
{
    for (const auto& rt : info.replaced) {
        // TODO: filter to near-top -- rt.mining_feerate >= cached next-block line. For now park
        // every replaced package; the line filter arrives with the BlockConnected handler.
        std::vector<CTransactionRef> pkg = Build1P1C(rt.tx);
        int64_t weight = 0;
        for (const auto& t : pkg) weight += GetTransactionWeight(*t);
        m_buffer.Park({.txns = std::move(pkg), .value = rt.mining_feerate.fee, .weight = weight});
    }
}

} // namespace node
