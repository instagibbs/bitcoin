// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/anticycle.h>

#include <consensus/validation.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>
#include <primitives/block.h>
#include <sync.h>
#include <txmempool.h>
#include <validation.h>

#include <algorithm>
#include <optional>
#include <set>
#include <utility>

namespace node {

AntiCycle::AntiCycle(ChainstateManager& chainman, CTxMemPool& mempool, int64_t max_park_weight)
    : m_chainman{chainman}, m_mempool{mempool}, m_buffer{max_park_weight} {}

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

void AntiCycle::TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason, uint64_t)
{
    // Collect parked packages whose contended outpoint this removal may have left unspent.
    std::vector<std::pair<COutPoint, ParkBuffer::ParkedPackage>> candidates;
    {
        LOCK(m_mempool.cs);
        for (const auto& in : tx->vin) {
            const auto* pkg = m_buffer.FindByInput(in.prevout);
            if (!pkg) continue;
            // The removed tx was a top spender of this outpoint; reinstate only on a
            // top -> free/low transition (it left the outpoint unspent). Decision routed through
            // the unit-tested state machine.
            const bool now_above = m_mempool.GetConflictTx(in.prevout) != nullptr;
            if (OutpointTransition(/*prev_above=*/true, now_above, /*spender_changed=*/true) != CycleAction::kReinstate) continue;
            candidates.emplace_back(in.prevout, *pkg);
        }
    }
    // Attempt re-add outside the mempool lock (ProcessTransaction/ProcessNewPackage lock
    // internally). Re-add goes through normal validation, so it succeeds only if the package
    // can pay its way back in -- retry, not immunity.
    for (const auto& [outpoint, pkg] : candidates) {
        if (Reinstate(pkg)) m_buffer.Remove(outpoint);
    }
}

void AntiCycle::BlockConnected(const kernel::ChainstateRole&, const std::shared_ptr<const CBlock>& block, const CBlockIndex*)
{
    for (const auto& tx : block->vtx) {
        for (const auto& in : tx->vin) {
            const auto* pkg = m_buffer.FindByInput(in.prevout);
            if (!pkg) continue;
            // A package member confirming is the package progressing on-chain, not invalidation;
            // only a non-member spend of a footprint outpoint makes the package unreinstatable.
            const bool by_member = std::any_of(pkg->txns.begin(), pkg->txns.end(),
                [&](const CTransactionRef& t) { return t->GetHash() == tx->GetHash(); });
            if (!by_member) m_buffer.Remove(in.prevout);
        }
    }
}

bool AntiCycle::Reinstate(const ParkBuffer::ParkedPackage& package)
{
    std::vector<CTransactionRef> to_add;
    for (const auto& t : package.txns) {
        if (!m_mempool.exists(t->GetHash())) to_add.push_back(t);
    }
    if (to_add.empty()) return false;
    if (to_add.size() == 1) {
        return m_chainman.ProcessTransaction(to_add.front()).m_result_type == MempoolAcceptResult::ResultType::VALID;
    }
    const auto result = WITH_LOCK(::cs_main, return ProcessNewPackage(m_chainman.ActiveChainstate(), m_mempool, to_add, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt));
    return result.m_state.IsValid();
}

} // namespace node
