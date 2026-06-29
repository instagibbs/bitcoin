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

std::vector<CTransactionRef> AntiCycle::BuildVictimCluster(const std::vector<ReplacedTransaction>& replaced) const
{
    std::vector<CTransactionRef> cluster;
    std::set<Txid> ids;
    const auto add = [&](const CTransactionRef& t) {
        if (ids.insert(t->GetHash()).second) cluster.push_back(t);
    };
    for (const auto& rt : replaced) add(rt.tx);
    // Pull in any surviving mempool parents of the evicted transactions (e.g. a CPFP parent that
    // outlived its evicted child); a parent evicted alongside its child is already present.
    for (const auto& rt : replaced) {
        for (const auto& in : rt.tx->vin) {
            if (auto p = m_mempool.get(in.prevout.hash)) add(p);
        }
    }
    if (cluster.size() > 2) return {}; // beyond 1P1C: not parked (PoC bound)
    // Order parent-before-child so the cluster can be re-added as a package.
    if (cluster.size() == 2 &&
        std::any_of(cluster[0]->vin.begin(), cluster[0]->vin.end(),
                    [&](const CTxIn& in) { return in.prevout.hash == cluster[1]->GetHash(); })) {
        std::swap(cluster[0], cluster[1]);
    }
    return cluster;
}

void AntiCycle::MempoolTransactionsReplaced(const MempoolReplacementInfo& info)
{
    // TODO: filter to near-top -- mining_feerate >= cached next-block line. For now park every
    // replacement; the line filter arrives with the BlockConnected handler.
    std::vector<CTransactionRef> cluster = BuildVictimCluster(info.replaced);
    if (cluster.empty()) return;
    int64_t weight = 0;
    for (const auto& t : cluster) weight += GetTransactionWeight(*t);
    CAmount value = 0;
    for (const auto& rt : info.replaced) value += rt.mining_feerate.fee;
    m_buffer.Park({.txns = std::move(cluster), .value = value, .weight = weight});
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
