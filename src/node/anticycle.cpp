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

// Order transactions so a parent precedes any of its children within the set (required to re-add
// the set as a package). The input set is small (a chunk's worth).
static std::vector<CTransactionRef> TopoSort(const std::vector<CTransactionRef>& txns)
{
    std::set<Txid> ids;
    for (const auto& t : txns) ids.insert(t->GetHash());
    std::vector<CTransactionRef> sorted;
    std::set<Txid> placed;
    while (sorted.size() < txns.size()) {
        const size_t before = sorted.size();
        for (const auto& t : txns) {
            if (placed.count(t->GetHash())) continue;
            const bool parents_placed = std::none_of(t->vin.begin(), t->vin.end(),
                [&](const CTxIn& in) { return ids.count(in.prevout.hash) && !placed.count(in.prevout.hash); });
            if (parents_placed) { sorted.push_back(t); placed.insert(t->GetHash()); }
        }
        if (sorted.size() == before) { // no progress (cycle -- impossible for valid txns); bail
            for (const auto& t : txns) if (placed.insert(t->GetHash()).second) sorted.push_back(t);
        }
    }
    return sorted;
}

void AntiCycle::MempoolTransactionsReplaced(const MempoolReplacementInfo& info)
{
    // Park the displaced CHUNK -- the mining-score unit, including surviving chunk-mates,
    // reconstructed at eviction and carried in the feed. Not the whole cluster (over-grab), and
    // not just the evicted portion (that drops the now-unbumped parent, which is the prime
    // next-eviction candidate, leaving the package unreinstatable if it later goes).
    // TODO: filter by chunk feerate >= cached next-block line; for now park every replacement,
    // which is correct on an uncongested mempool.
    if (info.displaced_chunk.empty()) return;
    CAmount value = 0;
    for (const auto& rt : info.replaced) value = std::max(value, rt.mining_feerate.fee); // chunk fee
    std::vector<CTransactionRef> pkg = TopoSort(info.displaced_chunk);
    int64_t weight = 0;
    for (const auto& t : pkg) weight += GetTransactionWeight(*t);
    m_buffer.Park({.txns = std::move(pkg), .value = value, .weight = weight});
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
