// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_ANTICYCLE_H
#define BITCOIN_NODE_ANTICYCLE_H

#include <consensus/consensus.h>
#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <util/feefrac.h>
#include <validationinterface.h>

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

class CBlock;
class CBlockIndex;
class ChainstateManager;
class CTxMemPool;
namespace kernel { struct ChainstateRole; }

namespace node {

/** Default cap on the total weight of parked packages (~one block). */
static constexpr int64_t DEFAULT_ANTICYCLE_MAX_WEIGHT{4'000'000};

/** Action the anti-cycling state machine takes for a protected outpoint on a transition. */
enum class CycleAction { kNone, kPark, kClear, kReinstate };

/** The per-outpoint state-machine transition (faithful to the anticycle PoC). `*_above` is
 *  whether the outpoint is spent at/above the next-block line; `spender_changed` whether the
 *  current spender differs from the previous one.
 *
 *  - top -> top (different spender): a next-block victim was displaced -- the cycling move,
 *    generally the attacker -> PARK the displaced victim.
 *  - top -> free/low: the top spender withdrew -> REINSTATE the parked victim.
 *  - free/low -> top: the slot was legitimately refilled at next-block feerate -- generally the
 *    honest owner re-establishing -> CLEAR the stale victim (never resurrect a transaction the
 *    owner deliberately replaced).
 *
 *  This is a pure function so the decision logic is unit-testable in isolation. */
constexpr CycleAction OutpointTransition(bool prev_above, bool now_above, bool spender_changed)
{
    if (prev_above && now_above) return spender_changed ? CycleAction::kPark : CycleAction::kNone;
    if (prev_above && !now_above) return CycleAction::kReinstate;
    if (!prev_above && now_above) return CycleAction::kClear;
    return CycleAction::kNone;
}

/** Coordinator for the anti-cycling mitigation.
 *
 *  Subscribes to mempool/validation events, parks RBF-evicted near-top packages in a
 *  ParkBuffer, and reinstates them through normal validation when their contended outpoint
 *  frees. See docs/replacement-cycling-park-buffer-design.md.
 *
 *  This increment implements park-on-replacement and reinstate-on-free. The free/low->top
 *  clear, the on-chain drain, and the next-block-line filter arrive in later increments. */
class AntiCycle : public CValidationInterface
{
public:
    AntiCycle(ChainstateManager& chainman, CTxMemPool& mempool, int64_t max_park_weight,
              int64_t line_weight = MAX_BLOCK_WEIGHT);

    /** Park the chunk(s) displaced by an RBF replacement, if at/above the next-block line -- the
     *  near-top mining unit. Below-line ("not above thresh") evictions are not cached, so a cheap
     *  squatter cannot deny a near-top victim its slot. */
    void MempoolTransactionsReplaced(const MempoolReplacementInfo& info) override;

    /** B->A clear: when a transaction (re-)takes a protected outpoint into the next-block set from
     *  a free/below-line state, drop any stale parked victim on it -- honest-user protection, and
     *  the reset that lets an honest defender eventually acquire the slot. */
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override;

    /** When a removal leaves a parked package's contended outpoint unspent, reinstate the
     *  package through normal validation. */
    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence) override;

    /** Drop parked packages whose footprint outpoint was spent on-chain by a non-member
     *  transaction (permanently invalid). */
    void BlockConnected(const kernel::ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override;

    /** Recompute and cache the next-block line from the current mempool. Called on block connect;
     *  public so tests can refresh after staging a mempool. */
    void RefreshNextBlockLine();

    /** Inspection access to the park buffer (for tests). */
    const ParkBuffer& buffer() const { return m_buffer; }

private:
    /** Re-add the package members not already in the mempool, through normal validation.
     *  Returns true if anything was accepted. */
    bool Reinstate(const ParkBuffer::ParkedPackage& package);

    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;
    ParkBuffer m_buffer;
    const int64_t m_line_weight;
    FeePerWeight m_next_block_line{};
    /** Outpoints parked by the in-flight A->A replacement, so the replacing transaction's add is
     *  not mistaken for a B->A take of them. Consumed by the next TransactionAddedToMempool. */
    std::set<COutPoint> m_recent_parks;
};

} // namespace node

#endif // BITCOIN_NODE_ANTICYCLE_H
