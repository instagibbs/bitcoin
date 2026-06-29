// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_ANTICYCLE_H
#define BITCOIN_NODE_ANTICYCLE_H

#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <validationinterface.h>

#include <cstdint>
#include <vector>

class CTxMemPool;
struct MempoolReplacementInfo;

namespace node {

/** Coordinator for the anti-cycling mitigation.
 *
 *  Subscribes to mempool/validation events, parks RBF-evicted near-top packages in a
 *  ParkBuffer, and (in later increments) reinstates them through normal validation when the
 *  contended outpoint frees. See docs/replacement-cycling-park-buffer-design.md.
 *
 *  This increment implements park-on-replacement only. */
class AntiCycle : public CValidationInterface
{
public:
    AntiCycle(CTxMemPool& mempool, int64_t max_park_weight);

    /** Park the 1P1C cluster of each transaction evicted by an RBF replacement. */
    void MempoolTransactionsReplaced(const MempoolReplacementInfo& info) override;

    /** Inspection access to the park buffer (for tests). */
    const ParkBuffer& buffer() const { return m_buffer; }

private:
    /** The package to park for an evicted transaction: the transaction itself, plus its single
     *  unconfirmed mempool parent if it has exactly one (bounded to 1P1C). */
    std::vector<CTransactionRef> Build1P1C(const CTransactionRef& evicted) const;

    CTxMemPool& m_mempool;
    ParkBuffer m_buffer;
};

} // namespace node

#endif // BITCOIN_NODE_ANTICYCLE_H
