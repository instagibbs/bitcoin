// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PKGRELAY_H
#define BITCOIN_NODE_PKGRELAY_H

#include <common/bloom.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <protocol.h>
#include <sync.h>
#include <txmempool.h>

#include <cstddef>
#include <utility>
#include <vector>

class CTxMemPoolEntry;

namespace node {
/** Maximum number of transactions a PackageFallback holds. */
inline constexpr size_t MAX_PKG_FALLBACK{1000};

/** Return the parent to announce this transaction with to a package relay peer, or nullptr to
 *  announce it on its own. A transaction is paired with its parent if it has exactly one unconfirmed
 *  parent, which has no unconfirmed parents and no other unconfirmed children, and its chunk in a
 *  linearization of the two pays the peer's feefilter. That chunk is the child alone if the child
 *  does not pay a higher feerate than the parent, and both transactions otherwise.
 *
 *  Only a parent's only child is paired: the children of one parent would each make a peer download
 *  the parent again, while the fees pay for relaying it once. */
const CTxMemPoolEntry* GetPackageRelayParent(const CTxMemPool& pool, const CTxMemPoolEntry& child, const CFeeRate& filterrate)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** What to announce to a peer. */
struct InventoryToSend {
    /** Packages, with pkginv. */
    std::vector<PkgInv> pkgs;
    /** Transactions on their own, with inv. */
    std::vector<CTransactionRef> txs;
};

/** Decide how to announce mempool transactions, given best first (see
 *  CTxMemPool::ExtractBestByMiningScoreWithTopology), to a peer:
 *  - If the peer relays packages, a transaction with a parent to announce it with (see
 *    GetPackageRelayParent) is announced in a package with it, unless the peer knows the transaction
 *    or the package. Its parent is then not announced on its own.
 *  - Other transactions are announced on their own if they pay the peer's feefilter. Whether the peer
 *    knows them is left to the caller.
 *  - Then the transactions in `fallback` (see PackageFallback) that are in the mempool and pay the
 *    feefilter, on their own and without pairing them.
 *  `known` holds the hashes the peer knows: wtxids, and the ids of packages we announced to it. */
InventoryToSend SelectInventory(const CTxMemPool& pool, const std::vector<CTxMemPool::txiter>& txs,
                                const std::vector<Wtxid>& fallback, const CFeeRate& filterrate,
                                bool pkgrelay, const CRollingBloomFilter& known)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs);

/** Transactions to announce to a peer on their own, because it asked for a package with them that we
 *  could not serve any more. We may have announced them only in that package (see SelectInventory),
 *  and the peer would not hear of them from us otherwise. */
class PackageFallback
{
    std::vector<Wtxid> m_wtxids;

public:
    /** Queue the transactions of the package that are in the mempool and not known to the peer,
     *  each once, up to MAX_PKG_FALLBACK. */
    void Add(const PkgInv& pkg, const CTxMemPool& pool, const CRollingBloomFilter& known);
    /** The queued transactions, leaving none queued and no memory allocated. */
    std::vector<Wtxid> Take() { return std::exchange(m_wtxids, {}); }
    bool empty() const { return m_wtxids.empty(); }
    size_t size() const { return m_wtxids.size(); }
};
} // namespace node

#endif // BITCOIN_NODE_PKGRELAY_H
