// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PARK_BUFFER_H
#define BITCOIN_NODE_PARK_BUFFER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace node {

/** A bounded, fee-ordered store of RBF-evicted transaction packages ("clusters"),
 *  indexed by the external outpoints each package spends (its "footprint").
 *
 *  This is the core of the anti-cycling mitigation: when a near-top transaction is
 *  cycled out of the mempool, its cluster is parked here. When one of the outpoints it
 *  needs frees up (the attacker withdraws the replacement), the parked package is retried
 *  through normal validation.
 *
 *  Invariant: parked packages are mutually disjoint -- no two parked packages spend a
 *  common external outpoint. A newcomer whose footprint conflicts with a parked package
 *  is rejected (first-come). This keeps the buffer's contents jointly fillable, so its
 *  value can't be inflated by mutually-exclusive entries.
 *
 *  TODO: allow a higher-value package to *replace* the conflicting parked package(s) it
 *  would evict (admit only if its value exceeds their summed value). Deferred to avoid an
 *  RBF-style check in admission; first-come is simpler and DoS-resistant, at the cost that
 *  a near-top "squatter" sharing an anyone-can-spend outpoint can deny a victim its slot.
 *
 *  Bounded by a maximum total weight; over the cap, the lowest-value package is evicted
 *  (so occupying the buffer costs ~a block of fees). Not thread-safe. */
class ParkBuffer
{
public:
    /** A parked package: the cluster evicted together, the realizable next-block fee
     *  value used for ranking, and its total weight for cap accounting. */
    struct ParkedPackage {
        std::vector<CTransactionRef> txns;
        CAmount value{0};
        int64_t weight{0};
    };

    explicit ParkBuffer(int64_t max_weight) : m_max_weight{max_weight} {}

    /** Park a package, indexed by its external-input footprint. Admitted only if that
     *  footprint is disjoint from every parked package; returns true if admitted (false
     *  if rejected for conflict). After admission the weight cap is enforced by evicting
     *  the lowest-value package, which may be this one. */
    bool Park(ParkedPackage package);

    /** The package whose footprint contains this outpoint, or nullptr. By the disjointness
     *  invariant at most one package matches. */
    const ParkedPackage* FindByInput(const COutPoint& outpoint) const;

    /** Remove the package whose footprint contains this outpoint (e.g. after it has been
     *  reinstated, or its input was spent on-chain), clearing its entire footprint from
     *  the index. Returns true if a package was removed. */
    bool Remove(const COutPoint& outpoint);

    /** Number of parked packages. */
    size_t Size() const;

    /** Total weight of all parked packages. */
    int64_t TotalWeight() const;

    /** The configured maximum total weight (the cap). */
    int64_t MaxWeight() const { return m_max_weight; }

    /** Cumulative count of packages evicted because the weight cap was exceeded. */
    uint64_t EvictedOverCap() const { return m_evicted_over_cap; }

    /** A copy of every currently parked package, for inspection / stats. */
    std::vector<ParkedPackage> Packages() const;

    /** Assert internal invariants: weight total, index consistency, footprint disjointness,
     *  and the weight cap. For use by tests and fuzzers. */
    void SanityCheck() const;

private:
    const int64_t m_max_weight;
    int64_t m_total_weight{0};
    uint64_t m_next_id{0};
    uint64_t m_evicted_over_cap{0};

    struct Entry {
        ParkedPackage package;
        std::vector<COutPoint> footprint;
    };

    /** Remove an entry: clear its footprint from the index and decrement the weight. */
    void EraseEntry(std::map<uint64_t, Entry>::iterator it);

    /** Parked packages by id. */
    std::map<uint64_t, Entry> m_packages;
    /** Index from each footprint outpoint to its package id. */
    std::map<COutPoint, uint64_t> m_index;
};

} // namespace node

#endif // BITCOIN_NODE_PARK_BUFFER_H
