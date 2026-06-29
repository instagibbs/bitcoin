// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <set>
#include <vector>

using node::ParkBuffer;

namespace {
// The external outpoints a package spends (mirror of ParkBuffer's internal computation),
// used to cross-check the buffer's first-come disjointness behaviour.
std::set<COutPoint> Footprint(const std::vector<CTransactionRef>& txns)
{
    std::set<COutPoint> internal;
    for (const auto& tx : txns) {
        for (uint32_t i = 0; i < tx->vout.size(); ++i) internal.emplace(tx->GetHash(), i);
    }
    std::set<COutPoint> fp;
    for (const auto& tx : txns) {
        for (const auto& in : tx->vin) {
            if (!internal.count(in.prevout)) fp.insert(in.prevout);
        }
    }
    return fp;
}
} // namespace

FUZZ_TARGET(park_buffer)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // Small fixed pool of outpoints so packages frequently share inputs, exercising the
    // disjointness / first-come logic and the cap eviction.
    std::vector<COutPoint> pool;
    for (uint8_t i = 0; i < 6; ++i) pool.emplace_back(Txid::FromUint256(uint256{i}), 0);

    ParkBuffer parkbuf{fdp.ConsumeIntegralInRange<int64_t>(0, 4'000'000)};

    LIMITED_WHILE(fdp.ConsumeBool(), 3000) {
        CallOneOf(
            fdp,
            [&] { // Park a package over a random subset of the pool.
                std::vector<COutPoint> inputs;
                for (const auto& op : pool) {
                    if (fdp.ConsumeBool()) inputs.push_back(op);
                }
                if (inputs.empty()) inputs.push_back(pool[fdp.ConsumeIntegralInRange<size_t>(0, pool.size() - 1)]);

                CMutableTransaction mtx;
                for (const auto& in : inputs) mtx.vin.emplace_back(in);
                mtx.vout.emplace_back(CAmount{0}, CScript{} << OP_TRUE);
                std::vector<CTransactionRef> txns{MakeTransactionRef(mtx)};

                // Occasionally a 2-tx package: child spends the parent's output (internal link).
                if (fdp.ConsumeBool()) {
                    CMutableTransaction child;
                    child.vin.emplace_back(COutPoint{txns[0]->GetHash(), 0});
                    child.vout.emplace_back(CAmount{0}, CScript{} << OP_TRUE);
                    txns.push_back(MakeTransactionRef(child));
                }

                const auto fp = Footprint(txns);
                const bool conflict = std::any_of(fp.begin(), fp.end(),
                    [&](const COutPoint& op) { return parkbuf.FindByInput(op) != nullptr; });

                int64_t weight = 0;
                for (const auto& t : txns) weight += GetTransactionWeight(*t);
                const bool admitted = parkbuf.Park({.txns = txns,
                                                     .value = fdp.ConsumeIntegralInRange<CAmount>(0, 1'000'000),
                                                     .weight = weight});
                // First-come disjointness: a footprint-conflicting package is always rejected.
                if (conflict) assert(!admitted);
                parkbuf.SanityCheck();
            },
            [&] { // Look up a random outpoint.
                const auto& op = pool[fdp.ConsumeIntegralInRange<size_t>(0, pool.size() - 1)];
                if (const auto* pkg = parkbuf.FindByInput(op)) {
                    // The queried outpoint must be in the returned package's footprint.
                    assert(Footprint(pkg->txns).count(op));
                }
                parkbuf.SanityCheck();
            },
            [&] { // Remove the package containing a random outpoint.
                const auto& op = pool[fdp.ConsumeIntegralInRange<size_t>(0, pool.size() - 1)];
                if (parkbuf.Remove(op)) {
                    assert(parkbuf.FindByInput(op) == nullptr);
                }
                parkbuf.SanityCheck();
            });
    }
    parkbuf.SanityCheck();
}
