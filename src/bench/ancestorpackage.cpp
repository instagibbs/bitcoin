// Copyright (c) 2011-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <node/mini_miner.h>
#include <policy/ancestor_packages.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>

static void AncestorPackageLinearization(benchmark::Bench& bench)
{

    FastRandomContext rand{false};
    Package txns;

    int max_cluster_size = 500;
    if (bench.complexityN() > 1) {
        max_cluster_size = static_cast<int>(bench.complexityN());
    }

    std::deque<COutPoint> available_coins;
    for (uint32_t i = 0; i < uint32_t{100}; ++i) {
        available_coins.push_back(COutPoint{uint256::ZERO, i});
    }

    for (uint32_t count = max_cluster_size - 1; !available_coins.empty() && count; --count)
    {
        CMutableTransaction mtx = CMutableTransaction();
        const size_t num_inputs = rand.randrange(available_coins.size()) + 1;
        const size_t num_outputs = rand.randrange(50) + 1;
        for (size_t n{0}; n < num_inputs; ++n) {
            auto prevout = available_coins.front();
            mtx.vin.push_back(CTxIn(prevout, CScript()));
            available_coins.pop_front();
        }
        for (uint32_t n{0}; n < num_outputs; ++n) {
            mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
        }
        CTransactionRef tx = MakeTransactionRef(mtx);
        txns.push_back(tx);

        // At least one output is available for spending by descendant
        for (uint32_t n{0}; n < num_outputs; ++n) {
            if (n == 0 || rand.randbool()) {
                available_coins.push_back(COutPoint{tx->GetHash(), n});
            }
        }
    }

    assert(!available_coins.empty());

    // Now spend all available coins to make sure it's an ancestor package
    size_t num_coins = available_coins.size();
    CMutableTransaction child_mtx;
    for (size_t avail = 0; avail < num_coins; avail++) {
        auto prevout = available_coins[0];
        child_mtx.vin.push_back(CTxIn(prevout, CScript()));
        available_coins.pop_front();
    }
    child_mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
    CTransactionRef child_tx = MakeTransactionRef(child_mtx);
    txns.push_back(child_tx);

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        AncestorPackage ancestor_package(txns);
        assert(ancestor_package.IsAncestorPackage());
        for (size_t i = 0; i < txns.size(); i++) {
            ancestor_package.AddFeeAndVsize(txns[i]->GetHash(), rand.randrange(1000000), rand.randrange(1000));
        }
        ancestor_package.LinearizeWithFees();
    });
}

BENCHMARK(AncestorPackageLinearization, benchmark::PriorityLevel::HIGH);
