// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <net.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <txorphanage.h>
#include <util/check.h>

#include <cstdint>
#include <memory>


static void OrphanageEviction(benchmark::Bench& bench)
{
    NodeId NUM_PEERS{125};
    unsigned int NUM_TRANSACTIONS{MAX_GLOBAL_ANNOUNCEMENTS};

    FastRandomContext det_rand{true};

    TxOrphanage orphanage;
    for (unsigned int i{0}; i < NUM_TRANSACTIONS; ++i) {
        // Very small transaction
        CMutableTransaction tx;
        tx.vin.emplace_back(Txid::FromUint256(det_rand.rand256()), i);
        tx.vout.resize(1);
        tx.vout[0].scriptPubKey = CScript();
        // Each output progressively larger
        tx.vout[0].nValue = i * CENT;
        auto ptx{MakeTransactionRef(tx)};

        orphanage.AddTx(ptx, i % NUM_PEERS);
    }

    assert(orphanage.Size() == NUM_TRANSACTIONS);

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        orphanage.LimitOrphans(0, det_rand);
    });
}

BENCHMARK(OrphanageEviction, benchmark::PriorityLevel::HIGH);
