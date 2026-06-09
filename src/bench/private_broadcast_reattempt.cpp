// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <key.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

// Investigation bench: cost of the cs_main-held loop in
// PeerManagerImpl::ReattemptPrivateBroadcast(), which calls
// ChainstateManager::ProcessTransaction(tx, test_accept=true) once per stale
// private-broadcast transaction under a single LOCK(cs_main).
//
// The whole loop holds cs_main, so the stall = N * cost(one test_accept).
// We measure the per-tx test_accept cost both COLD (first validation, full
// signature checks) and WARM (re-validation hitting the script/signature
// caches, which is the steady-state every ~2.5 min since the same tx objects
// are re-validated each cycle).
//
// For realistic numbers build a Release config and pass -checkmempool=0 (the
// mainnet default) so the periodic O(mempool) consistency check does not
// contaminate the measurement.

namespace {

// Build num_txs valid, signed, 1-in/1-out transactions that spend confirmed
// outputs and are NOT in the mempool (so test_accept returns VALID).
std::vector<CTransactionRef> BuildValidTxs(TestChain100Setup& setup, size_t num_txs)
{
    // P2PK to coinbaseKey: spendable with coinbaseKey alone (same as the
    // coinbase outputs), avoiding segwit signing-provider setup. ECDSA verify
    // cost is what test_accept pays, identical to a P2WPKH spend.
    const CScript p2pk{CScript() << ToByteVector(setup.coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    const CFeeRate feerate{1000};

    // Mature all 100 coinbase outputs.
    setup.mineBlocks(100);

    const size_t num_funders{setup.m_coinbase_txns.size()}; // 100
    const size_t outs_per{(num_txs + num_funders - 1) / num_funders};

    // Fan each mature coinbase output out into `outs_per` P2PK outputs and
    // mine each funder into its own block. Size outputs off each coinbase's
    // actual value (regtest subsidy halves), leaving headroom for fees.
    struct Funded {
        CTransactionRef tx;
        int height;
        CAmount out_val;
    };
    std::vector<Funded> funders;
    for (size_t i = 0; i < num_funders; ++i) {
        const CAmount each{setup.m_coinbase_txns[i]->vout[0].nValue / static_cast<CAmount>(outs_per + 1)};
        std::vector<CTxOut> outs;
        outs.reserve(outs_per);
        for (size_t o = 0; o < outs_per; ++o) outs.emplace_back(each, p2pk);

        auto [funder, fee] = setup.CreateValidTransaction(
            {setup.m_coinbase_txns[i]}, {COutPoint{setup.m_coinbase_txns[i]->GetHash(), 0}},
            /*input_height=*/static_cast<int>(i + 1), {setup.coinbaseKey}, outs, feerate, /*fee_output=*/0);
        setup.CreateAndProcessBlock({funder}, p2pk);
        const int height{WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Height())};
        funders.push_back({MakeTransactionRef(funder), height, each});
    }

    // One leaf tx per funder output, spending it (1-in/1-out), unsubmitted.
    std::vector<CTransactionRef> txs;
    txs.reserve(num_txs);
    for (const auto& f : funders) {
        for (size_t o = 0; o < outs_per && txs.size() < num_txs; ++o) {
            auto [leaf, leaf_fee] = setup.CreateValidTransaction(
                {f.tx}, {COutPoint{f.tx->GetHash(), static_cast<uint32_t>(o)}}, f.height,
                {setup.coinbaseKey}, {CTxOut{f.out_val / 2, p2pk}}, feerate, /*fee_output=*/0);
            txs.push_back(MakeTransactionRef(leaf));
        }
    }
    return txs;
}

void ReattemptTestAccept(benchmark::Bench& bench, size_t num_txs)
{
    const auto setup{MakeNoLogFileContext<TestChain100Setup>(
        ChainType::REGTEST, {.extra_args = {"-checkmempool=0"}})};
    ChainstateManager& chainman{*setup->m_node.chainman};

    const auto txs{BuildValidTxs(*setup, num_txs)};

    // COLD pass: each tx validated for the first time (caches empty for them).
    {
        LOCK(cs_main);
        const auto t0{std::chrono::steady_clock::now()};
        for (const auto& tx : txs) {
            const auto res{chainman.ProcessTransaction(tx, /*test_accept=*/true)};
            assert(res.m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
        const auto dt{std::chrono::steady_clock::now() - t0};
        const auto ns{std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count()};
        std::cout << "[reattempt cold] N=" << num_txs
                  << " total=" << (ns / 1e6) << "ms"
                  << " per-tx=" << (static_cast<double>(ns) / num_txs / 1e3) << "us\n";
    }

    // WARM steady state: re-validate the same txs (cache hits) under cs_main,
    // matching how ReattemptPrivateBroadcast re-checks persistent txs each cycle.
    bench.run([&] {
        LOCK(cs_main);
        for (const auto& tx : txs) {
            ankerl::nanobench::doNotOptimizeAway(chainman.ProcessTransaction(tx, /*test_accept=*/true));
        }
    });
}

} // namespace

static void PrivateBroadcastReattempt1k(benchmark::Bench& b) { ReattemptTestAccept(b, 1000); }
static void PrivateBroadcastReattempt10k(benchmark::Bench& b) { ReattemptTestAccept(b, 10000); }

BENCHMARK(PrivateBroadcastReattempt1k);
BENCHMARK(PrivateBroadcastReattempt10k);
