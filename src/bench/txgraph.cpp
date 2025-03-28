// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <txgraph.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

namespace {

static void MakeBlockBuilder(benchmark::Bench& bench)
{
    auto txgraph = MakeTxGraph(MAX_CLUSTER_COUNT_LIMIT);

    // 15384 minimally sized txs at highest feerate fit into a block
    // ~ 240 max sized clusters
    // average seems to be ~50 max sized clusters

    std::vector<std::vector<TxGraph::Ref>> tx_refs_refs;
    // N max sized clusters, "mine the whole thing"
    for (unsigned int h{0}; h < 50; h++) {
        //std::vector<TxGraph::Ref> tx_refs;
        tx_refs_refs.emplace_back();
        for (unsigned int i{0}; i < MAX_CLUSTER_COUNT_LIMIT; i++) {
            tx_refs_refs[h].push_back(txgraph->AddTransaction(FeePerWeight(i, 1)));
            for (unsigned int j{0}; j < i; j++) {
                if (j % 3 != 0) txgraph->AddDependency(tx_refs_refs[h][j], tx_refs_refs[h][i]);
            }
        }
    }

    assert(!txgraph->IsOversized());
    txgraph->DoWork();

    bench.run([&]() {
        // Block builder is created and goes out of scope each run
        auto block_builder = txgraph->GetBlockBuilder();
        unsigned int count{0};
        while (block_builder) {
            const auto chunk = block_builder->GetCurrentChunk();
            if (!chunk) break;
 //           if (count % 30) {
 //               block_builder->Skip();
 //           } else {
                block_builder->Include();
 //           }
        }
    });
}

static void WorstMainChunk(benchmark::Bench& bench)
{
    auto txgraph = MakeTxGraph(MAX_CLUSTER_COUNT_LIMIT);

    std::vector<TxGraph::Ref> tx_refs;
    for (unsigned int i{0}; i < MAX_CLUSTER_COUNT_LIMIT; i++) {
        tx_refs.push_back(txgraph->AddTransaction(FeePerWeight(i, 1)));
        for (unsigned int j{0}; j < i; j++) {
            if (j % 3 != 0) txgraph->AddDependency(tx_refs[j], tx_refs[i]);
        }
    }

    assert(!txgraph->IsOversized());
    txgraph->DoWork();

    bench.run([&]() {
        txgraph->GetWorstMainChunk();
    });
}

static void TxGraphBuild(benchmark::Bench& bench)
{
    auto txgraph = MakeTxGraph(MAX_CLUSTER_COUNT_LIMIT);

    // Make a max-sized cluster, DoWork() to trigger all pending work,
    // and then remove all transactions.
    bench.run([&]() {
        std::vector<TxGraph::Ref> tx_refs;
        for (unsigned int i{0}; i < MAX_CLUSTER_COUNT_LIMIT; i++) {
            tx_refs.push_back(txgraph->AddTransaction(FeePerWeight(i, 1)));
            for (unsigned int j{0}; j < i; j++) {
                if (j % 3 != 0) txgraph->AddDependency(tx_refs[j], tx_refs[i]);
            }
        }
        assert(!txgraph->IsOversized());
        txgraph->DoWork();
        for (unsigned int i{0}; i < tx_refs.size(); i++) {
            txgraph->RemoveTransaction(tx_refs[i]);
        }

        assert(txgraph->GetTransactionCount() == 0);
    });
}

} // namespace

BENCHMARK(MakeBlockBuilder, benchmark::PriorityLevel::HIGH);
BENCHMARK(WorstMainChunk, benchmark::PriorityLevel::HIGH);
BENCHMARK(TxGraphBuild, benchmark::PriorityLevel::HIGH);
