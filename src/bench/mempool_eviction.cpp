// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <kernel/cs_main.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/check.h>

#include <cstdint>
#include <memory>
#include <vector>


static void AddTx(const CTransactionRef& tx, const CAmount& nFee, CTxMemPool& pool) EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
{
    int64_t nTime = 0;
    unsigned int nHeight = 1;
    uint64_t sequence = 0;
    bool spendsCoinbase = false;
    unsigned int sigOpCost = 4;
    LockPoints lp;
    TryAddToMempool(pool, CTxMemPoolEntry(
        tx, nFee, nTime, nHeight, sequence,
        spendsCoinbase, sigOpCost, lp));
}

// Right now this is only testing eviction performance in an extremely small
// mempool. Code needs to be written to generate a much wider variety of
// unique transactions for a more meaningful performance measurement.
static void MempoolEviction(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();

    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vin.resize(1);
    tx1.vin[0].scriptSig = CScript() << OP_1;
    tx1.vin[0].scriptWitness.stack.push_back({1});
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;

    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vin.resize(1);
    tx2.vin[0].scriptSig = CScript() << OP_2;
    tx2.vin[0].scriptWitness.stack.push_back({2});
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_2 << OP_EQUAL;
    tx2.vout[0].nValue = 10 * COIN;

    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vin.resize(1);
    tx3.vin[0].prevout = COutPoint(tx2.GetHash(), 0);
    tx3.vin[0].scriptSig = CScript() << OP_2;
    tx3.vin[0].scriptWitness.stack.push_back({3});
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_3 << OP_EQUAL;
    tx3.vout[0].nValue = 10 * COIN;

    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vin.resize(2);
    tx4.vin[0].prevout.SetNull();
    tx4.vin[0].scriptSig = CScript() << OP_4;
    tx4.vin[0].scriptWitness.stack.push_back({4});
    tx4.vin[1].prevout.SetNull();
    tx4.vin[1].scriptSig = CScript() << OP_4;
    tx4.vin[1].scriptWitness.stack.push_back({4});
    tx4.vout.resize(2);
    tx4.vout[0].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[0].nValue = 10 * COIN;
    tx4.vout[1].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vin.resize(2);
    tx5.vin[0].prevout = COutPoint(tx4.GetHash(), 0);
    tx5.vin[0].scriptSig = CScript() << OP_4;
    tx5.vin[0].scriptWitness.stack.push_back({4});
    tx5.vin[1].prevout.SetNull();
    tx5.vin[1].scriptSig = CScript() << OP_5;
    tx5.vin[1].scriptWitness.stack.push_back({5});
    tx5.vout.resize(2);
    tx5.vout[0].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[0].nValue = 10 * COIN;
    tx5.vout[1].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vin.resize(2);
    tx6.vin[0].prevout = COutPoint(tx4.GetHash(), 1);
    tx6.vin[0].scriptSig = CScript() << OP_4;
    tx6.vin[0].scriptWitness.stack.push_back({4});
    tx6.vin[1].prevout.SetNull();
    tx6.vin[1].scriptSig = CScript() << OP_6;
    tx6.vin[1].scriptWitness.stack.push_back({6});
    tx6.vout.resize(2);
    tx6.vout[0].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[0].nValue = 10 * COIN;
    tx6.vout[1].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(2);
    tx7.vin[0].prevout = COutPoint(tx5.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_5;
    tx7.vin[0].scriptWitness.stack.push_back({5});
    tx7.vin[1].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[1].scriptSig = CScript() << OP_6;
    tx7.vin[1].scriptWitness.stack.push_back({6});
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[1].nValue = 10 * COIN;

    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    // Create transaction references outside the "hot loop"
    const CTransactionRef tx1_r{MakeTransactionRef(tx1)};
    const CTransactionRef tx2_r{MakeTransactionRef(tx2)};
    const CTransactionRef tx3_r{MakeTransactionRef(tx3)};
    const CTransactionRef tx4_r{MakeTransactionRef(tx4)};
    const CTransactionRef tx5_r{MakeTransactionRef(tx5)};
    const CTransactionRef tx6_r{MakeTransactionRef(tx6)};
    const CTransactionRef tx7_r{MakeTransactionRef(tx7)};

    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        AddTx(tx1_r, 10000LL, pool);
        AddTx(tx2_r, 5000LL, pool);
        AddTx(tx3_r, 20000LL, pool);
        AddTx(tx4_r, 7000LL, pool);
        AddTx(tx5_r, 1000LL, pool);
        AddTx(tx6_r, 1100LL, pool);
        AddTx(tx7_r, 9000LL, pool);
        pool.TrimToSize(pool.DynamicMemoryUsage() * 3 / 4);
        pool.TrimToSize(GetVirtualTransactionSize(*tx1_r));
    });
}

BENCHMARK(MempoolEviction);

// Measure eviction selection separately from graph mutation, diagram checks, and scripts. Each
// cluster is full and supplies an unspent output to the replacement, so every root is pinned and
// every child is a candidate. With the default count limit, 63 pinned roots leave no budget.
static void SiblingEviction(benchmark::Bench& bench, uint32_t num_clusters)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    CMutableTransaction replacement;
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    for (uint32_t cluster{0}; cluster < num_clusters; ++cluster) {
        CMutableTransaction root;
        root.vin.emplace_back(COutPoint{Txid{}, cluster});
        root.vout.assign(limits.cluster_count, CTxOut{COIN, CScript() << OP_TRUE});
        const auto root_ref = MakeTransactionRef(root);
        AddTx(root_ref, 1000, pool);
        replacement.vin.emplace_back(COutPoint{root_ref->GetHash(), uint32_t(limits.cluster_count - 1)});
        for (uint32_t child{0}; child + 1 < limits.cluster_count; ++child) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{root_ref->GetHash(), child});
            tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
            AddTx(MakeTransactionRef(tx), 1000, pool);
        }
    }
    const auto entry = TestMemPoolEntryHelper{}.FromTx(replacement);
    const auto parents = pool.GetParents(entry);
    const auto ancestors = pool.CalculateMemPoolAncestors(entry);
    const int64_t budget{int64_t{limits.cluster_count} - 1 - num_clusters};
    const auto expected{static_cast<size_t>(int64_t{num_clusters} * (int64_t{limits.cluster_count} - 1) - budget)};
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto evictions = GetEntriesForSiblingEviction(pool, entry, parents, ancestors, /*removals=*/{},
                                                            limits.cluster_count, limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR);
        assert(evictions && evictions->size() == expected);
    });
}

// Adversarial shape for dependency work: each cluster is a full chain, so the candidates have
// 1..63 ancestors each. The replacement spends the root's second output; every root is pinned.
static void SiblingEvictionChains(benchmark::Bench& bench, uint32_t num_clusters)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    CMutableTransaction replacement;
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    for (uint32_t cluster{0}; cluster < num_clusters; ++cluster) {
        CMutableTransaction root;
        root.vin.emplace_back(COutPoint{Txid{}, cluster});
        root.vout.assign(2, CTxOut{COIN, CScript() << OP_TRUE});
        auto prev = MakeTransactionRef(root);
        AddTx(prev, 1000, pool);
        replacement.vin.emplace_back(COutPoint{prev->GetHash(), 1});
        for (uint32_t depth{1}; depth < limits.cluster_count; ++depth) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{prev->GetHash(), 0});
            tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
            prev = MakeTransactionRef(tx);
            AddTx(prev, 1000, pool);
        }
    }
    const auto entry = TestMemPoolEntryHelper{}.FromTx(replacement);
    const auto parents = pool.GetParents(entry);
    const auto ancestors = pool.CalculateMemPoolAncestors(entry);
    const int64_t budget{int64_t{limits.cluster_count} - 1 - num_clusters};
    const auto expected{static_cast<size_t>(int64_t{num_clusters} * (int64_t{limits.cluster_count} - 1) - budget)};
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto evictions = GetEntriesForSiblingEviction(pool, entry, parents, ancestors, /*removals=*/{},
                                                            limits.cluster_count, limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR);
        assert(evictions && evictions->size() == expected);
    });
}

// Reference point: the pre-existing Rule 5 collection at its maximum size. The replacement
// conflicts with the root of each of 100 full clusters, so ordinary RBF collects all 6,400
// descendants. Overlapping conflicts can repeat work, so this is not a CPU upper bound.
static void MempoolRbfConflictsMaxClusters(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    CMutableTransaction replacement;
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    CTxMemPool::setEntries conflicts;
    for (uint32_t cluster{0}; cluster < MAX_REPLACEMENT_CANDIDATES; ++cluster) {
        CMutableTransaction root;
        root.vin.emplace_back(COutPoint{Txid{}, cluster});
        root.vout.assign(limits.cluster_count - 1, CTxOut{COIN, CScript() << OP_TRUE});
        const auto root_ref = MakeTransactionRef(root);
        AddTx(root_ref, 1000, pool);
        replacement.vin.emplace_back(COutPoint{Txid{}, cluster});
        conflicts.insert(*pool.GetIter(root_ref->GetHash()));
        for (uint32_t child{0}; child + 1 < limits.cluster_count; ++child) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{root_ref->GetHash(), child});
            tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
            AddTx(MakeTransactionRef(tx), 1000, pool);
        }
    }
    const CTransaction tx{replacement};
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        CTxMemPool::setEntries all_conflicts;
        const auto err = GetEntriesForConflicts(tx, pool, conflicts, all_conflicts);
        assert(!err && all_conflicts.size() == MAX_REPLACEMENT_CANDIDATES * limits.cluster_count);
    });
}

// The common rejection: a child of a full chain. The pinned set alone does not fit, so the
// selector returns before reading any cluster. Includes the caller's ancestor query.
static void MempoolSiblingEvictionTooLongChain(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    CMutableTransaction root;
    root.vin.emplace_back(COutPoint{Txid{}, 0});
    root.vout.emplace_back(COIN, CScript() << OP_TRUE);
    auto prev = MakeTransactionRef(root);
    AddTx(prev, 1000, pool);
    for (uint32_t depth{1}; depth < limits.cluster_count; ++depth) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{prev->GetHash(), 0});
        tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
        prev = MakeTransactionRef(tx);
        AddTx(prev, 1000, pool);
    }
    CMutableTransaction replacement;
    replacement.vin.emplace_back(COutPoint{prev->GetHash(), 0});
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    const auto entry = TestMemPoolEntryHelper{}.FromTx(replacement);
    const auto parents = pool.GetParents(entry);
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto ancestors = pool.CalculateMemPoolAncestors(entry);
        const auto evictions = GetEntriesForSiblingEviction(pool, entry, parents, ancestors, /*removals=*/{},
                                                            limits.cluster_count, limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR);
        assert(!evictions);
    });
}

// Free work outside the selector: the replacement spends the tips of 63 full chains, so the
// caller's ancestor union enumerates about 4,000 entries before the pinned set is rejected.
static void MempoolSiblingEvictionMaxChainTips(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    CMutableTransaction replacement;
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    for (uint32_t cluster{0}; cluster + 1 < limits.cluster_count; ++cluster) {
        CMutableTransaction root;
        root.vin.emplace_back(COutPoint{Txid{}, cluster});
        root.vout.emplace_back(COIN, CScript() << OP_TRUE);
        auto prev = MakeTransactionRef(root);
        AddTx(prev, 1000, pool);
        for (uint32_t depth{1}; depth < limits.cluster_count; ++depth) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{prev->GetHash(), 0});
            tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
            prev = MakeTransactionRef(tx);
            AddTx(prev, 1000, pool);
        }
        replacement.vin.emplace_back(COutPoint{prev->GetHash(), 0});
    }
    const auto entry = TestMemPoolEntryHelper{}.FromTx(replacement);
    const auto parents = pool.GetParents(entry);
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        const auto ancestors = pool.CalculateMemPoolAncestors(entry);
        const auto evictions = GetEntriesForSiblingEviction(pool, entry, parents, ancestors, /*removals=*/{},
                                                            limits.cluster_count, limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR);
        assert(!evictions);
    });
}

// Large staged removal set: in each of 63 clusters the root is pinned, one child is a direct
// conflict heading a 31-deep chain (removed with its descendants), and another child heads a
// 31-deep candidate chain. Includes the ordinary conflict collection that precedes selection.
static void MempoolSiblingEvictionMaxRemovals(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    CTxMemPool& pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    const auto& limits{pool.m_opts.limits};
    const uint32_t half{(limits.cluster_count - 1) / 2};
    CMutableTransaction replacement;
    replacement.vout.emplace_back(COIN, CScript() << OP_TRUE);
    CTxMemPool::setEntries conflicts;
    for (uint32_t cluster{0}; cluster + 1 < limits.cluster_count; ++cluster) {
        CMutableTransaction root;
        root.vin.emplace_back(COutPoint{Txid{}, cluster});
        root.vout.assign(3, CTxOut{COIN, CScript() << OP_TRUE});
        const auto root_ref = MakeTransactionRef(root);
        AddTx(root_ref, 1000, pool);
        replacement.vin.emplace_back(COutPoint{root_ref->GetHash(), 2});
        for (uint32_t branch{0}; branch < 2; ++branch) {
            auto prev = root_ref;
            for (uint32_t depth{0}; depth < half; ++depth) {
                CMutableTransaction tx;
                tx.vin.emplace_back(COutPoint{prev->GetHash(), depth == 0 ? branch : 0});
                if (branch == 0 && depth == 0) {
                    const COutPoint confirmed_input{Txid{}, MAX_REPLACEMENT_CANDIDATES + cluster};
                    tx.vin.emplace_back(confirmed_input);
                    replacement.vin.emplace_back(confirmed_input);
                }
                tx.vout.emplace_back(COIN, CScript() << OP_TRUE);
                prev = MakeTransactionRef(tx);
                AddTx(prev, 1000, pool);
                if (branch == 0 && depth == 0) conflicts.insert(*pool.GetIter(prev->GetHash()));
            }
        }
    }
    const auto entry = TestMemPoolEntryHelper{}.FromTx(replacement);
    const CTransaction tx{replacement};
    const auto parents = pool.GetParents(entry);
    const auto ancestors = pool.CalculateMemPoolAncestors(entry);
    bench.run([&]() NO_THREAD_SAFETY_ANALYSIS {
        CTxMemPool::setEntries removals;
        const auto err = GetEntriesForConflicts(tx, pool, conflicts, removals);
        assert(!err && removals.size() == (limits.cluster_count - 1) * half);
        const auto evictions = GetEntriesForSiblingEviction(pool, entry, parents, ancestors, removals,
                                                            limits.cluster_count, limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR);
        assert(evictions && evictions->size() == (limits.cluster_count - 1) * half);
    });
}

static void MempoolSiblingEvictionSingleCluster(benchmark::Bench& bench)
{
    SiblingEviction(bench, 1);
}

static void MempoolSiblingEvictionMaxClusters(benchmark::Bench& bench)
{
    SiblingEviction(bench, DEFAULT_CLUSTER_LIMIT - 1);
}

static void MempoolSiblingEvictionSingleChain(benchmark::Bench& bench)
{
    SiblingEvictionChains(bench, 1);
}

static void MempoolSiblingEvictionMaxChains(benchmark::Bench& bench)
{
    SiblingEvictionChains(bench, DEFAULT_CLUSTER_LIMIT - 1);
}

BENCHMARK(MempoolRbfConflictsMaxClusters);
BENCHMARK(MempoolSiblingEvictionTooLongChain);
BENCHMARK(MempoolSiblingEvictionMaxChainTips);
BENCHMARK(MempoolSiblingEvictionMaxRemovals);
BENCHMARK(MempoolSiblingEvictionSingleCluster);
BENCHMARK(MempoolSiblingEvictionMaxClusters);
BENCHMARK(MempoolSiblingEvictionSingleChain);
BENCHMARK(MempoolSiblingEvictionMaxChains);
