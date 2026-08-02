// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/coinstats.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>

namespace {
using CoinMap = std::map<COutPoint, Coin>;

TestChain100Setup* g_setup;
kernel::CCoinsStats g_baseline_stats;
uint256 g_baseline_best;
constexpr std::chrono::seconds FLUSH_BASE_TIME{1'600'000'000};

bool SameCoin(const Coin& first, const Coin& second)
{
    return first.out == second.out && first.nHeight == second.nHeight &&
           first.IsCoinBase() == second.IsCoinBase();
}

void AssertLogicalStatsEqual(const kernel::CCoinsStats& first, const kernel::CCoinsStats& second)
{
    assert(first.nHeight == second.nHeight);
    assert(first.hashBlock == second.hashBlock);
    assert(first.nTransactions == second.nTransactions);
    assert(first.nTransactionOutputs == second.nTransactionOutputs);
    assert(first.nBogoSize == second.nBogoSize);
    assert(first.hashSerialized == second.hashSerialized);
    assert(first.total_amount == second.total_amount);
    assert(first.coins_count == second.coins_count);
    assert(first.index_used == second.index_used);
    assert(first.total_subsidy == second.total_subsidy);
    assert(first.total_unspendables_genesis_block == second.total_unspendables_genesis_block);
    assert(first.total_unspendables_bip30 == second.total_unspendables_bip30);
    assert(first.total_unspendables_scripts == second.total_unspendables_scripts);
    assert(first.total_unspendables_unclaimed_rewards == second.total_unspendables_unclaimed_rewards);
    assert(first.total_prevout_spent_amount == second.total_prevout_spent_amount);
    assert(first.total_new_outputs_ex_coinbase_amount == second.total_new_outputs_ex_coinbase_amount);
    assert(first.total_coinbase_amount == second.total_coinbase_amount);
}

void AssertStatsWithAddedCoins(const kernel::CCoinsStats& stats, const CoinMap& added)
{
    CAmount added_amount{0};
    uint64_t added_bogo_size{0};
    for (const auto& [_, coin] : added) {
        added_amount += coin.out.nValue;
        added_bogo_size += kernel::GetBogoSize(coin.out.scriptPubKey);
    }

    assert(stats.nHeight == g_baseline_stats.nHeight);
    assert(stats.hashBlock == g_baseline_stats.hashBlock);
    assert(stats.nTransactions == g_baseline_stats.nTransactions + 1);
    assert(stats.nTransactionOutputs == g_baseline_stats.nTransactionOutputs + added.size());
    assert(stats.nBogoSize == g_baseline_stats.nBogoSize + added_bogo_size);
    assert(stats.hashSerialized != g_baseline_stats.hashSerialized);
    assert(stats.total_amount.has_value());
    assert(g_baseline_stats.total_amount.has_value());
    assert(*stats.total_amount == *g_baseline_stats.total_amount + added_amount);
    assert(stats.coins_count == g_baseline_stats.coins_count + added.size());
    assert(!stats.index_used);
}

void initialize_validation_flush()
{
    TestOpts opts;
    opts.coins_db_in_memory = false;
    opts.block_tree_db_in_memory = false;
    opts.extra_args = {"-fastprune=1", "-maxmempool=0", "-prune=1"};
    static const auto setup{MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST, opts)};
    g_setup = setup.get();

    auto& chainman{*Assert(g_setup->m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    g_setup->m_clock.set(FLUSH_BASE_TIME);
    chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
    {
        LOCK(chainman.GetMutex());
        assert(Assert(g_setup->m_node.mempool)->m_opts.max_size_bytes == 0);
        assert(chainstate.CoinsTip().GetCacheSize() == 0);
        g_baseline_best = Assert(chainman.ActiveTip())->GetBlockHash();
        assert(chainstate.CoinsTip().GetBestBlock() == g_baseline_best);
        assert(chainstate.CoinsDB().GetBestBlock() == g_baseline_best);
        assert(chainstate.CoinsDB().GetHeadBlocks().empty());
        g_baseline_stats = *Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            chainstate.CoinsDB(),
            chainman.m_blockman));
        assert(g_baseline_stats.hashBlock == g_baseline_best);
        assert(g_baseline_stats.nHeight == chainman.ActiveHeight());
    }
    chainman.CheckBlockIndex();
}

enum class CacheBudget {
    OK,
    LARGE,
    CRITICAL,
};

enum class PruneAction {
    NONE,
    MANUAL,
    AUTOMATIC,
};

enum class PruneLock {
    NONE,
    UNBOUNDED,
    LIMITED,
};

struct FlushScenario {
    FlushStateMode mode;
    CacheBudget cache_budget;
    bool periodic_due;
    bool expect_write;
    bool expect_empty_cache;
    PruneAction prune_action{PruneAction::NONE};
    PruneLock prune_lock{PruneLock::NONE};
};

constexpr std::array FLUSH_SCENARIOS{
    FlushScenario{FlushStateMode::NONE, CacheBudget::OK, false, false, false},
    FlushScenario{FlushStateMode::NONE, CacheBudget::CRITICAL, false, false, false},
    FlushScenario{FlushStateMode::IF_NEEDED, CacheBudget::OK, false, false, false},
    FlushScenario{FlushStateMode::IF_NEEDED, CacheBudget::LARGE, false, false, false},
    FlushScenario{FlushStateMode::IF_NEEDED, CacheBudget::CRITICAL, false, true, true},
    FlushScenario{FlushStateMode::PERIODIC, CacheBudget::OK, false, false, false},
    FlushScenario{FlushStateMode::PERIODIC, CacheBudget::OK, true, true, false},
    FlushScenario{FlushStateMode::PERIODIC, CacheBudget::LARGE, false, true, true},
    FlushScenario{FlushStateMode::PERIODIC, CacheBudget::CRITICAL, false, true, true},
    FlushScenario{FlushStateMode::FORCE_SYNC, CacheBudget::OK, false, true, false},
    FlushScenario{FlushStateMode::FORCE_FLUSH, CacheBudget::OK, false, true, true},
    FlushScenario{FlushStateMode::NONE, CacheBudget::OK, false, false, false, PruneAction::MANUAL},
    FlushScenario{FlushStateMode::NONE, CacheBudget::OK, false, false, false, PruneAction::MANUAL, PruneLock::UNBOUNDED},
    FlushScenario{FlushStateMode::NONE, CacheBudget::OK, false, false, false, PruneAction::AUTOMATIC, PruneLock::LIMITED},
};
} // namespace

FUZZ_TARGET(validation_flush, .init = initialize_validation_flush)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& chainman{*Assert(g_setup->m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& blockman{chainman.m_blockman};
    const FlushScenario scenario{fuzzed_data_provider.PickValueInArray(FLUSH_SCENARIOS)};
    const size_t coin_count{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 16)};
    const Txid synthetic_txid{Txid::FromUint256(uint256::ONE)};

    LOCK(chainman.GetMutex());
    assert(chainstate.CoinsTip().GetCacheSize() == 0);
    assert(chainstate.CoinsTip().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetHeadBlocks().empty());
    assert(blockman.IsPruneMode());
    assert(blockman.m_blockfiles_indexed);
    const size_t original_cache_budget{chainstate.m_coinstip_cache_size_bytes};
    const bool original_have_pruned{blockman.m_have_pruned};

    CoinMap added;
    for (uint32_t index{0}; index < coin_count; ++index) {
        const COutPoint outpoint{synthetic_txid, index};
        assert(!chainstate.CoinsTip().HaveCoin(outpoint));
        assert(!chainstate.CoinsDB().HaveCoin(outpoint));
        const CAmount value{fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(1, COIN)};
        const CScript script{CScript{} << static_cast<int64_t>(index + 1) << OP_DROP << OP_TRUE};
        Coin coin{
            CTxOut{value, script},
            fuzzed_data_provider.ConsumeIntegralInRange<int>(1, chainman.ActiveHeight()),
            fuzzed_data_provider.ConsumeBool()};
        assert(added.emplace(outpoint, coin).second);
        chainstate.CoinsTip().AddCoin(outpoint, std::move(coin), /*possible_overwrite=*/false);
    }
    assert(chainstate.CoinsTip().GetCacheSize() == added.size());
    assert(chainstate.CoinsTip().GetDirtyCount() == added.size());

    const size_t memory_usage{chainstate.CoinsTip().DynamicMemoryUsage()};
    assert(memory_usage > 0);
    CoinsCacheSizeState expected_cache_state;
    switch (scenario.cache_budget) {
    case CacheBudget::OK:
        chainstate.m_coinstip_cache_size_bytes = memory_usage * 2 + 1;
        expected_cache_state = CoinsCacheSizeState::OK;
        break;
    case CacheBudget::LARGE:
        chainstate.m_coinstip_cache_size_bytes = memory_usage;
        expected_cache_state = CoinsCacheSizeState::LARGE;
        break;
    case CacheBudget::CRITICAL:
        chainstate.m_coinstip_cache_size_bytes = memory_usage - 1;
        expected_cache_state = CoinsCacheSizeState::CRITICAL;
        break;
    }
    assert(chainstate.GetCoinsCacheSizeState() == expected_cache_state);

    g_setup->m_clock.set(
        FLUSH_BASE_TIME + (scenario.periodic_due ? std::chrono::hours{2} : std::chrono::hours{0}));
    if (scenario.prune_lock != PruneLock::NONE) {
        const int height_first{scenario.prune_lock == PruneLock::LIMITED
                ? chainman.ActiveHeight()
                : std::numeric_limits<int>::max()};
        blockman.UpdatePruneLock("validation_flush", node::PruneLockInfo{height_first});
    }
    BlockValidationState state;
    if (scenario.prune_action == PruneAction::AUTOMATIC) {
        assert(scenario.mode == FlushStateMode::NONE);
        chainstate.PruneAndFlush();
    } else {
        const int manual_height{scenario.prune_action == PruneAction::MANUAL
                ? chainman.ActiveHeight()
                : 0};
        assert(chainstate.FlushStateToDisk(state, scenario.mode, manual_height));
    }
    if (scenario.prune_lock != PruneLock::NONE) {
        assert(blockman.DeletePruneLock("validation_flush"));
    }
    assert(state.IsValid());
    assert(blockman.m_have_pruned == original_have_pruned);
    assert(chainstate.CoinsTip().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetHeadBlocks().empty());
    assert(chainstate.CoinsTip().GetCacheSize() ==
           (scenario.expect_empty_cache ? 0 : added.size()));
    assert(chainstate.CoinsTip().GetDirtyCount() ==
           (scenario.expect_write ? 0 : added.size()));

    for (const auto& [outpoint, expected] : added) {
        const std::optional<Coin> stored{chainstate.CoinsDB().PeekCoin(outpoint)};
        assert(stored.has_value() == scenario.expect_write);
        if (stored) assert(SameCoin(*stored, expected));
    }
    const kernel::CCoinsStats flushed_stats{*Assert(kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        chainstate.CoinsDB(),
        chainman.m_blockman))};
    if (scenario.expect_write) {
        AssertStatsWithAddedCoins(flushed_stats, added);
    } else {
        AssertLogicalStatsEqual(flushed_stats, g_baseline_stats);
    }

    for (const auto& [outpoint, _] : added) {
        assert(chainstate.CoinsTip().SpendCoin(outpoint));
    }
    g_setup->m_clock.set(FLUSH_BASE_TIME);
    chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
    assert(chainstate.CoinsTip().GetCacheSize() == 0);
    assert(chainstate.CoinsTip().GetDirtyCount() == 0);
    assert(chainstate.CoinsTip().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetBestBlock() == g_baseline_best);
    assert(chainstate.CoinsDB().GetHeadBlocks().empty());
    for (const auto& [outpoint, _] : added) {
        assert(!chainstate.CoinsDB().HaveCoin(outpoint));
    }
    const kernel::CCoinsStats restored_stats{*Assert(kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        chainstate.CoinsDB(),
        chainman.m_blockman))};
    AssertLogicalStatsEqual(restored_stats, g_baseline_stats);

    chainstate.m_coinstip_cache_size_bytes = original_cache_budget;
    Assert(g_setup->m_node.mempool)->check(chainstate.CoinsTip(), chainman.ActiveHeight() + 1);
    chainman.CheckBlockIndex();
}
