// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/coinstats.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace {
using CoinMap = std::map<COutPoint, Coin>;

TestChain100Setup* g_setup;
CBlockIndex* g_fork;
std::array<std::vector<CBlock>, 2> g_branch_blocks;
std::array<std::vector<CBlockIndex*>, 2> g_branch_indices;
std::array<std::vector<CoinMap>, 2> g_branch_states;
std::set<COutPoint> g_all_outpoints;
kernel::CCoinsStats g_verify_stats;

class ReplayCoinsView final : public CCoinsViewCache
{
public:
    explicit ReplayCoinsView(std::vector<uint256> heads)
        : CCoinsViewCache{&CoinsViewEmpty::Get(), /*deterministic=*/true}, m_heads{std::move(heads)}
    {
    }

    std::vector<uint256> GetHeadBlocks() const override { return m_heads; }

    void BatchWrite(CoinsViewCacheCursor& cursor, const uint256& block_hash) override
    {
        CCoinsViewCache::BatchWrite(cursor, block_hash);
        m_heads.clear();
    }

private:
    std::vector<uint256> m_heads;
};

struct ReplayTestChainstate : public Chainstate {
    bool ReplayBlocksWithView(CCoinsView& view) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return ReplayBlocks(view);
    }
};

bool SameCoin(const Coin& first, const Coin& second)
{
    return first.out == second.out && first.nHeight == second.nHeight &&
           first.IsCoinBase() == second.IsCoinBase();
}

void ApplyBlock(CoinMap& coins, const CBlock& block, int height)
{
    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn& input : tx->vin) {
                g_all_outpoints.insert(input.prevout);
                assert(coins.erase(input.prevout) == 1);
            }
        }
        for (uint32_t index{0}; index < tx->vout.size(); ++index) {
            const COutPoint outpoint{tx->GetHash(), index};
            g_all_outpoints.insert(outpoint);
            if (!tx->vout[index].scriptPubKey.IsUnspendable()) {
                assert(coins.emplace(outpoint, Coin{tx->vout[index], height, tx->IsCoinBase()}).second);
            }
        }
    }
}

std::vector<CMutableTransaction> MakeBranchTransactions(unsigned branch)
{
    const CTransactionRef& source{g_setup->m_coinbase_txns.at(0)};
    const CAmount source_value{source->vout.at(0).nValue};
    const CScript script{CScript{} << static_cast<int64_t>(branch + 1) << OP_DROP << OP_TRUE};
    const CAmount first_fee{1'000 + static_cast<CAmount>(branch)};
    const CAmount first_value{10 * COIN + static_cast<CAmount>(branch) * CENT};

    auto [first, actual_fee] = g_setup->CreateValidTransaction(
        /*input_transactions=*/{source},
        /*inputs=*/{COutPoint{source->GetHash(), 0}},
        /*input_height=*/1,
        /*input_signing_keys=*/{g_setup->coinbaseKey},
        /*outputs=*/{
            CTxOut{first_value, script},
            CTxOut{source_value - first_value - first_fee, script},
        },
        /*feerate=*/std::nullopt,
        /*fee_output=*/std::nullopt);
    assert(actual_fee == first_fee);

    const CTransaction first_tx{first};
    const CAmount second_fee{2'000 + static_cast<CAmount>(branch)};
    CMutableTransaction second;
    second.version = 2;
    second.vin.emplace_back(COutPoint{first_tx.GetHash(), 0});
    second.vin.emplace_back(COutPoint{first_tx.GetHash(), 1});
    second.vout.emplace_back(source_value - first_fee - second_fee, script);

    const CTransaction second_tx{second};
    const CAmount third_fee{3'000 + static_cast<CAmount>(branch)};
    const CAmount third_value{5 * COIN + static_cast<CAmount>(branch) * CENT};
    CMutableTransaction third;
    third.version = 2;
    third.vin.emplace_back(COutPoint{second_tx.GetHash(), 0});
    third.vout.emplace_back(third_value, script);
    third.vout.emplace_back(
        source_value - first_fee - second_fee - third_fee - third_value,
        script);

    return {std::move(first), std::move(second), std::move(third)};
}

void BuildBranch(unsigned branch)
{
    const CScript coinbase_script{
        CScript{} << static_cast<int64_t>(branch + 10) << OP_DROP << OP_TRUE};
    const std::vector<CMutableTransaction> transactions{MakeBranchTransactions(branch)};
    g_branch_indices[branch].push_back(g_fork);
    for (const CMutableTransaction& transaction : transactions) {
        CBlock block{g_setup->CreateAndProcessBlock({transaction}, coinbase_script)};
        auto& chainman{*Assert(g_setup->m_node.chainman)};
        CBlockIndex* index;
        {
            LOCK(chainman.GetMutex());
            index = Assert(chainman.m_blockman.LookupBlockIndex(block.GetHash()));
            assert(index->pprev == g_branch_indices[branch].back());
            assert(index->nStatus & BLOCK_HAVE_DATA);
            assert(index->nStatus & BLOCK_HAVE_UNDO);
            assert(chainman.ActiveTip() == index);
        }
        g_branch_blocks[branch].push_back(std::move(block));
        g_branch_indices[branch].push_back(index);
        g_setup->m_clock += 1s;
    }
}

void AssertCoinsEqual(const CCoinsView& view, const CoinMap& expected)
{
    CAmount total{0};
    size_t count{0};
    for (const COutPoint& outpoint : g_all_outpoints) {
        const std::optional<Coin> actual{view.PeekCoin(outpoint)};
        const auto expected_it{expected.find(outpoint)};
        assert(actual.has_value() == (expected_it != expected.end()));
        if (actual) {
            assert(SameCoin(*actual, expected_it->second));
            total += actual->out.nValue;
            ++count;
        }
    }
    CAmount expected_total{0};
    for (const auto& [_, coin] : expected) expected_total += coin.out.nValue;
    assert(total == expected_total);
    assert(count == expected.size());
}

void AssertViewEquals(const ReplayCoinsView& view, const CoinMap& expected)
{
    AssertCoinsEqual(view, expected);
    assert(view.GetCacheSize() == expected.size());
}

void AssertStatsEqual(const kernel::CCoinsStats& first, const kernel::CCoinsStats& second)
{
    assert(first.nHeight == second.nHeight);
    assert(first.hashBlock == second.hashBlock);
    assert(first.nTransactions == second.nTransactions);
    assert(first.nTransactionOutputs == second.nTransactionOutputs);
    assert(first.nBogoSize == second.nBogoSize);
    assert(first.hashSerialized == second.hashSerialized);
    assert(first.nDiskSize == second.nDiskSize);
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

void SeedView(ReplayCoinsView& view, const CoinMap& old_state, const CoinMap& new_state,
              FuzzedDataProvider& fuzzed_data_provider)
{
    for (const COutPoint& outpoint : g_all_outpoints) {
        const auto old_it{old_state.find(outpoint)};
        const auto new_it{new_state.find(outpoint)};
        const Coin* selected{nullptr};
        if (old_it != old_state.end() && new_it != new_state.end() &&
            SameCoin(old_it->second, new_it->second)) {
            selected = &old_it->second;
        } else if (fuzzed_data_provider.ConsumeBool()) {
            if (old_it != old_state.end()) selected = &old_it->second;
        } else if (new_it != new_state.end()) {
            selected = &new_it->second;
        }
        if (selected) view.AddCoin(outpoint, Coin{*selected}, /*possible_overwrite=*/false);
    }
    assert(view.GetBestBlock().IsNull());
}

void initialize_validation_replay()
{
    static const auto setup{MakeNoLogFileContext<TestChain100Setup>()};
    g_setup = setup.get();
    auto& chainman{*Assert(g_setup->m_node.chainman)};
    {
        LOCK(chainman.GetMutex());
        g_fork = Assert(chainman.ActiveTip());
        assert(g_fork->nHeight == COINBASE_MATURITY);
    }

    BuildBranch(/*branch=*/0);
    {
        BlockValidationState state;
        assert(chainman.ActiveChainstate().InvalidateBlock(state, g_branch_indices[0].at(1)));
        assert(state.IsValid());
        LOCK(chainman.GetMutex());
        assert(chainman.ActiveTip() == g_fork);
    }
    BuildBranch(/*branch=*/1);
    {
        LOCK(chainman.GetMutex());
        chainman.ActiveChainstate().ResetBlockFailureFlags(g_branch_indices[0].at(1));
        chainman.RecalculateBestHeader();
        assert(chainman.ActiveTip() == g_branch_indices[1].back());
        assert(chainman.ActiveHeight() == COINBASE_MATURITY + 3);
        for (const auto& branch : g_branch_indices) {
            for (size_t depth{1}; depth < branch.size(); ++depth) {
                assert(branch[depth]->IsValid(BLOCK_VALID_SCRIPTS));
                assert(branch[depth]->nStatus & BLOCK_HAVE_DATA);
                assert(branch[depth]->nStatus & BLOCK_HAVE_UNDO);
            }
        }
        assert(Assert(g_setup->m_node.mempool)->size() == 0);
    }

    CoinMap fork_state;
    for (size_t index{0}; index < g_setup->m_coinbase_txns.size(); ++index) {
        const CTransactionRef& coinbase{g_setup->m_coinbase_txns[index]};
        const COutPoint outpoint{coinbase->GetHash(), 0};
        g_all_outpoints.insert(outpoint);
        assert(fork_state.emplace(
            outpoint,
            Coin{coinbase->vout.at(0), static_cast<int>(index + 1), /*coinbase=*/true}).second);
    }
    for (unsigned branch{0}; branch < g_branch_states.size(); ++branch) {
        g_branch_states[branch].push_back(fork_state);
        for (size_t depth{0}; depth < g_branch_blocks[branch].size(); ++depth) {
            CoinMap state{g_branch_states[branch].back()};
            ApplyBlock(state, g_branch_blocks[branch][depth], COINBASE_MATURITY + depth + 1);
            g_branch_states[branch].push_back(std::move(state));
        }
    }
    chainman.CheckBlockIndex();
}

void initialize_validation_verify_db()
{
    initialize_validation_replay();
    auto& chainman{*Assert(g_setup->m_node.chainman)};
    {
        LOCK(chainman.GetMutex());
        auto& chainstate{chainman.ActiveChainstate()};
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
        assert(chainstate.CoinsDB().GetBestBlock() == chainman.ActiveTip()->GetBlockHash());
        AssertCoinsEqual(chainstate.CoinsDB(), g_branch_states[1].back());
        g_verify_stats = *Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            chainstate.CoinsDB(),
            chainman.m_blockman));
        assert(g_verify_stats.hashBlock == chainman.ActiveTip()->GetBlockHash());
        assert(g_verify_stats.nHeight == chainman.ActiveHeight());
    }
    chainman.CheckBlockIndex();
}

struct Endpoint {
    unsigned branch;
    size_t depth;
};
} // namespace

FUZZ_TARGET(validation_replay, .init = initialize_validation_replay)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    auto& chainman{*Assert(g_setup->m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& mempool{*Assert(g_setup->m_node.mempool)};
    const unsigned operation{fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 19)};

    Endpoint old_endpoint{0, 3};
    Endpoint new_endpoint{1, 3};
    bool old_is_null{false};
    switch (operation) {
    case 0: break; // Cross-fork replay.
    case 1: old_endpoint = {1, 3}; new_endpoint = {0, 3}; break;
    case 2: old_endpoint = {0, 3}; new_endpoint = {0, 0}; break;
    case 3: old_endpoint = {0, 0}; new_endpoint = {0, 3}; break;
    case 4: old_endpoint = {0, 3}; new_endpoint = {0, 3}; break;
    case 5: old_endpoint = {0, 1}; new_endpoint = {0, 3}; break;
    case 6: old_endpoint = {0, 3}; new_endpoint = {0, 1}; break;
    case 7: old_is_null = true; new_endpoint = {0, 3}; break;
    default:
        old_endpoint = {
            fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 1),
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 3),
        };
        new_endpoint = {
            fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 1),
            fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 3),
        };
        break;
    }

    const CBlockIndex* active_tip;
    uint256 active_coins_tip;
    uint256 active_coins_db;
    size_t block_index_size;
    size_t candidate_count;
    size_t mempool_size;
    {
        LOCK(chainman.GetMutex());
        active_tip = Assert(chainman.ActiveTip());
        active_coins_tip = chainstate.CoinsTip().GetBestBlock();
        active_coins_db = chainstate.CoinsDB().GetBestBlock();
        block_index_size = chainman.BlockIndex().size();
        candidate_count = chainstate.setBlockIndexCandidates.size();
        mempool_size = mempool.size();
    }

    const CBlockIndex* old_index{g_branch_indices[old_endpoint.branch][old_endpoint.depth]};
    const CBlockIndex* new_index{g_branch_indices[new_endpoint.branch][new_endpoint.depth]};
    const CoinMap empty_state;
    const CoinMap& old_state{old_is_null ? empty_state : g_branch_states[old_endpoint.branch][old_endpoint.depth]};
    const CoinMap& new_state{g_branch_states[new_endpoint.branch][new_endpoint.depth]};

    std::vector<uint256> heads{new_index->GetBlockHash(), old_is_null ? uint256{} : old_index->GetBlockHash()};
    if (operation >= 16) {
        const uint256 unknown{uint256::ONE};
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(unknown)) == nullptr);
        if (operation == 16) {
            heads.resize(1);
        } else if (operation == 17) {
            heads.push_back(new_index->GetBlockHash());
        } else if (operation == 18) {
            heads[0] = unknown;
        } else {
            heads[1] = unknown;
        }
    }

    ReplayCoinsView view{heads};
    if (operation >= 16) {
        for (const auto& [outpoint, coin] : old_state) {
            view.AddCoin(outpoint, Coin{coin}, /*possible_overwrite=*/false);
        }
    } else {
        SeedView(view, old_state, new_state, fuzzed_data_provider);
    }

    {
        LOCK(chainman.GetMutex());
        auto& replay_chainstate{static_cast<ReplayTestChainstate&>(chainstate)};
        const bool replayed{replay_chainstate.ReplayBlocksWithView(view)};
        assert(replayed == (operation < 16));
        if (replayed) {
            assert(view.GetHeadBlocks().empty());
            assert(view.GetBestBlock() == new_index->GetBlockHash());
            AssertViewEquals(view, new_state);

            // Once the transition marker is cleared, replay is an idempotent no-op.
            assert(replay_chainstate.ReplayBlocksWithView(view));
            assert(view.GetHeadBlocks().empty());
            assert(view.GetBestBlock() == new_index->GetBlockHash());
            AssertViewEquals(view, new_state);
        } else {
            assert(view.GetHeadBlocks() == heads);
            assert(view.GetBestBlock().IsNull());
            AssertViewEquals(view, old_state);
        }
    }

    // The production entry point must remain a state-preserving no-op once its
    // real database has no transition marker.
    assert(chainstate.ReplayBlocks());

    {
        LOCK(chainman.GetMutex());
        assert(chainman.ActiveTip() == active_tip);
        assert(chainman.ActiveHeight() == active_tip->nHeight);
        assert(chainstate.CoinsTip().GetBestBlock() == active_coins_tip);
        assert(chainstate.CoinsDB().GetBestBlock() == active_coins_db);
        assert(chainman.BlockIndex().size() == block_index_size);
        assert(chainstate.setBlockIndexCandidates.size() == candidate_count);
        assert(mempool.size() == mempool_size);
        mempool.check(chainstate.CoinsTip(), chainman.ActiveHeight() + 1);
    }
    chainman.CheckBlockIndex();
}

FUZZ_TARGET(validation_verify_db, .init = initialize_validation_verify_db)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    auto& chainman{*Assert(g_setup->m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& mempool{*Assert(g_setup->m_node.mempool)};
    const unsigned operation{fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 15)};
    constexpr int VERIFY_HEIGHT{COINBASE_MATURITY + 3};

    int check_level{0};
    int check_depth{1};
    bool insufficient_cache{false};
    bool interrupt{false};
    unsigned corruption{0};
    switch (operation) {
    case 0: break;
    case 1: check_level = 1; break;
    case 2: check_level = 2; break;
    case 3: check_level = 3; break;
    case 4: check_level = 4; break;
    case 5: check_level = 4; check_depth = 3; break;
    case 6: check_level = 4; check_depth = 0; break;
    case 7: check_level = -1; check_depth = -1; break;
    case 8: check_level = 5; check_depth = VERIFY_HEIGHT + 1; break;
    case 9: check_level = 3; check_depth = 2; insufficient_cache = true; break;
    case 10: check_level = 4; check_depth = 0; insufficient_cache = true; break;
    case 11: check_level = 2; check_depth = 3; interrupt = true; break;
    case 12: check_level = 3; corruption = 1; break;
    case 13: check_level = 3; corruption = 2; break;
    case 14: check_level = 4; corruption = 3; break;
    case 15:
        check_level = fuzzed_data_provider.ConsumeIntegral<int>();
        check_depth = fuzzed_data_provider.ConsumeIntegral<int>();
        break;
    }

    LOCK(chainman.GetMutex());
    const CBlockIndex* const active_tip{Assert(chainman.ActiveTip())};
    assert(active_tip == g_branch_indices[1].back());
    assert(active_tip->nHeight == VERIFY_HEIGHT);
    const uint256 coins_tip_best{chainstate.CoinsTip().GetBestBlock()};
    const uint256 coins_db_best{chainstate.CoinsDB().GetBestBlock()};
    const size_t coins_tip_size{chainstate.CoinsTip().GetCacheSize()};
    const size_t block_index_size{chainman.BlockIndex().size()};
    const size_t candidate_count{chainstate.setBlockIndexCandidates.size()};
    const size_t mempool_size{mempool.size()};
    const size_t original_cache_budget{chainstate.m_coinstip_cache_size_bytes};
    const kernel::CCoinsStats stats_before{*Assert(kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        chainstate.CoinsDB(),
        chainman.m_blockman))};
    AssertStatsEqual(stats_before, g_verify_stats);
    AssertCoinsEqual(chainstate.CoinsDB(), g_branch_states[1].back());

    CCoinsView* coins_view{&chainstate.CoinsDB()};
    CoinMap corrupt_state;
    std::unique_ptr<ReplayCoinsView> corrupt_view;
    if (corruption != 0) {
        corrupt_state = g_branch_states[1].back();
        const CTransactionRef& tip_coinbase{g_branch_blocks[1].back().vtx.front()};
        const COutPoint tip_coinbase_out{tip_coinbase->GetHash(), 0};
        if (corruption == 1) {
            assert(corrupt_state.erase(tip_coinbase_out) == 1);
        } else if (corruption == 2) {
            Coin& coin{corrupt_state.at(tip_coinbase_out)};
            switch (fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 3)) {
            case 0: ++coin.out.nValue; break;
            case 1: --coin.nHeight; break;
            case 2: coin.fCoinBase = false; break;
            case 3: coin.out.scriptPubKey << OP_DROP; break;
            }
        } else {
            const CTransactionRef& previous_tx{g_branch_blocks[1].at(1).vtx.at(1)};
            const COutPoint stale_outpoint{g_branch_blocks[1].at(2).vtx.at(1)->vin.front().prevout};
            assert(stale_outpoint == COutPoint(previous_tx->GetHash(), 0));
            assert(corrupt_state.emplace(
                stale_outpoint,
                Coin{previous_tx->vout.at(0), VERIFY_HEIGHT - 1, /*coinbase=*/false}).second);
        }
        corrupt_view = std::make_unique<ReplayCoinsView>(std::vector<uint256>{});
        for (const auto& [outpoint, coin] : corrupt_state) {
            corrupt_view->AddCoin(outpoint, Coin{coin}, /*possible_overwrite=*/false);
        }
        corrupt_view->SetBestBlock(active_tip->GetBlockHash());
        AssertViewEquals(*corrupt_view, corrupt_state);
        coins_view = corrupt_view.get();
    }

    VerifyDBResult expected{VerifyDBResult::SUCCESS};
    if (insufficient_cache) {
        assert(chainstate.CoinsTip().DynamicMemoryUsage() > 0);
        chainstate.m_coinstip_cache_size_bytes = 0;
        expected = VerifyDBResult::SKIPPED_L3_CHECKS;
    } else if (interrupt) {
        expected = VerifyDBResult::INTERRUPTED;
    } else if (corruption != 0) {
        expected = VerifyDBResult::CORRUPTED_BLOCK_DB;
    }

    const auto verify_once = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        assert(!static_cast<bool>(g_setup->m_interrupt));
        if (interrupt) assert(g_setup->m_interrupt());
        VerifyDBResult result;
        {
            CVerifyDB verify_db{chainman.GetNotifications()};
            result = verify_db.VerifyDB(
                chainstate,
                chainman.GetConsensus(),
                *coins_view,
                check_level,
                check_depth);
        }
        if (interrupt) assert(g_setup->m_interrupt.reset());
        return result;
    };
    assert(verify_once() == expected);
    assert(verify_once() == expected);
    chainstate.m_coinstip_cache_size_bytes = original_cache_budget;

    if (corrupt_view) {
        assert(corrupt_view->GetBestBlock() == active_tip->GetBlockHash());
        AssertViewEquals(*corrupt_view, corrupt_state);
    }
    const kernel::CCoinsStats stats_after{*Assert(kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        chainstate.CoinsDB(),
        chainman.m_blockman))};
    AssertStatsEqual(stats_after, g_verify_stats);
    AssertCoinsEqual(chainstate.CoinsDB(), g_branch_states[1].back());
    assert(chainman.ActiveTip() == active_tip);
    assert(chainman.ActiveHeight() == VERIFY_HEIGHT);
    assert(chainstate.CoinsTip().GetBestBlock() == coins_tip_best);
    assert(chainstate.CoinsDB().GetBestBlock() == coins_db_best);
    assert(chainstate.CoinsTip().GetCacheSize() == coins_tip_size);
    assert(chainman.BlockIndex().size() == block_index_size);
    assert(chainstate.setBlockIndexCandidates.size() == candidate_count);
    assert(mempool.size() == mempool_size);
    mempool.check(chainstate.CoinsTip(), chainman.ActiveHeight() + 1);
    chainman.CheckBlockIndex();
}
