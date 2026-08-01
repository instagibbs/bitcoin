// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
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

void AssertViewEquals(const ReplayCoinsView& view, const CoinMap& expected)
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
    assert(view.GetCacheSize() == expected.size());
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
