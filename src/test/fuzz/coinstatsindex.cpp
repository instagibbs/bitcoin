// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {
struct ExpectedStats {
    int height;
    uint256 block_hash;
    uint64_t transaction_outputs;
    uint64_t bogo_size;
    CAmount total_amount;
    CAmount total_subsidy;
    arith_uint256 total_prevout_spent_amount;
    arith_uint256 total_new_outputs_ex_coinbase_amount;
    arith_uint256 total_coinbase_amount;
    CAmount total_unspendables_genesis_block;
    CAmount total_unspendables_bip30;
    CAmount total_unspendables_scripts;
    CAmount total_unspendables_unclaimed_rewards;
};

struct BlockSpec {
    CAmount fee;
    CAmount burned_output;
    CAmount side_output;
    CAmount unclaimed_reward;
    CAmount burned_coinbase;
    bool reverse_outputs;
    bool reverse_coinbase;
};

struct BranchBlock {
    std::shared_ptr<const CBlock> block;
    CBlockIndex* index;
    ExpectedStats expected;
};

struct Branch {
    uint8_t id;
    const CBlockIndex* previous_index;
    CTransactionRef previous_transaction;
    uint32_t previous_output;
    Coin previous_coin;
    ExpectedStats expected;
    std::vector<BranchBlock> blocks;
};

ExpectedStats ExpectedFromStats(const kernel::CCoinsStats& stats)
{
    assert(stats.total_amount);
    return {
        stats.nHeight,
        stats.hashBlock,
        stats.nTransactionOutputs,
        stats.nBogoSize,
        *stats.total_amount,
        stats.total_subsidy,
        stats.total_prevout_spent_amount,
        stats.total_new_outputs_ex_coinbase_amount,
        stats.total_coinbase_amount,
        stats.total_unspendables_genesis_block,
        stats.total_unspendables_bip30,
        stats.total_unspendables_scripts,
        stats.total_unspendables_unclaimed_rewards,
    };
}

void AssertExpected(const kernel::CCoinsStats& stats, const ExpectedStats& expected)
{
    assert(stats.index_used);
    assert(stats.nHeight == expected.height);
    assert(stats.hashBlock == expected.block_hash);
    assert(stats.nTransactionOutputs == expected.transaction_outputs);
    assert(stats.nBogoSize == expected.bogo_size);
    assert(stats.total_amount == std::optional<CAmount>{expected.total_amount});
    assert(stats.total_subsidy == expected.total_subsidy);
    assert(stats.total_prevout_spent_amount == expected.total_prevout_spent_amount);
    assert(stats.total_new_outputs_ex_coinbase_amount == expected.total_new_outputs_ex_coinbase_amount);
    assert(stats.total_coinbase_amount == expected.total_coinbase_amount);
    assert(stats.total_unspendables_genesis_block == expected.total_unspendables_genesis_block);
    assert(stats.total_unspendables_bip30 == expected.total_unspendables_bip30);
    assert(stats.total_unspendables_scripts == expected.total_unspendables_scripts);
    assert(stats.total_unspendables_unclaimed_rewards == expected.total_unspendables_unclaimed_rewards);
}

void AssertStatsEqual(const kernel::CCoinsStats& first, const kernel::CCoinsStats& second)
{
    assert(first.nHeight == second.nHeight);
    assert(first.hashBlock == second.hashBlock);
    assert(first.nTransactionOutputs == second.nTransactionOutputs);
    assert(first.nBogoSize == second.nBogoSize);
    assert(first.hashSerialized == second.hashSerialized);
    assert(first.total_amount == second.total_amount);
    assert(first.index_used == second.index_used);
    assert(first.total_subsidy == second.total_subsidy);
    assert(first.total_prevout_spent_amount == second.total_prevout_spent_amount);
    assert(first.total_new_outputs_ex_coinbase_amount == second.total_new_outputs_ex_coinbase_amount);
    assert(first.total_coinbase_amount == second.total_coinbase_amount);
    assert(first.total_unspendables_genesis_block == second.total_unspendables_genesis_block);
    assert(first.total_unspendables_bip30 == second.total_unspendables_bip30);
    assert(first.total_unspendables_scripts == second.total_unspendables_scripts);
    assert(first.total_unspendables_unclaimed_rewards == second.total_unspendables_unclaimed_rewards);
}

CScript SpendableScript(uint8_t branch, size_t depth, bool side)
{
    const int64_t tag{static_cast<int64_t>(branch) * 1'000 + static_cast<int64_t>(depth) * 2 + side};
    return CScript{} << tag << OP_DROP << OP_TRUE;
}

CScript UnspendableScript(uint8_t branch, size_t depth, bool coinbase)
{
    return CScript{} << OP_RETURN << std::vector<unsigned char>{branch, static_cast<unsigned char>(depth), coinbase};
}

BlockSpec ConsumeBlockSpec(FuzzedDataProvider& fuzzed_data_provider)
{
    return {
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeBool(),
        fuzzed_data_provider.ConsumeBool(),
    };
}

void FinalizeBlock(CBlock& block, ChainstateManager& chainman)
{
    node::RegenerateCommitments(block, chainman);
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) {
        ++block.nNonce;
        assert(block.nNonce != 0);
    }
}

CBlock MakeBlock(const node::NodeContext& node, const CBlockIndex& previous,
                 const CMutableTransaction& transaction, CAmount fee,
                 const BlockSpec& spec, uint8_t branch, size_t depth)
{
    auto& chainman{*Assert(node.chainman)};
    node::BlockCreateOptions options;
    options.use_mempool = false;
    options.coinbase_output_script = SpendableScript(branch, depth, /*side=*/true);
    CBlock block{*Assert(PrepareBlock(node, options))};
    block.hashPrevBlock = previous.GetBlockHash();
    block.nTime = previous.nTime + 1;
    block.nBits = GetNextWorkRequired(&previous, &block, chainman.GetConsensus());

    CMutableTransaction coinbase{*block.vtx.front()};
    const int commitment_index{GetWitnessCommitmentIndex(block)};
    assert(commitment_index >= 0);
    const CTxOut commitment{coinbase.vout.at(commitment_index)};
    coinbase.vin.front().scriptSig = CScript{} << previous.nHeight + 1;
    coinbase.nLockTime = static_cast<uint32_t>(previous.nHeight);
    const CAmount subsidy{GetBlockSubsidy(previous.nHeight + 1, chainman.GetConsensus())};
    assert(spec.unclaimed_reward <= subsidy + fee);
    const CAmount claimed{subsidy + fee - spec.unclaimed_reward};
    const CAmount burned{std::min(spec.burned_coinbase, claimed)};
    std::vector<CTxOut> coinbase_outputs;
    coinbase_outputs.emplace_back(claimed - burned, SpendableScript(branch, depth, /*side=*/true));
    if (burned != 0) {
        coinbase_outputs.emplace_back(burned, UnspendableScript(branch, depth, /*coinbase=*/true));
    }
    if (spec.reverse_coinbase) std::reverse(coinbase_outputs.begin(), coinbase_outputs.end());
    // RegenerateCommitments replaces the commitment made by PrepareBlock, so
    // preserve that placeholder after replacing the economic coinbase outputs.
    coinbase_outputs.push_back(commitment);
    coinbase.vout = std::move(coinbase_outputs);

    block.vtx = {MakeTransactionRef(std::move(coinbase)), MakeTransactionRef(transaction)};
    FinalizeBlock(block, chainman);
    return block;
}

CBlockIndex* ProcessBlock(const node::NodeContext& node, std::shared_ptr<const CBlock> block)
{
    auto& chainman{*Assert(node.chainman)};
    const uint256 hash{block->GetHash()};
    bool new_block{false};
    assert(chainman.ProcessNewBlock(
        std::move(block), /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    assert(new_block);
    LOCK(chainman.GetMutex());
    CBlockIndex* const index{Assert(chainman.m_blockman.LookupBlockIndex(hash))};
    assert(index->nStatus & BLOCK_HAVE_DATA);
    assert(index->IsValid(BLOCK_VALID_TRANSACTIONS));
    return index;
}

void ApplyBlock(ExpectedStats& expected, const CBlock& block, const Coin& spent_coin,
                const Consensus::Params& consensus)
{
    assert(block.vtx.size() == 2);
    const CTransaction& transaction{*block.vtx.at(1)};
    assert(transaction.vin.size() == 1);
    assert(expected.transaction_outputs > 0);
    assert(expected.bogo_size >= kernel::GetBogoSize(spent_coin.out.scriptPubKey));
    assert(expected.total_amount >= spent_coin.out.nValue);

    --expected.transaction_outputs;
    expected.bogo_size -= kernel::GetBogoSize(spent_coin.out.scriptPubKey);
    expected.total_amount -= spent_coin.out.nValue;
    expected.total_prevout_spent_amount += spent_coin.out.nValue;

    CAmount transaction_outputs{0};
    CAmount coinbase_outputs{0};
    for (size_t tx_index{0}; tx_index < block.vtx.size(); ++tx_index) {
        const bool coinbase{tx_index == 0};
        for (const CTxOut& output : block.vtx.at(tx_index)->vout) {
            if (coinbase) {
                coinbase_outputs += output.nValue;
            } else {
                transaction_outputs += output.nValue;
            }
            if (output.scriptPubKey.IsUnspendable()) {
                expected.total_unspendables_scripts += output.nValue;
                continue;
            }
            ++expected.transaction_outputs;
            expected.bogo_size += kernel::GetBogoSize(output.scriptPubKey);
            expected.total_amount += output.nValue;
            if (coinbase) {
                expected.total_coinbase_amount += output.nValue;
            } else {
                expected.total_new_outputs_ex_coinbase_amount += output.nValue;
            }
        }
    }

    const int height{expected.height + 1};
    const CAmount subsidy{GetBlockSubsidy(height, consensus)};
    const CAmount unclaimed{spent_coin.out.nValue + subsidy - transaction_outputs - coinbase_outputs};
    assert(unclaimed >= 0);
    expected.total_subsidy += subsidy;
    expected.total_unspendables_unclaimed_rewards += unclaimed;
    expected.height = height;
    expected.block_hash = block.GetHash();
}

void AppendBlock(TestChain100Setup& setup, Branch& branch,
                 FuzzedDataProvider& fuzzed_data_provider)
{
    const size_t depth{branch.blocks.size() + 1};
    const BlockSpec spec{ConsumeBlockSpec(fuzzed_data_provider)};
    const CAmount input_value{branch.previous_coin.out.nValue};
    assert(input_value > spec.fee + spec.burned_output + spec.side_output);
    const CAmount chain_value{input_value - spec.fee - spec.burned_output - spec.side_output};
    const CScript chain_script{SpendableScript(branch.id, depth, /*side=*/false)};

    std::vector<CTxOut> outputs;
    outputs.emplace_back(chain_value, chain_script);
    if (spec.burned_output != 0) {
        outputs.emplace_back(spec.burned_output, UnspendableScript(branch.id, depth, /*coinbase=*/false));
    }
    if (spec.side_output != 0) {
        outputs.emplace_back(spec.side_output, SpendableScript(branch.id, depth, /*side=*/true));
    }
    if (spec.reverse_outputs) std::reverse(outputs.begin(), outputs.end());

    const auto chain_output_it{std::find_if(outputs.begin(), outputs.end(), [&](const CTxOut& output) {
        return output.scriptPubKey == chain_script;
    })};
    assert(chain_output_it != outputs.end());
    const uint32_t chain_output{static_cast<uint32_t>(chain_output_it - outputs.begin())};

    CMutableTransaction transaction;
    if (branch.blocks.empty()) {
        transaction = setup.CreateValidMempoolTransaction(
            /*input_transactions=*/{branch.previous_transaction},
            /*inputs=*/{COutPoint{branch.previous_transaction->GetHash(), branch.previous_output}},
            /*input_height=*/branch.previous_coin.nHeight,
            /*input_signing_keys=*/{setup.coinbaseKey},
            outputs,
            /*submit=*/false);
    } else {
        transaction.version = 2;
        transaction.vin.emplace_back(branch.previous_transaction->GetHash(), branch.previous_output);
        transaction.vout = outputs;
    }

    const auto block{std::make_shared<const CBlock>(MakeBlock(
        setup.m_node, *branch.previous_index, transaction, spec.fee, spec, branch.id, depth))};
    CBlockIndex* const index{ProcessBlock(setup.m_node, block)};
    ApplyBlock(branch.expected, *block, branch.previous_coin, Assert(setup.m_node.chainman)->GetConsensus());
    assert(branch.expected.height == index->nHeight);
    assert(branch.expected.block_hash == index->GetBlockHash());
    branch.blocks.push_back({block, index, branch.expected});
    branch.previous_index = index;
    branch.previous_transaction = block->vtx.at(1);
    branch.previous_output = chain_output;
    branch.previous_coin = Coin{branch.previous_transaction->vout.at(chain_output), index->nHeight, /*coinbase=*/false};
}

kernel::CCoinsStats AssertLookup(CoinStatsIndex& index, const BranchBlock& block)
{
    const auto stats{index.LookUpStats(*block.index)};
    assert(stats);
    AssertExpected(*stats, block.expected);
    return *stats;
}

kernel::CCoinsStats AssertActiveStats(CoinStatsIndex& index, const node::NodeContext& node,
                                      const CBlockIndex& tip, const ExpectedStats& expected)
{
    auto& chainman{*Assert(node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    assert(index.BlockUntilSyncedToCurrentChain());
    const IndexSummary summary{index.GetSummary()};
    assert(summary.synced);
    assert(summary.best_block_height == tip.nHeight);
    assert(summary.best_block_hash == tip.GetBlockHash());

    const auto indexed{index.LookUpStats(tip)};
    assert(indexed);
    AssertExpected(*indexed, expected);

    std::optional<kernel::CCoinsStats> direct;
    {
        LOCK(chainman.GetMutex());
        assert(chainman.ActiveTip() == &tip);
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
        assert(chainstate.CoinsTip().GetCacheSize() == 0);
        assert(chainstate.CoinsTip().GetBestBlock() == tip.GetBlockHash());
        assert(chainstate.CoinsDB().GetBestBlock() == tip.GetBlockHash());
        direct = kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::MUHASH, chainstate.CoinsDB(), chainman.m_blockman);
        assert(direct);
        assert(node.mempool->size() == 0);
        node.mempool->check(chainstate.CoinsTip(), tip.nHeight + 1);
        chainman.CheckBlockIndex();
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();

    assert(!direct->index_used);
    assert(direct->nHeight == indexed->nHeight);
    assert(direct->hashBlock == indexed->hashBlock);
    assert(direct->hashSerialized == indexed->hashSerialized);
    assert(direct->nTransactionOutputs == indexed->nTransactionOutputs);
    assert(direct->nTransactionOutputs == direct->coins_count);
    assert(direct->nBogoSize == indexed->nBogoSize);
    assert(direct->total_amount == indexed->total_amount);
    return *indexed;
}

kernel::CCoinsStats AssertUnflushedStats(CoinStatsIndex& index, const node::NodeContext& node,
                                         const CBlockIndex& tip, const uint256& committed_tip,
                                         const ExpectedStats& expected)
{
    auto& chainman{*Assert(node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    assert(index.BlockUntilSyncedToCurrentChain());
    const IndexSummary summary{index.GetSummary()};
    assert(summary.synced);
    assert(summary.best_block_height == tip.nHeight);
    assert(summary.best_block_hash == tip.GetBlockHash());

    const auto indexed{index.LookUpStats(tip)};
    assert(indexed);
    AssertExpected(*indexed, expected);
    {
        LOCK(chainman.GetMutex());
        assert(chainman.ActiveTip() == &tip);
        assert(chainstate.CoinsTip().GetBestBlock() == tip.GetBlockHash());
        assert(chainstate.CoinsDB().GetBestBlock() == committed_tip);
        assert(node.mempool->size() == 0);
        node.mempool->check(chainstate.CoinsTip(), tip.nHeight + 1);
        chainman.CheckBlockIndex();
    }
    return *indexed;
}
} // namespace

FUZZ_TARGET(coinstatsindex_reorg)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(std::chrono::seconds{1'600'000'000});
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const size_t first_branch_depth{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 3)};

    auto setup{MakeNoLogFileContext<TestChain100Setup>(
        ChainType::REGTEST, TestOpts{.setup_net = false})};
    auto& node{setup->m_node};
    auto& chainman{*Assert(node.chainman)};
    const CBlockIndex* base_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip())};
    assert(base_tip);
    assert(base_tip->nHeight == COINBASE_MATURITY);
    const CTransactionRef source{setup->m_coinbase_txns.front()};
    assert(!source->vout.empty());
    assert(!source->vout.front().scriptPubKey.IsUnspendable());

    kernel::CCoinsStats base_stats;
    std::vector<kernel::CCoinsStats> branch_a_stats;
    std::vector<kernel::CCoinsStats> branch_b_stats;
    IndexSummary committed_summary;
    {
        CoinStatsIndex index{interfaces::MakeChain(node), 1_MiB,
                             /*f_memory=*/false, /*f_wipe=*/true};
        assert(index.Init());
        assert(!index.BlockUntilSyncedToCurrentChain());
        assert(!index.LookUpStats(*base_tip));
        index.Sync();

        const auto initial_stats{index.LookUpStats(*base_tip)};
        assert(initial_stats);
        const ExpectedStats expected_base{ExpectedFromStats(*initial_stats)};
        base_stats = AssertActiveStats(index, node, *base_tip, expected_base);

        const Coin source_coin{source->vout.front(), /*height=*/1, /*coinbase=*/true};
        Branch branch_a{
            /*id=*/1,
            base_tip,
            source,
            /*previous_output=*/0,
            source_coin,
            expected_base,
            {},
        };
        Branch branch_b{
            /*id=*/2,
            base_tip,
            source,
            /*previous_output=*/0,
            source_coin,
            expected_base,
            {},
        };

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_a, fuzzed_data_provider);
            assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
            branch_a_stats.push_back(AssertActiveStats(
                index, node, *branch_a.previous_index, branch_a.expected));
        }

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_b, fuzzed_data_provider);
        }
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        assert(index.GetSummary().best_block_hash == branch_a.previous_index->GetBlockHash());

        AppendBlock(*setup, branch_b, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AssertActiveStats(index, node, *branch_b.previous_index, branch_b.expected);
        for (const BranchBlock& block : branch_b.blocks) {
            branch_b_stats.push_back(AssertLookup(index, block));
        }
        for (size_t i{0}; i < branch_a.blocks.size(); ++i) {
            AssertStatsEqual(AssertLookup(index, branch_a.blocks.at(i)), branch_a_stats.at(i));
        }

        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(branch_a.previous_index->nChainWork == branch_b.previous_index->nChainWork);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertActiveStats(index, node, *branch_a.previous_index, branch_a.expected);

        branch_a_stats.clear();
        for (const BranchBlock& block : branch_a.blocks) {
            branch_a_stats.push_back(AssertLookup(index, block));
        }
        for (size_t i{0}; i < branch_b.blocks.size(); ++i) {
            AssertStatsEqual(AssertLookup(index, branch_b.blocks.at(i)), branch_b_stats.at(i));
        }

        committed_summary = index.GetSummary();
        assert(committed_summary.best_block_hash == branch_a.previous_index->GetBlockHash());
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        branch_a_stats.push_back(AssertUnflushedStats(
            index, node, *branch_a.previous_index, committed_summary.best_block_hash,
            branch_a.expected));
        for (size_t i{0}; i < branch_b.blocks.size(); ++i) {
            AssertStatsEqual(AssertLookup(index, branch_b.blocks.at(i)), branch_b_stats.at(i));
        }

        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(node), 1_MiB,
                             /*f_memory=*/false, /*f_wipe=*/false};
        assert(index.Init());
        assert(index.GetSummary().best_block_height == committed_summary.best_block_height);
        assert(index.GetSummary().best_block_hash == committed_summary.best_block_hash);
        assert(!index.GetSummary().synced);
        assert(!index.BlockUntilSyncedToCurrentChain());
        index.Sync();

        const CBlockIndex* final_tip{WITH_LOCK(
            chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(branch_a_stats.back().hashBlock))};
        assert(final_tip);
        AssertStatsEqual(
            AssertActiveStats(index, node, *final_tip, ExpectedFromStats(branch_a_stats.back())),
            branch_a_stats.back());

        const auto reloaded_base{index.LookUpStats(*base_tip)};
        assert(reloaded_base);
        AssertStatsEqual(*reloaded_base, base_stats);
        for (const kernel::CCoinsStats& expected : branch_a_stats) {
            const CBlockIndex* block{WITH_LOCK(
                chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(expected.hashBlock))};
            assert(block);
            const auto actual{index.LookUpStats(*block)};
            assert(actual);
            AssertStatsEqual(*actual, expected);
        }
        for (const kernel::CCoinsStats& expected : branch_b_stats) {
            const CBlockIndex* block{WITH_LOCK(
                chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(expected.hashBlock))};
            assert(block);
            const auto actual{index.LookUpStats(*block)};
            assert(actual);
            AssertStatsEqual(*actual, expected);
        }
        index.Stop();
    }
}
