// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/coinstats.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace {
void AssertStatsEqual(const kernel::CCoinsStats& first, const kernel::CCoinsStats& second)
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
    // A round trip may rewrite the same logical database into different
    // LevelDB files, so physical disk size is deliberately not an invariant.
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
                 const std::vector<CMutableTransaction>& transactions,
                 const CScript& coinbase_script)
{
    auto& chainman{*Assert(node.chainman)};
    node::BlockCreateOptions options;
    options.use_mempool = false;
    options.coinbase_output_script = coinbase_script;
    CBlock block{*Assert(PrepareBlock(node, options))};
    block.hashPrevBlock = previous.GetBlockHash();
    block.nTime = previous.nTime + 1;
    block.nBits = GetNextWorkRequired(&previous, &block, chainman.GetConsensus());

    CMutableTransaction coinbase{*block.vtx.front()};
    coinbase.vin.front().scriptSig = CScript{} << previous.nHeight + 1;
    coinbase.nLockTime = static_cast<uint32_t>(previous.nHeight);
    block.vtx = {MakeTransactionRef(std::move(coinbase))};
    for (const CMutableTransaction& tx : transactions) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    FinalizeBlock(block, chainman);
    return block;
}

struct BlockValidationStateCatcher final : public CValidationInterface {
    explicit BlockValidationStateCatcher(const uint256& hash) : m_hash{hash} {}

    const uint256 m_hash;
    std::optional<BlockValidationState> m_state;

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>& block,
                      const BlockValidationState& state) override
    {
        if (block->GetHash() == m_hash) m_state = state;
    }
};

CBlockIndex* ProcessValidBlock(const node::NodeContext& node, CBlock block)
{
    auto& chainman{*Assert(node.chainman)};
    const uint256 hash{block.GetHash()};
    bool new_block{false};
    assert(chainman.ProcessNewBlock(
        std::make_shared<const CBlock>(std::move(block)),
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block));
    assert(new_block);
    LOCK(chainman.GetMutex());
    CBlockIndex* const index{Assert(chainman.m_blockman.LookupBlockIndex(hash))};
    assert(index->nStatus & BLOCK_HAVE_DATA);
    assert(index->IsValid(BLOCK_VALID_TRANSACTIONS));
    return index;
}

CMutableTransaction MakeSpend(const COutPoint& input, CAmount output_value,
                              const CScript& output_script)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(input);
    tx.vout.emplace_back(output_value, output_script);
    return tx;
}

CMutableTransaction MakeWitnessSpend(const COutPoint& input,
                                     const std::vector<CTxOut>& outputs)
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(input);
    const CScript witness_script{CScript{} << OP_TRUE};
    tx.vin.front().scriptWitness.stack.emplace_back(
        witness_script.begin(), witness_script.end());
    tx.vout = outputs;
    return tx;
}

} // namespace

// Force a higher-work fork to fail only after the active chain has been
// disconnected and the valid prefix of the candidate has been connected.
FUZZ_TARGET(validation_activation_failure)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const unsigned mode{fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 7)};
    const size_t fork_depth{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(3, 40)};
    SetMockTime(std::chrono::seconds{1'600'000'000});

    auto setup{MakeNoLogFileContext<TestingSetup>()};
    auto& node{setup->m_node};
    auto& chainman{*Assert(node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& mempool{*Assert(node.mempool)};
    const CScript true_script{CScript{} << OP_TRUE};
    const CScript false_script{CScript{} << OP_FALSE};

    std::vector<CTransactionRef> coinbases;
    coinbases.reserve(COINBASE_MATURITY);
    node::BlockCreateOptions mining_options;
    mining_options.use_mempool = false;
    mining_options.coinbase_output_script = P2WSH_OP_TRUE;
    for (int height{1}; height <= COINBASE_MATURITY; ++height) {
        std::shared_ptr<CBlock> block{Assert(PrepareBlock(node, mining_options))};
        coinbases.push_back(block->vtx.front());
        assert(!MineBlock(node, block).IsNull());
        SetMockTime(std::chrono::seconds{1'600'000'000 + height});
    }

    const CTransactionRef& funding_tx{coinbases.at(0)};
    const COutPoint funding_out{funding_tx->GetHash(), 0};
    const CAmount funding_value{funding_tx->vout.front().nValue};
    CBlockIndex* fork;
    {
        LOCK(chainman.GetMutex());
        fork = Assert(chainman.ActiveTip());
    }
    assert(fork->nHeight == COINBASE_MATURITY);

    std::vector<CTransactionRef> active_transactions;
    std::vector<CBlockIndex*> active_indices;
    active_transactions.reserve(fork_depth);
    active_indices.reserve(fork_depth);
    CAmount active_value{funding_value};
    COutPoint active_input{funding_out};
    CBlockIndex* active_previous{fork};
    for (size_t depth{0}; depth < fork_depth; ++depth) {
        active_value -= 1'000;
        const CMutableTransaction tx{depth == 0 ?
            MakeWitnessSpend(active_input, {CTxOut{active_value, true_script}}) :
            MakeSpend(active_input, active_value, true_script)};
        const CTransactionRef tx_ref{MakeTransactionRef(tx)};
        CBlockIndex* const index{ProcessValidBlock(
            node,
            MakeBlock(
                node,
                *active_previous,
                {tx},
                CScript{} << static_cast<int64_t>(1'000 + depth) << OP_DROP << OP_TRUE))};
        active_transactions.push_back(tx_ref);
        active_indices.push_back(index);
        active_input = COutPoint{tx_ref->GetHash(), 0};
        active_previous = index;
    }
    CBlockIndex* const active_tip{active_indices.back()};
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == active_tip);

    // Keep an unrelated transaction in the mempool while both candidate chains
    // repeatedly disconnect and reconnect around the invalid block.
    const CTransactionRef& mempool_funding{coinbases.at(1)};
    const CAmount mempool_funding_value{mempool_funding->vout.front().nValue};
    const CMutableTransaction unrelated_tx{MakeWitnessSpend(
        COutPoint{mempool_funding->GetHash(), 0},
        {CTxOut{mempool_funding_value - 1'000, P2WSH_OP_TRUE}})};
    const CTransactionRef unrelated_ref{MakeTransactionRef(unrelated_tx)};
    {
        LOCK(chainman.GetMutex());
        const MempoolAcceptResult result{chainman.ProcessTransaction(unrelated_ref)};
        assert(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    assert(mempool.size() == 1);
    assert(mempool.exists(unrelated_ref->GetWitnessHash()));

    std::vector<CTransactionRef> side_transactions;
    std::vector<CBlock> side_blocks;
    std::vector<CBlockIndex*> side_indices;
    side_transactions.reserve(fork_depth);
    side_blocks.reserve(fork_depth);
    side_indices.reserve(fork_depth);
    CAmount side_value{funding_value};
    COutPoint side_input{funding_out};
    CBlockIndex* side_previous{fork};
    for (size_t depth{0}; depth < fork_depth; ++depth) {
        CMutableTransaction tx;
        if (depth == 0) {
            side_value -= 10'000;
            tx = MakeWitnessSpend(
                side_input,
                {
                    CTxOut{side_value, true_script},
                    CTxOut{1'000, false_script},
                });
        } else if (depth == 1) {
            side_value -= 2'000;
            tx.version = 2;
            tx.vin.emplace_back(side_input);
            tx.vout.emplace_back(side_value, true_script);
            tx.vout.emplace_back(1'000, true_script);
        } else {
            side_value -= 1'000;
            tx = MakeSpend(side_input, side_value, true_script);
        }
        const CTransactionRef tx_ref{MakeTransactionRef(tx)};
        CBlock block{MakeBlock(
            node,
            *side_previous,
            {tx},
            CScript{} << static_cast<int64_t>(2'000 + depth) << OP_DROP << OP_TRUE)};
        CBlockIndex* const index{ProcessValidBlock(node, block)};
        side_transactions.push_back(tx_ref);
        side_blocks.push_back(std::move(block));
        side_indices.push_back(index);
        side_input = COutPoint{tx_ref->GetHash(), 0};
        side_previous = index;
    }
    const CTransactionRef& side_tx1_ref{side_transactions.at(0)};
    const CTransactionRef& side_tx2_ref{side_transactions.at(1)};
    const CTransactionRef& side_tip_tx{side_transactions.back()};
    CBlockIndex* const side_tip{side_indices.back()};
    assert(side_tip->nHeight == active_tip->nHeight);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == active_tip);

    kernel::CCoinsStats stats_before;
    uint256 coins_best;
    size_t block_index_size;
    {
        LOCK(chainman.GetMutex());
        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
        stats_before = *Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            chainstate.CoinsDB(),
            chainman.m_blockman));
        assert(stats_before.hashBlock == active_tip->GetBlockHash());
        assert(stats_before.nHeight == active_tip->nHeight);
        coins_best = chainstate.CoinsDB().GetBestBlock();
        block_index_size = chainman.BlockIndex().size();
        assert(chainstate.CoinsTip().GetBestBlock() == coins_best);
        assert(chainstate.CoinsTip().GetCacheSize() == 0);
        assert(mempool.size() == 1);
        mempool.check(chainstate.CoinsTip(), chainman.ActiveHeight() + 1);
    }

    std::vector<CMutableTransaction> invalid_transactions;
    std::string_view expected_reason;
    if (mode == 0) {
        invalid_transactions.push_back(MakeSpend(
            COutPoint{Txid::FromUint256(uint256::ONE), 0}, 0, true_script));
        expected_reason = "bad-txns-inputs-missingorspent";
    } else if (mode == 1) {
        invalid_transactions.push_back(MakeSpend(
            COutPoint{side_tx1_ref->GetHash(), 1}, 0, true_script));
        expected_reason = "block-script-verify-flag-failed";
    } else if (mode == 3) {
        invalid_transactions.push_back(MakeSpend(
            COutPoint{side_tip_tx->GetHash(), 0},
            side_tip_tx->vout.front().nValue - 1'000,
            true_script));
        invalid_transactions.push_back(MakeSpend(
            COutPoint{side_tip_tx->GetHash(), 0},
            side_tip_tx->vout.front().nValue - 2'000,
            true_script));
        expected_reason = "bad-txns-inputs-missingorspent";
    } else if (mode == 4) {
        invalid_transactions.push_back(MakeSpend(
            COutPoint{side_tip_tx->GetHash(), 0},
            side_tip_tx->vout.front().nValue + 1,
            true_script));
        expected_reason = "bad-txns-in-belowout";
    } else if (mode == 5) {
        invalid_transactions.push_back(MakeSpend(
            COutPoint{side_blocks.back().vtx.front()->GetHash(), 0},
            side_blocks.back().vtx.front()->vout.front().nValue,
            true_script));
        expected_reason = "bad-txns-premature-spend-of-coinbase";
    } else if (mode == 6) {
        CMutableTransaction nonfinal{MakeSpend(
            COutPoint{side_tip_tx->GetHash(), 0},
            side_tip_tx->vout.front().nValue,
            true_script)};
        nonfinal.vin.front().nSequence = 2;
        invalid_transactions.push_back(std::move(nonfinal));
        expected_reason = "bad-txns-nonfinal";
    } else if (mode == 7) {
        invalid_transactions.emplace_back(*side_tx2_ref);
        expected_reason = "bad-txns-BIP30";
    }

    CBlock invalid_block{MakeBlock(
        node, *side_tip, invalid_transactions,
        CScript{} << OP_14 << OP_DROP << OP_TRUE)};
    if (mode == 2) {
        CMutableTransaction coinbase{*invalid_block.vtx.front()};
        ++coinbase.vout.front().nValue;
        invalid_block.vtx.front() = MakeTransactionRef(std::move(coinbase));
        FinalizeBlock(invalid_block, chainman);
        expected_reason = "bad-cb-amount";
    }
    assert(!expected_reason.empty());

    const uint256 invalid_hash{invalid_block.GetHash()};
    const auto invalid_shared{std::make_shared<const CBlock>(invalid_block)};
    BlockValidationStateCatcher catcher{invalid_hash};
    node.validation_signals->RegisterValidationInterface(&catcher);
    bool new_block{false};
    const bool processed{chainman.ProcessNewBlock(
        invalid_shared,
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &new_block)};
    node.validation_signals->UnregisterValidationInterface(&catcher);
    node.validation_signals->SyncWithValidationInterfaceQueue();

    assert(processed);
    assert(new_block);
    assert(catcher.m_state);
    assert(catcher.m_state->IsInvalid());
    assert(!catcher.m_state->IsError());
    assert(catcher.m_state->GetResult() == BlockValidationResult::BLOCK_CONSENSUS);
    if (mode == 1) {
        assert(std::string_view{catcher.m_state->GetRejectReason()}.starts_with(expected_reason));
    } else {
        assert(catcher.m_state->GetRejectReason() == expected_reason);
    }

    BlockValidationStateCatcher duplicate_catcher{invalid_hash};
    node.validation_signals->RegisterValidationInterface(&duplicate_catcher);
    bool duplicate_new_block{true};
    const bool duplicate_processed{chainman.ProcessNewBlock(
        invalid_shared,
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        &duplicate_new_block)};
    node.validation_signals->UnregisterValidationInterface(&duplicate_catcher);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    assert(!duplicate_processed);
    assert(!duplicate_new_block);
    assert(duplicate_catcher.m_state);
    assert(duplicate_catcher.m_state->IsInvalid());
    assert(!duplicate_catcher.m_state->IsError());
    assert(duplicate_catcher.m_state->GetResult() == BlockValidationResult::BLOCK_CACHED_INVALID);
    assert(duplicate_catcher.m_state->GetRejectReason() == "duplicate-invalid");

    {
        LOCK(chainman.GetMutex());
        CBlockIndex* const invalid_index{Assert(chainman.m_blockman.LookupBlockIndex(invalid_hash))};
        assert(invalid_index->nStatus & BLOCK_HAVE_DATA);
        assert(invalid_index->nStatus & BLOCK_FAILED_VALID);
        assert(!chainstate.setBlockIndexCandidates.contains(invalid_index));
        assert(chainman.ActiveTip() == active_tip);
        assert(chainman.ActiveHeight() == active_tip->nHeight);
        assert(chainstate.CoinsTip().GetBestBlock() == active_tip->GetBlockHash());
        assert(chainman.BlockIndex().size() == block_index_size + 1);
        assert(chainstate.setBlockIndexCandidates.contains(active_tip));
        for (const CBlockIndex* candidate : chainstate.setBlockIndexCandidates) {
            assert(!(candidate->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)));
            assert(candidate->HaveNumChainTxs());
        }
        for (const CBlockIndex* index : active_indices) {
            assert(index->IsValid(BLOCK_VALID_SCRIPTS));
        }
        for (const CBlockIndex* index : side_indices) assert(index->IsValid(BLOCK_VALID_SCRIPTS));

        const Coin& active_coin{chainstate.CoinsTip().AccessCoin(
            COutPoint{active_transactions.back()->GetHash(), 0})};
        assert(!active_coin.IsSpent());
        assert(active_coin.out == active_transactions.back()->vout.front());
        assert(active_coin.nHeight == active_tip->nHeight);
        assert(!active_coin.IsCoinBase());
        assert(chainstate.CoinsTip().AccessCoin(funding_out).IsSpent());
        assert(chainstate.CoinsTip().AccessCoin(
            COutPoint{side_tx1_ref->GetHash(), 0}).IsSpent());
        assert(chainstate.CoinsTip().AccessCoin(
            COutPoint{side_tx2_ref->GetHash(), 1}).IsSpent());
        assert(chainstate.CoinsTip().AccessCoin(
            COutPoint{side_tip_tx->GetHash(), 0}).IsSpent());

        assert(mempool.size() == 1);
        assert(mempool.exists(unrelated_ref->GetWitnessHash()));
        for (const CTransactionRef& tx : active_transactions) {
            assert(!mempool.exists(tx->GetWitnessHash()));
        }
        for (const CTransactionRef& tx : side_transactions) {
            assert(!mempool.exists(tx->GetWitnessHash()));
        }
        mempool.check(chainstate.CoinsTip(), chainman.ActiveHeight() + 1);

        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
        assert(chainstate.CoinsTip().GetCacheSize() == 0);
        assert(chainstate.CoinsTip().GetBestBlock() == coins_best);
        assert(chainstate.CoinsDB().GetBestBlock() == coins_best);
        assert(chainstate.CoinsDB().GetHeadBlocks().empty());
        const kernel::CCoinsStats stats_after{*Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            chainstate.CoinsDB(),
            chainman.m_blockman))};
        AssertStatsEqual(stats_after, stats_before);
    }
    chainman.CheckBlockIndex();
}
