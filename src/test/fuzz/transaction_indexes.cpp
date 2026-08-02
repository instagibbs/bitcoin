// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <index/txindex.h>
#include <index/txospenderindex.h>
#include <interfaces/chain.h>
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
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace {
struct BlockSpec {
    CAmount fee;
    CAmount burned_output;
    CAmount side_output;
    size_t extra_inputs;
    bool reverse_outputs;
};

struct TransactionRecord {
    std::shared_ptr<const CBlock> block;
    const CBlockIndex* index;
    CTransactionRef coinbase;
    CTransactionRef transaction;
    std::vector<COutPoint> inputs;
    COutPoint chain_output;
};

struct Branch {
    uint8_t id;
    const CBlockIndex* previous_index;
    CTransactionRef previous_transaction;
    uint32_t previous_output;
    std::vector<TransactionRecord> records;
};

CScript SpendableScript(uint8_t branch, size_t depth, bool side)
{
    const int64_t tag{static_cast<int64_t>(branch) * 1'000 + static_cast<int64_t>(depth) * 2 + side};
    return CScript{} << tag << OP_DROP << OP_TRUE;
}

CScript UnspendableScript(uint8_t branch, size_t depth)
{
    return CScript{} << OP_RETURN << std::vector<unsigned char>{branch, static_cast<unsigned char>(depth)};
}

BlockSpec ConsumeBlockSpec(FuzzedDataProvider& fuzzed_data_provider)
{
    return {
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 2),
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
                 uint8_t branch, size_t depth)
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
    coinbase.vout = {
        CTxOut{GetBlockSubsidy(previous.nHeight + 1, chainman.GetConsensus()) + fee,
               SpendableScript(branch, depth, /*side=*/true)},
        commitment,
    };

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

void AssertTxFound(const TxIndex& index, const CTransactionRef& expected,
                   const uint256& expected_block_hash)
{
    CTransactionRef transaction;
    uint256 block_hash;
    assert(index.FindTx(expected->GetHash(), block_hash, transaction));
    assert(transaction);
    assert(*transaction == *expected);
    assert(transaction->GetWitnessHash() == expected->GetWitnessHash());
    assert(block_hash == expected_block_hash);
}

void AssertTxNotFound(const TxIndex& index, const CTransactionRef& transaction)
{
    CTransactionRef found;
    uint256 block_hash;
    assert(!index.FindTx(transaction->GetHash(), block_hash, found));
}

void AssertRecordFound(const TxIndex& index, const TransactionRecord& record)
{
    AssertTxFound(index, record.coinbase, record.index->GetBlockHash());
    AssertTxFound(index, record.transaction, record.index->GetBlockHash());
}

void AssertRecordNotFound(const TxIndex& index, const TransactionRecord& record)
{
    AssertTxNotFound(index, record.coinbase);
    AssertTxNotFound(index, record.transaction);
}

void AssertSpender(const TxoSpenderIndex& index, const COutPoint& outpoint,
                   const TransactionRecord* expected)
{
    const auto result{index.FindSpender(outpoint)};
    assert(result);
    const std::optional<TxoSpender>& spender{result.value()};
    if (!expected) {
        assert(!spender);
        return;
    }
    assert(spender);
    assert(spender->tx);
    assert(*spender->tx == *expected->transaction);
    assert(spender->tx->GetWitnessHash() == expected->transaction->GetWitnessHash());
    assert(spender->block_hash == expected->index->GetBlockHash());
}

std::vector<TransactionRecord> BranchRecords(const Branch& branch)
{
    return branch.records;
}

void AssertSpenderState(const TxoSpenderIndex& index,
                        const std::vector<TransactionRecord>& active,
                        const std::vector<TransactionRecord>& first_branch,
                        const std::vector<TransactionRecord>& second_branch)
{
    std::map<COutPoint, const TransactionRecord*> expected;
    for (const TransactionRecord& record : active) {
        for (const COutPoint& input : record.inputs) {
            assert(expected.emplace(input, &record).second);
        }
    }

    std::set<COutPoint> queries;
    for (const std::vector<TransactionRecord>* branch : {&first_branch, &second_branch}) {
        for (const TransactionRecord& record : *branch) {
            queries.insert(record.inputs.begin(), record.inputs.end());
            queries.insert(record.chain_output);
        }
    }
    queries.emplace(Txid{}, std::numeric_limits<uint32_t>::max());
    for (const COutPoint& outpoint : queries) {
        const auto match{expected.find(outpoint)};
        AssertSpender(index, outpoint, match == expected.end() ? nullptr : match->second);
    }
}

void AssertIndexesActive(TxIndex& tx_index, TxoSpenderIndex& spender_index,
                         const node::NodeContext& node, const CBlockIndex& tip,
                         bool flush)
{
    auto& chainman{*Assert(node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    assert(tx_index.BlockUntilSyncedToCurrentChain());
    assert(spender_index.BlockUntilSyncedToCurrentChain());
    for (const BaseIndex* index : {static_cast<BaseIndex*>(&tx_index),
                                  static_cast<BaseIndex*>(&spender_index)}) {
        const IndexSummary summary{index->GetSummary()};
        assert(summary.synced);
        assert(summary.best_block_height == tip.nHeight);
        assert(summary.best_block_hash == tip.GetBlockHash());
    }
    {
        LOCK(chainman.GetMutex());
        assert(chainman.ActiveTip() == &tip);
        if (flush) chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
        assert(chainstate.CoinsTip().GetBestBlock() == tip.GetBlockHash());
        assert(node.mempool->size() == 0);
        node.mempool->check(chainstate.CoinsTip(), tip.nHeight + 1);
        chainman.CheckBlockIndex();
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();
}

void AssertUnflushed(TxIndex& tx_index, TxoSpenderIndex& spender_index,
                     const node::NodeContext& node, const CBlockIndex& tip,
                     const uint256& committed_tip)
{
    AssertIndexesActive(tx_index, spender_index, node, tip, /*flush=*/false);
    auto& chainman{*Assert(node.chainman)};
    LOCK(chainman.GetMutex());
    assert(chainman.ActiveChainstate().CoinsDB().GetBestBlock() == committed_tip);
}

void AppendBlock(TestChain100Setup& setup, Branch& branch,
                 FuzzedDataProvider& fuzzed_data_provider)
{
    const size_t depth{branch.records.size() + 1};
    const BlockSpec spec{ConsumeBlockSpec(fuzzed_data_provider)};
    std::vector<CTransactionRef> input_transactions{branch.previous_transaction};
    std::vector<COutPoint> inputs{
        COutPoint{branch.previous_transaction->GetHash(), branch.previous_output}};
    CAmount input_value{branch.previous_transaction->vout.at(branch.previous_output).nValue};
    for (size_t i{0}; i < spec.extra_inputs; ++i) {
        const size_t source_index{1 + (depth - 1) * 2 + i};
        const CTransactionRef& source{setup.m_coinbase_txns.at(source_index)};
        assert(!source->vout.empty());
        input_transactions.push_back(source);
        inputs.emplace_back(source->GetHash(), 0);
        input_value += source->vout.front().nValue;
    }
    assert(input_value > spec.fee + spec.burned_output + spec.side_output);
    const CAmount chain_value{input_value - spec.fee - spec.burned_output - spec.side_output};
    const CScript chain_script{SpendableScript(branch.id, depth, /*side=*/false)};

    std::vector<CTxOut> outputs;
    outputs.emplace_back(chain_value, chain_script);
    if (spec.burned_output != 0) {
        outputs.emplace_back(spec.burned_output, UnspendableScript(branch.id, depth));
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

    const CMutableTransaction transaction{setup.CreateValidMempoolTransaction(
        input_transactions, inputs, /*input_height=*/1,
        /*input_signing_keys=*/{setup.coinbaseKey}, outputs, /*submit=*/false)};
    const auto block{std::make_shared<const CBlock>(MakeBlock(
        setup.m_node, *branch.previous_index, transaction, spec.fee, branch.id, depth))};
    CBlockIndex* const index{ProcessBlock(setup.m_node, block)};
    const CTransactionRef spending_transaction{block->vtx.at(1)};
    branch.records.push_back({
        block,
        index,
        block->vtx.front(),
        spending_transaction,
        inputs,
        COutPoint{spending_transaction->GetHash(), chain_output},
    });
    branch.previous_index = index;
    branch.previous_transaction = spending_transaction;
    branch.previous_output = chain_output;
}

void AssertRecordsFound(const TxIndex& index, const std::vector<TransactionRecord>& records)
{
    for (const TransactionRecord& record : records) AssertRecordFound(index, record);
}
} // namespace

FUZZ_TARGET(transaction_indexes_reorg)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(std::chrono::seconds{1'600'000'000});
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const size_t first_branch_depth{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 3)};

    auto setup{MakeNoLogFileContext<TestChain100Setup>(
        ChainType::REGTEST, TestOpts{.setup_net = false})};
    auto& node{setup->m_node};
    auto& chainman{*Assert(node.chainman)};
    for (size_t i{0}; i < 20; ++i) {
        setup->CreateAndProcessBlock({}, SpendableScript(/*branch=*/0, i, /*side=*/false));
    }
    node.validation_signals->SyncWithValidationInterfaceQueue();
    const CBlockIndex* base_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip())};
    assert(base_tip);
    assert(base_tip->nHeight == COINBASE_MATURITY + 20);
    const CTransactionRef source{setup->m_coinbase_txns.front()};
    const COutPoint source_outpoint{source->GetHash(), 0};
    const CBlockIndex* source_index{WITH_LOCK(
        chainman.GetMutex(), return chainman.ActiveChain()[1])};
    assert(source_index);

    std::vector<TransactionRecord> branch_a_records;
    std::vector<TransactionRecord> branch_b_records;
    IndexSummary committed_tx_summary;
    IndexSummary committed_spender_summary;
    uint256 final_tip_hash;
    {
        TxIndex tx_index{interfaces::MakeChain(node), 1_MiB,
                         /*f_memory=*/false, /*f_wipe=*/true};
        TxoSpenderIndex spender_index{interfaces::MakeChain(node), 1_MiB,
                                      /*f_memory=*/false, /*f_wipe=*/true};
        assert(tx_index.Init());
        assert(spender_index.Init());
        assert(!tx_index.BlockUntilSyncedToCurrentChain());
        assert(!spender_index.BlockUntilSyncedToCurrentChain());
        AssertTxNotFound(tx_index, source);
        AssertSpender(spender_index, source_outpoint, nullptr);
        tx_index.Sync();
        spender_index.Sync();

        AssertIndexesActive(tx_index, spender_index, node, *base_tip, /*flush=*/true);
        AssertTxFound(tx_index, source, source_index->GetBlockHash());
        AssertSpender(spender_index, source_outpoint, nullptr);
        for (const CTransactionRef& transaction : Params().GenesisBlock().vtx) {
            AssertTxNotFound(tx_index, transaction);
        }

        Branch branch_a{
            /*id=*/1,
            base_tip,
            source,
            /*previous_output=*/0,
            {},
        };
        Branch branch_b{
            /*id=*/2,
            base_tip,
            source,
            /*previous_output=*/0,
            {},
        };

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_a, fuzzed_data_provider);
            assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
            AssertIndexesActive(tx_index, spender_index, node, *branch_a.previous_index, /*flush=*/true);
            AssertRecordFound(tx_index, branch_a.records.back());
            AssertSpenderState(spender_index, BranchRecords(branch_a),
                               BranchRecords(branch_a), BranchRecords(branch_b));
        }

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_b, fuzzed_data_provider);
            AssertRecordNotFound(tx_index, branch_b.records.back());
        }
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertSpenderState(spender_index, BranchRecords(branch_a),
                           BranchRecords(branch_a), BranchRecords(branch_b));

        AppendBlock(*setup, branch_b, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AssertIndexesActive(tx_index, spender_index, node, *branch_b.previous_index, /*flush=*/true);
        AssertRecordsFound(tx_index, BranchRecords(branch_a));
        AssertRecordsFound(tx_index, BranchRecords(branch_b));
        AssertSpenderState(spender_index, BranchRecords(branch_b),
                           BranchRecords(branch_a), BranchRecords(branch_b));

        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(branch_a.previous_index->nChainWork == branch_b.previous_index->nChainWork);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AssertRecordNotFound(tx_index, branch_a.records.back());
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertIndexesActive(tx_index, spender_index, node, *branch_a.previous_index, /*flush=*/true);
        AssertRecordsFound(tx_index, BranchRecords(branch_a));
        AssertRecordsFound(tx_index, BranchRecords(branch_b));
        AssertSpenderState(spender_index, BranchRecords(branch_a),
                           BranchRecords(branch_a), BranchRecords(branch_b));

        committed_tx_summary = tx_index.GetSummary();
        committed_spender_summary = spender_index.GetSummary();
        assert(committed_tx_summary.best_block_hash == branch_a.previous_index->GetBlockHash());
        assert(committed_spender_summary.best_block_hash == committed_tx_summary.best_block_hash);
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertUnflushed(tx_index, spender_index, node, *branch_a.previous_index,
                        committed_tx_summary.best_block_hash);
        AssertRecordsFound(tx_index, BranchRecords(branch_a));
        AssertRecordsFound(tx_index, BranchRecords(branch_b));
        AssertSpenderState(spender_index, BranchRecords(branch_a),
                           BranchRecords(branch_a), BranchRecords(branch_b));

        branch_a_records = BranchRecords(branch_a);
        branch_b_records = BranchRecords(branch_b);
        final_tip_hash = branch_a.previous_index->GetBlockHash();
        tx_index.Stop();
        spender_index.Stop();
    }

    {
        TxIndex tx_index{interfaces::MakeChain(node), 1_MiB,
                         /*f_memory=*/false, /*f_wipe=*/false};
        TxoSpenderIndex spender_index{interfaces::MakeChain(node), 1_MiB,
                                      /*f_memory=*/false, /*f_wipe=*/false};
        assert(tx_index.Init());
        assert(spender_index.Init());
        assert(tx_index.GetSummary().best_block_hash == committed_tx_summary.best_block_hash);
        assert(spender_index.GetSummary().best_block_hash == committed_spender_summary.best_block_hash);
        assert(!tx_index.GetSummary().synced);
        assert(!spender_index.GetSummary().synced);
        assert(!tx_index.BlockUntilSyncedToCurrentChain());
        assert(!spender_index.BlockUntilSyncedToCurrentChain());
        tx_index.Sync();
        spender_index.Sync();

        const CBlockIndex* final_tip{WITH_LOCK(
            chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(final_tip_hash))};
        assert(final_tip);
        AssertIndexesActive(tx_index, spender_index, node, *final_tip, /*flush=*/true);
        AssertTxFound(tx_index, source, source_index->GetBlockHash());
        AssertRecordsFound(tx_index, branch_a_records);
        AssertRecordsFound(tx_index, branch_b_records);
        AssertSpenderState(spender_index, branch_a_records,
                           branch_a_records, branch_b_records);
        tx_index.Stop();
        spender_index.Stop();
    }
}
