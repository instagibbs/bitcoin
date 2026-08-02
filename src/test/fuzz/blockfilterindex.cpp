// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <blockfilter.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <index/blockfilterindex.h>
#include <interfaces/chain.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/blockfilter.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <undo.h>
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
using ElementSet = GCSFilter::ElementSet;

struct BlockSpec {
    CAmount fee;
    CAmount burned_output;
    CAmount side_output;
    CAmount empty_output;
    bool reverse_outputs;
};

struct FilterRecord {
    const CBlockIndex* index;
    BlockFilter filter;
    uint256 header;
    std::optional<ElementSet> elements;
};

struct BranchBlock {
    std::shared_ptr<const CBlock> block;
    FilterRecord record;
};

struct Branch {
    uint8_t id;
    const CBlockIndex* previous_index;
    CTransactionRef previous_transaction;
    uint32_t previous_output;
    Coin previous_coin;
    uint256 previous_header;
    std::vector<BranchBlock> blocks;
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
        fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, 20'000),
        fuzzed_data_provider.ConsumeBool(),
    };
}

ElementSet ExpectedElements(const CBlock& block, const Coin& spent_coin)
{
    ElementSet elements;
    for (const CTransactionRef& transaction : block.vtx) {
        for (const CTxOut& output : transaction->vout) {
            const CScript& script{output.scriptPubKey};
            if (script.empty() || script.front() == OP_RETURN) continue;
            elements.emplace(script.begin(), script.end());
        }
    }
    const CScript& spent_script{spent_coin.out.scriptPubKey};
    if (!spent_script.empty()) {
        elements.emplace(spent_script.begin(), spent_script.end());
    }
    return elements;
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

void AssertFilterEqual(const BlockFilter& actual, const BlockFilter& expected)
{
    assert(actual.GetFilterType() == expected.GetFilterType());
    assert(actual.GetBlockHash() == expected.GetBlockHash());
    assert(actual.GetEncodedFilter() == expected.GetEncodedFilter());
    assert(actual.GetHash() == expected.GetHash());
    assert(actual.GetFilter().GetN() == expected.GetFilter().GetN());
}

void AssertRecord(BlockFilterIndex& index, const FilterRecord& expected,
                  const node::NodeContext& node)
{
    BlockFilter filter;
    uint256 header;
    assert(index.LookupFilter(expected.index, filter));
    assert(index.LookupFilterHeader(expected.index, header));
    AssertFilterEqual(filter, expected.filter);
    assert(header == expected.header);

    BlockFilter direct;
    assert(ComputeFilter(BlockFilterType::BASIC, *expected.index, direct,
                         Assert(node.chainman)->m_blockman));
    AssertFilterEqual(filter, direct);

    if (expected.elements) {
        assert(filter.GetFilter().GetN() == expected.elements->size());
        for (const GCSFilter::Element& element : *expected.elements) {
            assert(filter.GetFilter().Match(element));
        }
        assert(filter.GetFilter().MatchAny(*expected.elements) == !expected.elements->empty());
    }
}

void AssertRange(BlockFilterIndex& index, const std::vector<FilterRecord>& expected)
{
    assert(!expected.empty());
    const int start_height{expected.front().index->nHeight};
    const CBlockIndex* const stop_index{expected.back().index};
    assert(stop_index->nHeight - start_height + 1 == static_cast<int>(expected.size()));

    std::vector<BlockFilter> filters(1);
    std::vector<uint256> hashes(1);
    assert(index.LookupFilterRange(start_height, stop_index, filters));
    assert(index.LookupFilterHashRange(start_height, stop_index, hashes));
    assert(filters.size() == expected.size());
    assert(hashes.size() == expected.size());
    for (size_t i{0}; i < expected.size(); ++i) {
        assert(expected.at(i).index->nHeight == start_height + static_cast<int>(i));
        AssertFilterEqual(filters.at(i), expected.at(i).filter);
        assert(hashes.at(i) == expected.at(i).filter.GetHash());
    }
}

void AssertInvalidRanges(BlockFilterIndex& index, const CBlockIndex& stop_index)
{
    std::vector<BlockFilter> filters(1);
    std::vector<uint256> hashes(1);
    assert(!index.LookupFilterRange(-1, &stop_index, filters));
    assert(!index.LookupFilterHashRange(-1, &stop_index, hashes));
    assert(filters.size() == 1);
    assert(hashes.size() == 1);
    assert(!index.LookupFilterRange(stop_index.nHeight + 1, &stop_index, filters));
    assert(!index.LookupFilterHashRange(stop_index.nHeight + 1, &stop_index, hashes));
    assert(filters.size() == 1);
    assert(hashes.size() == 1);
}

std::vector<FilterRecord> BuildInitialRecords(BlockFilterIndex& index,
                                              const node::NodeContext& node)
{
    auto& chainman{*Assert(node.chainman)};
    std::vector<const CBlockIndex*> block_indexes;
    {
        LOCK(chainman.GetMutex());
        for (const CBlockIndex* block_index{chainman.ActiveChain().Genesis()};
             block_index;
             block_index = chainman.ActiveChain().Next(*block_index)) {
            block_indexes.push_back(block_index);
        }
    }

    std::vector<FilterRecord> records;
    uint256 previous_header;
    for (const CBlockIndex* block_index : block_indexes) {
        BlockFilter filter;
        assert(ComputeFilter(BlockFilterType::BASIC, *block_index, filter,
                             chainman.m_blockman));
        const uint256 header{filter.ComputeHeader(previous_header)};
        records.push_back({block_index, filter, header, std::nullopt});
        AssertRecord(index, records.back(), node);
        previous_header = header;
    }
    AssertRange(index, records);
    // Genesis is a compact-filter checkpoint, so a repeated lookup exercises
    // the public header-cache path without constructing an artificial chain.
    AssertRecord(index, records.front(), node);
    return records;
}

std::vector<FilterRecord> BranchRecords(const Branch& branch)
{
    std::vector<FilterRecord> records;
    records.reserve(branch.blocks.size());
    for (const BranchBlock& block : branch.blocks) records.push_back(block.record);
    return records;
}

void AssertBranch(BlockFilterIndex& index, const Branch& branch,
                  const node::NodeContext& node)
{
    const std::vector<FilterRecord> records{BranchRecords(branch)};
    AssertRange(index, records);
    for (const FilterRecord& record : records) AssertRecord(index, record, node);
}

void AssertNotIndexed(BlockFilterIndex& index, const CBlockIndex& block_index)
{
    BlockFilter filter;
    uint256 header;
    std::vector<BlockFilter> filters(1);
    std::vector<uint256> hashes(1);
    assert(!index.LookupFilter(&block_index, filter));
    assert(!index.LookupFilterHeader(&block_index, header));
    assert(!index.LookupFilterRange(block_index.nHeight, &block_index, filters));
    assert(!index.LookupFilterHashRange(block_index.nHeight, &block_index, hashes));
    assert(filters.size() == 1);
    assert(hashes.size() == 1);
}

void AssertGlobalLifecycle(node::NodeContext& node)
{
    assert(GetBlockFilterIndex(BlockFilterType::BASIC) == nullptr);
    assert(InitBlockFilterIndex([&] { return interfaces::MakeChain(node); },
                                BlockFilterType::BASIC, 1_MiB, /*f_memory=*/true,
                                /*f_wipe=*/false));
    BlockFilterIndex* const index{GetBlockFilterIndex(BlockFilterType::BASIC)};
    assert(index);
    assert(index->GetFilterType() == BlockFilterType::BASIC);
    assert(!InitBlockFilterIndex([&] { return interfaces::MakeChain(node); },
                                 BlockFilterType::BASIC, 1_MiB, /*f_memory=*/true,
                                 /*f_wipe=*/false));
    size_t count{0};
    ForEachBlockFilterIndex([&](BlockFilterIndex& entry) {
        assert(&entry == index);
        ++count;
    });
    assert(count == 1);
    assert(DestroyBlockFilterIndex(BlockFilterType::BASIC));
    assert(!DestroyBlockFilterIndex(BlockFilterType::BASIC));
    assert(GetBlockFilterIndex(BlockFilterType::BASIC) == nullptr);
    assert(InitBlockFilterIndex([&] { return interfaces::MakeChain(node); },
                                BlockFilterType::BASIC, 1_MiB, /*f_memory=*/true,
                                /*f_wipe=*/false));
    DestroyAllBlockFilterIndexes();
    assert(GetBlockFilterIndex(BlockFilterType::BASIC) == nullptr);
}

void AssertActive(BlockFilterIndex& index, const node::NodeContext& node,
                  const CBlockIndex& tip, bool flush)
{
    auto& chainman{*Assert(node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    assert(index.BlockUntilSyncedToCurrentChain());
    const IndexSummary summary{index.GetSummary()};
    assert(summary.synced);
    assert(summary.best_block_height == tip.nHeight);
    assert(summary.best_block_hash == tip.GetBlockHash());
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

void AssertUnflushed(BlockFilterIndex& index, const node::NodeContext& node,
                     const CBlockIndex& tip, const uint256& committed_tip)
{
    AssertActive(index, node, tip, /*flush=*/false);
    auto& chainman{*Assert(node.chainman)};
    LOCK(chainman.GetMutex());
    assert(chainman.ActiveChainstate().CoinsDB().GetBestBlock() == committed_tip);
}

void AppendBlock(TestChain100Setup& setup, Branch& branch,
                 FuzzedDataProvider& fuzzed_data_provider)
{
    const size_t depth{branch.blocks.size() + 1};
    const BlockSpec spec{ConsumeBlockSpec(fuzzed_data_provider)};
    const CAmount input_value{branch.previous_coin.out.nValue};
    assert(input_value > spec.fee + spec.burned_output + spec.side_output + spec.empty_output);
    const CAmount chain_value{
        input_value - spec.fee - spec.burned_output - spec.side_output - spec.empty_output};
    const CScript chain_script{SpendableScript(branch.id, depth, /*side=*/false)};

    std::vector<CTxOut> outputs;
    outputs.emplace_back(chain_value, chain_script);
    if (spec.burned_output != 0) {
        outputs.emplace_back(spec.burned_output, UnspendableScript(branch.id, depth));
    }
    if (spec.side_output != 0) {
        outputs.emplace_back(spec.side_output, SpendableScript(branch.id, depth, /*side=*/true));
    }
    if (spec.empty_output != 0) {
        outputs.emplace_back(spec.empty_output, CScript{});
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
        setup.m_node, *branch.previous_index, transaction, spec.fee, branch.id, depth))};
    CBlockUndo undo;
    undo.vtxundo.resize(1);
    undo.vtxundo.front().vprevout.push_back(branch.previous_coin);
    BlockFilter filter{BlockFilterType::BASIC, *block, undo};
    const uint256 header{filter.ComputeHeader(branch.previous_header)};
    const ElementSet elements{ExpectedElements(*block, branch.previous_coin)};
    assert(filter.GetFilter().GetN() == elements.size());

    CBlockIndex* const index{ProcessBlock(setup.m_node, block)};
    branch.blocks.push_back({block, {index, filter, header, elements}});
    branch.previous_index = index;
    branch.previous_transaction = block->vtx.at(1);
    branch.previous_output = chain_output;
    branch.previous_coin = Coin{branch.previous_transaction->vout.at(chain_output),
                                index->nHeight, /*coinbase=*/false};
    branch.previous_header = header;
}
} // namespace

FUZZ_TARGET(blockfilterindex_reorg)
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
    assert(!source->vout.front().scriptPubKey.empty());

    FilterRecord base_record;
    std::vector<FilterRecord> branch_a_records;
    std::vector<FilterRecord> branch_b_records;
    IndexSummary committed_summary;
    uint256 final_tip_hash;
    {
        BlockFilterIndex index{interfaces::MakeChain(node), BlockFilterType::BASIC,
                               1_MiB, /*f_memory=*/false, /*f_wipe=*/true};
        assert(index.Init());
        assert(!index.BlockUntilSyncedToCurrentChain());
        AssertNotIndexed(index, *base_tip);
        index.Sync();

        const std::vector<FilterRecord> initial_records{BuildInitialRecords(index, node)};
        assert(initial_records.back().index == base_tip);
        base_record = initial_records.back();
        AssertActive(index, node, *base_tip, /*flush=*/true);
        AssertInvalidRanges(index, *base_tip);

        const Coin source_coin{source->vout.front(), /*height=*/1, /*coinbase=*/true};
        Branch branch_a{
            /*id=*/1,
            base_tip,
            source,
            /*previous_output=*/0,
            source_coin,
            base_record.header,
            {},
        };
        Branch branch_b{
            /*id=*/2,
            base_tip,
            source,
            /*previous_output=*/0,
            source_coin,
            base_record.header,
            {},
        };

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_a, fuzzed_data_provider);
            assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
            AssertActive(index, node, *branch_a.previous_index, /*flush=*/true);
            AssertRecord(index, branch_a.blocks.back().record, node);
        }

        for (size_t i{0}; i < first_branch_depth; ++i) {
            AppendBlock(*setup, branch_b, fuzzed_data_provider);
            AssertNotIndexed(index, *branch_b.previous_index);
        }
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);

        AppendBlock(*setup, branch_b, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AssertActive(index, node, *branch_b.previous_index, /*flush=*/true);
        AssertBranch(index, branch_b, node);
        AssertBranch(index, branch_a, node);

        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(branch_a.previous_index->nChainWork == branch_b.previous_index->nChainWork);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_b.previous_index);
        AssertNotIndexed(index, *branch_a.previous_index);
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertActive(index, node, *branch_a.previous_index, /*flush=*/true);
        AssertBranch(index, branch_a, node);
        AssertBranch(index, branch_b, node);

        committed_summary = index.GetSummary();
        assert(committed_summary.best_block_hash == branch_a.previous_index->GetBlockHash());
        AppendBlock(*setup, branch_a, fuzzed_data_provider);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()) == branch_a.previous_index);
        AssertUnflushed(index, node, *branch_a.previous_index, committed_summary.best_block_hash);
        AssertBranch(index, branch_a, node);
        AssertBranch(index, branch_b, node);

        branch_a_records = BranchRecords(branch_a);
        branch_b_records = BranchRecords(branch_b);
        final_tip_hash = branch_a.previous_index->GetBlockHash();
        index.Stop();
    }

    {
        BlockFilterIndex index{interfaces::MakeChain(node), BlockFilterType::BASIC,
                               1_MiB, /*f_memory=*/false, /*f_wipe=*/false};
        assert(index.Init());
        assert(index.GetSummary().best_block_height == committed_summary.best_block_height);
        assert(index.GetSummary().best_block_hash == committed_summary.best_block_hash);
        assert(!index.GetSummary().synced);
        assert(!index.BlockUntilSyncedToCurrentChain());
        index.Sync();

        const CBlockIndex* final_tip{WITH_LOCK(
            chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(final_tip_hash))};
        assert(final_tip);
        AssertActive(index, node, *final_tip, /*flush=*/true);
        AssertRecord(index, base_record, node);
        AssertRange(index, branch_a_records);
        AssertRange(index, branch_b_records);
        for (const FilterRecord& record : branch_a_records) AssertRecord(index, record, node);
        for (const FilterRecord& record : branch_b_records) AssertRecord(index, record, node);
        AssertInvalidRanges(index, *final_tip);
        index.Stop();
    }

    AssertGlobalLifecycle(node);
}
