// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <string>
#include <vector>

namespace {
constexpr int CHAIN_HEIGHT{400};
constexpr int PRUNE_LOCK_BUFFER{10};
constexpr std::array<int, 5> SIDE_BLOCK_HEIGHTS{10, 50, 110, 113, 200};

bool SameFileInfo(const kernel::CBlockFileInfo& first, const kernel::CBlockFileInfo& second)
{
    return first.nBlocks == second.nBlocks &&
        first.nSize == second.nSize &&
        first.nUndoSize == second.nUndoSize &&
        first.nHeightFirst == second.nHeightFirst &&
        first.nHeightLast == second.nHeightLast &&
        first.nTimeFirst == second.nTimeFirst &&
        first.nTimeLast == second.nTimeLast;
}

size_t BlockPadding(FuzzedDataProvider& provider, int height)
{
    static constexpr std::array<int, 10> LARGE_BLOCK_HEIGHTS{
        1, 10, 50, 90, 110, 112, 113, 200, 300, 400};
    if (std::ranges::find(LARGE_BLOCK_HEIGHTS, height) != LARGE_BLOCK_HEIGHTS.end()) {
        return provider.ConsumeIntegralInRange<size_t>(30'000, 46'000);
    }
    return provider.ConsumeIntegralInRange<size_t>(0, 16);
}

CBlock MakeBlock(FuzzedDataProvider& provider, const CBlockIndex& previous, int height,
                 bool padded = true, uint8_t branch_id = 0)
{
    CMutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.vin.resize(1);
    coinbase.vin.front().prevout.SetNull();
    coinbase.vin.front().scriptSig = CScript{} << static_cast<int64_t>(height)
                                               << static_cast<int64_t>(branch_id);
    coinbase.vout.emplace_back(0, CScript{});

    const size_t padding{padded ? BlockPadding(provider, height)
                                : provider.ConsumeIntegralInRange<size_t>(0, 16)};
    const uint8_t fill{provider.ConsumeIntegral<uint8_t>()};
    std::vector<uint8_t> bytes(padding, fill);
    const size_t prefix_size{std::min<size_t>(padding, 16)};
    const std::vector<uint8_t> prefix{provider.ConsumeBytes<uint8_t>(prefix_size)};
    std::copy(prefix.begin(), prefix.end(), bytes.begin());
    coinbase.vout.front().scriptPubKey = CScript{bytes.begin(), bytes.end()};

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = previous.GetBlockHash();
    block.nTime = previous.nTime + 1;
    block.nBits = Params().GenesisBlock().nBits;
    block.vtx = {MakeTransactionRef(std::move(coinbase))};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) {
        ++block.nNonce;
    }
    return block;
}

struct IndexState {
    uint32_t status;
    int file;
    unsigned int data_pos;
    unsigned int undo_pos;
};

struct FileState {
    kernel::CBlockFileInfo info;
    fs::path block_path;
    fs::path undo_path;
    FlatFilePos block_position;
    CBlockIndex* undo_index{nullptr};
};
} // namespace

FUZZ_TARGET(validation_prune)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider{buffer.data(), buffer.size()};

    const bool automatic{provider.ConsumeBool()};
    const int manual_height{provider.ConsumeIntegralInRange<int>(1, CHAIN_HEIGHT)};
    const bool use_prune_lock{provider.ConsumeBool()};
    const bool unbounded_prune_lock{provider.ConsumeBool()};
    const int prune_lock_height{provider.ConsumeIntegralInRange<int>(1, CHAIN_HEIGHT + 50)};
    const unsigned int closed_block_accounting{automatic
            ? provider.ConsumeIntegralInRange<unsigned int>(32_MiB, node::MAX_BLOCKFILE_SIZE)
            : 0};
    const unsigned int closed_undo_accounting{automatic
            ? provider.ConsumeIntegralInRange<unsigned int>(1_MiB, 8_MiB)
            : 0};
    const int headers_ahead{automatic
            ? provider.ConsumeIntegralInRange<int>(0, 32)
            : 0};
    FakeNodeClock clock{std::chrono::seconds{1'700'000'000}};

    TestOpts opts;
    opts.extra_args = {
        "-fastprune=1",
        "-maxmempool=0",
        automatic ? "-prune=550" : "-prune=1",
    };
    opts.min_validation_cache = true;
    opts.setup_net = false;
    opts.setup_validation_interface = false;
    auto setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, opts)};
    auto& chainman{*Assert(setup->m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& blockman{chainman.m_blockman};
    assert(blockman.IsPruneMode());
    assert(blockman.GetPruneTarget() == (automatic
            ? MIN_DISK_SPACE_FOR_BLOCK_FILES
            : node::BlockManager::PRUNE_TARGET_MANUAL));
    assert(!blockman.m_have_pruned);

    std::vector<CBlockIndex*> indexes;
    std::vector<CBlockIndex*> header_indexes;
    std::vector<CBlockIndex*> unlinked_indexes;
    std::vector<FlatFilePos> block_positions;
    indexes.reserve(CHAIN_HEIGHT);
    header_indexes.reserve(headers_ahead + SIDE_BLOCK_HEIGHTS.size());
    block_positions.reserve(CHAIN_HEIGHT);

    CBlockIndex* previous{WITH_LOCK(::cs_main, return chainstate.m_chain.Tip())};
    assert(previous && previous->nHeight == 0);
    CBlockIndex* best_header{previous};
    for (int height{1}; height <= CHAIN_HEIGHT; ++height) {
        const CBlock block{MakeBlock(provider, *previous, height)};
        CBlockIndex* index;
        FlatFilePos block_position;
        {
            LOCK(::cs_main);
            index = blockman.AddToBlockIndex(block, best_header);
            assert(index);
            assert(index->pprev == previous);
            assert(index->nHeight == height);
            block_position = blockman.WriteBlock(block, height);
            assert(!block_position.IsNull());
            index->nFile = block_position.nFile;
            index->nDataPos = block_position.nPos;
            index->nTx = 1;
            index->m_chain_tx_count = previous->m_chain_tx_count + 1;
            assert(index->RaiseValidity(BLOCK_VALID_TRANSACTIONS));
            index->nStatus |= BLOCK_HAVE_DATA;

            CBlockUndo undo;
            BlockValidationState state;
            assert(blockman.WriteBlockUndo(undo, state, *index));
            assert(state.IsValid());
            assert(index->nStatus & BLOCK_HAVE_UNDO);
        }
        indexes.push_back(index);
        block_positions.push_back(block_position);
        previous = index;

        if (std::ranges::find(SIDE_BLOCK_HEIGHTS, height) != SIDE_BLOCK_HEIGHTS.end()) {
            const CBlockIndex* const fork{Assert(index->pprev->pprev)};
            const CBlock parent_block{MakeBlock(
                provider, *fork, height - 1, /*padded=*/false, /*branch_id=*/1)};
            CBlockIndex* side_parent;
            {
                LOCK(::cs_main);
                side_parent = blockman.AddToBlockIndex(parent_block, best_header);
                assert(side_parent && side_parent->pprev == fork);
                assert(side_parent->nHeight == height - 1);
                assert(side_parent->nTx == 0);
                assert(!(side_parent->nStatus & BLOCK_HAVE_DATA));
            }
            header_indexes.push_back(side_parent);

            for (const uint8_t branch_id : {uint8_t{2}, uint8_t{3}}) {
                const CBlock side_block{MakeBlock(
                    provider, *side_parent, height, /*padded=*/false, branch_id)};
                CBlockIndex* side_index;
                FlatFilePos side_position;
                {
                    LOCK(::cs_main);
                    side_index = blockman.AddToBlockIndex(side_block, best_header);
                    assert(side_index && side_index->pprev == side_parent);
                    assert(side_index->nHeight == height);
                    side_position = blockman.WriteBlock(side_block, height);
                    assert(!side_position.IsNull());
                    side_index->nFile = side_position.nFile;
                    side_index->nDataPos = side_position.nPos;
                    side_index->nTx = 1;
                    assert(side_index->RaiseValidity(BLOCK_VALID_TRANSACTIONS));
                    side_index->nStatus |= BLOCK_HAVE_DATA;
                    blockman.AddUnlinkedBlock(side_index);
                    blockman.AddUnlinkedBlock(side_index);
                }
                indexes.push_back(side_index);
                unlinked_indexes.push_back(side_index);
                block_positions.push_back(side_position);
            }
        }
    }

    for (int offset{1}; offset <= headers_ahead; ++offset) {
        const CBlock header{MakeBlock(
            provider, *best_header, CHAIN_HEIGHT + offset, /*padded=*/false, /*branch_id=*/4)};
        LOCK(::cs_main);
        CBlockIndex* const index{blockman.AddToBlockIndex(header, best_header)};
        assert(index && index == best_header);
        assert(index->nHeight == CHAIN_HEIGHT + offset);
        assert(index->nTx == 0);
        assert(index->nFile == 0);
        assert(!(index->nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)));
        header_indexes.push_back(index);
    }

    {
        LOCK(::cs_main);
        chainstate.m_chain.SetTip(*previous);
        chainman.m_best_header = best_header;
        assert(chainstate.m_chain.Height() == CHAIN_HEIGHT);
        assert(best_header->nHeight == CHAIN_HEIGHT + headers_ahead);
        assert(best_header->GetAncestor(CHAIN_HEIGHT) == previous);
        assert(blockman.m_blocks_unlinked.size() == unlinked_indexes.size());
    }
    if (automatic) assert(chainman.IsInitialBlockDownload());

    if (use_prune_lock) {
        LOCK(::cs_main);
        blockman.UpdatePruneLock(
            "validation_prune",
            node::PruneLockInfo{.height_first = unbounded_prune_lock
                    ? std::numeric_limits<int>::max()
                    : prune_lock_height});
    }

    std::map<CBlockIndex*, IndexState> before_indexes;
    std::map<int, FileState> before_files;
    uint64_t expected_usage{0};
    int max_file{-1};
    const uint256 coins_best{WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetBestBlock())};
    const uint256 coins_db_best{WITH_LOCK(::cs_main, return chainstate.CoinsDB().GetBestBlock())};
    {
        LOCK(::cs_main);
        for (size_t i{0}; i < indexes.size(); ++i) {
            CBlockIndex* const index{indexes[i]};
            before_indexes.emplace(index, IndexState{
                .status = index->nStatus,
                .file = index->nFile,
                .data_pos = index->nDataPos,
                .undo_pos = index->nUndoPos,
            });
            max_file = std::max(max_file, index->nFile);
            auto [file_it, inserted]{before_files.try_emplace(index->nFile)};
            if (inserted) {
                file_it->second.block_position = block_positions[i];
            }
            if (!file_it->second.undo_index && (index->nStatus & BLOCK_HAVE_UNDO)) {
                file_it->second.undo_index = index;
            }
        }
        for (CBlockIndex* const index : header_indexes) {
            before_indexes.emplace(index, IndexState{
                .status = index->nStatus,
                .file = index->nFile,
                .data_pos = index->nDataPos,
                .undo_pos = index->nUndoPos,
            });
        }
        assert(before_indexes.size() == indexes.size() + header_indexes.size());
        assert(max_file > 0);
        for (auto& [file, state] : before_files) {
            if (automatic && file < max_file) {
                // Reach the production automatic-pruning threshold without allocating
                // hundreds of MiB. Only accounting for already-closed files is scaled;
                // serialized records and the live file cursor remain untouched.
                auto& info{*Assert(blockman.GetBlockFileInfo(file))};
                info.nSize = std::max(info.nSize, closed_block_accounting);
                info.nUndoSize = std::max(info.nUndoSize, closed_undo_accounting);
            }
            state.info = *Assert(blockman.GetBlockFileInfo(file));
            state.block_path = blockman.GetBlockPosFilename(FlatFilePos{file, 0});
            state.undo_path = state.block_path.parent_path();
            state.undo_path /= fs::PathFromString(strprintf("rev%05u.dat", file));
            assert(state.info.nSize > 0);
            assert(state.info.nUndoSize > 0);
            assert(state.undo_index);
            assert(fs::is_regular_file(state.block_path));
            assert(fs::is_regular_file(state.undo_path));
            expected_usage += state.info.nSize + state.info.nUndoSize;
        }
        assert(before_files.size() == static_cast<size_t>(max_file + 1));
        for (int file{0}; file <= max_file; ++file) assert(before_files.contains(file));
        assert(blockman.CalculateCurrentUsage() == expected_usage);
    }

    int last_prune{CHAIN_HEIGHT};
    if (use_prune_lock && !unbounded_prune_lock) {
        const int lock_height{prune_lock_height - PRUNE_LOCK_BUFFER - 1};
        last_prune = std::max(1, std::min(last_prune, lock_height));
    }
    const int requested_height{automatic ? CHAIN_HEIGHT : manual_height};
    const int prune_limit{std::min({
        requested_height,
        last_prune,
        CHAIN_HEIGHT - static_cast<int>(MIN_BLOCKS_TO_KEEP),
    })};
    const uint64_t base_automatic_buffer{
        node::BLOCKFILE_CHUNK_SIZE + node::UNDOFILE_CHUNK_SIZE};
    const uint64_t prune_target{blockman.GetPruneTarget()};
    const bool automatic_scan{!automatic ||
        expected_usage + base_automatic_buffer >= prune_target};
    const uint64_t automatic_buffer{base_automatic_buffer +
        (automatic_scan ? static_cast<uint64_t>(headers_ahead) * 1'000'000 : 0)};
    std::set<int> expected_pruned;
    if (automatic_scan) {
        for (const auto& [file, state] : before_files) {
            if (file >= max_file) continue;
            if (automatic && expected_usage + automatic_buffer < prune_target) break;
            if (state.info.nHeightLast <= static_cast<unsigned int>(prune_limit)) {
                expected_pruned.insert(file);
                expected_usage -= state.info.nSize + state.info.nUndoSize;
            }
        }
    }
    const uint256 expected_coins_db_best{
        expected_pruned.empty() ? coins_db_best : coins_best};

    if (automatic) {
        chainstate.PruneAndFlush();
    } else {
        PruneBlockFilesManual(chainstate, manual_height);
    }

    {
        LOCK(::cs_main);
        assert(chainstate.m_chain.Tip() == previous);
        assert(chainman.m_best_header == best_header);
        assert(chainstate.CoinsTip().GetBestBlock() == coins_best);
        assert(chainstate.CoinsDB().GetBestBlock() == expected_coins_db_best);
        assert(chainstate.CoinsDB().GetHeadBlocks().empty());
        assert(blockman.m_have_pruned == !expected_pruned.empty());
        assert(blockman.CalculateCurrentUsage() == expected_usage);

        if (!expected_pruned.empty()) {
            bool pruned_flag{false};
            assert(blockman.m_block_tree_db->ReadFlag("prunedblockfiles", pruned_flag));
            assert(pruned_flag);
        }

        for (const auto& [index, before] : before_indexes) {
            const bool pruned{(before.status & BLOCK_HAVE_DATA) &&
                expected_pruned.contains(before.file)};
            if (pruned) {
                assert(!(index->nStatus & BLOCK_HAVE_DATA));
                assert(!(index->nStatus & BLOCK_HAVE_UNDO));
                assert(index->nFile == 0);
                assert(index->nDataPos == 0);
                assert(index->nUndoPos == 0);
                assert(blockman.IsBlockPruned(*index));
            } else {
                assert(index->nStatus == before.status);
                assert(index->nFile == before.file);
                assert(index->nDataPos == before.data_pos);
                assert(index->nUndoPos == before.undo_pos);
                assert(!blockman.IsBlockPruned(*index));
            }
        }

        size_t expected_unlinked{0};
        for (CBlockIndex* const index : unlinked_indexes) {
            const bool retained{!expected_pruned.contains(before_indexes.at(index).file)};
            const size_t count{static_cast<size_t>(std::ranges::count(
                blockman.m_blocks_unlinked | std::views::values, index))};
            assert(count == retained);
            expected_unlinked += retained;
        }
        assert(blockman.m_blocks_unlinked.size() == expected_unlinked);

        for (const auto& [file, before] : before_files) {
            const bool pruned{expected_pruned.contains(file)};
            const kernel::CBlockFileInfo& after{*Assert(blockman.GetBlockFileInfo(file))};
            if (pruned) {
                assert(SameFileInfo(after, kernel::CBlockFileInfo{}));
            } else {
                assert(SameFileInfo(after, before.info));
            }
        }
    }

    for (const auto& [file, before] : before_files) {
        const bool pruned{expected_pruned.contains(file)};
        assert(fs::is_regular_file(before.block_path) == !pruned);
        assert(fs::is_regular_file(before.undo_path) == !pruned);
        const auto raw_block{blockman.ReadRawBlock(before.block_position)};
        assert(raw_block.has_value() == !pruned);
        CBlockUndo undo;
        assert(blockman.ReadBlockUndo(undo, *before.undo_index) == !pruned);
        if (!pruned) assert(undo.vtxundo.empty());
    }

    blockman.UnlinkPrunedFiles(expected_pruned);
    for (const int file : expected_pruned) {
        assert(!fs::exists(before_files.at(file).block_path));
        assert(!fs::exists(before_files.at(file).undo_path));
    }

    // Repeating the same automatic check, or a lower manual request, cannot prune
    // another file or perturb any in-memory, persisted, or physical state.
    const uint64_t usage_after{WITH_LOCK(::cs_main, return blockman.CalculateCurrentUsage())};
    if (automatic) {
        BlockValidationState state;
        assert(chainstate.FlushStateToDisk(state, FlushStateMode::NONE));
        assert(state.IsValid());
    } else {
        PruneBlockFilesManual(chainstate, 1);
    }
    {
        LOCK(::cs_main);
        assert(blockman.CalculateCurrentUsage() == usage_after);
        assert(chainstate.m_chain.Tip() == previous);
        assert(chainman.m_best_header == best_header);
        assert(chainstate.CoinsTip().GetBestBlock() == coins_best);
        assert(chainstate.CoinsDB().GetBestBlock() == expected_coins_db_best);
        assert(chainstate.CoinsDB().GetHeadBlocks().empty());
        assert(blockman.m_have_pruned == !expected_pruned.empty());

        for (const auto& [index, before] : before_indexes) {
            const bool pruned{(before.status & BLOCK_HAVE_DATA) &&
                expected_pruned.contains(before.file)};
            if (pruned) {
                assert(!(index->nStatus & BLOCK_HAVE_DATA));
                assert(!(index->nStatus & BLOCK_HAVE_UNDO));
                assert(index->nFile == 0);
                assert(index->nDataPos == 0);
                assert(index->nUndoPos == 0);
            } else {
                assert(index->nStatus == before.status);
                assert(index->nFile == before.file);
                assert(index->nDataPos == before.data_pos);
                assert(index->nUndoPos == before.undo_pos);
            }
        }
        for (const auto& [file, before] : before_files) {
            const bool pruned{expected_pruned.contains(file)};
            const kernel::CBlockFileInfo& after{*Assert(blockman.GetBlockFileInfo(file))};
            assert(SameFileInfo(after, pruned ? kernel::CBlockFileInfo{} : before.info));
        }
    }
    for (const auto& [file, before] : before_files) {
        const bool pruned{expected_pruned.contains(file)};
        assert(fs::is_regular_file(before.block_path) == !pruned);
        assert(fs::is_regular_file(before.undo_path) == !pruned);
    }
}
