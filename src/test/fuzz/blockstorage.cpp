// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <kernel/notifications_interface.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {
const BasicTestingSetup* g_setup;

constexpr uint32_t FAST_BLOCKFILE_SIZE{0x10000};

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

class BlockStorageModel
{
    std::array<std::optional<int>, node::BlockfileType::NUM_TYPES> m_cursors{0, std::nullopt};
    std::map<int, kernel::CBlockFileInfo> m_files;
    std::map<int, node::BlockfileType> m_file_types;

    int MaxFile() const
    {
        int result{0};
        for (const std::optional<int>& cursor : m_cursors) {
            if (cursor) result = std::max(result, *cursor);
        }
        return result;
    }

public:
    void UpdateBlock(const CBlock& block, unsigned int height, node::BlockfileType type,
                     const FlatFilePos& position)
    {
        auto& cursor{m_cursors[type]};
        if (!cursor || *cursor < position.nFile) cursor = position.nFile;
        assert(m_file_types.emplace(position.nFile, type).second ||
               m_file_types.at(position.nFile) == type);

        kernel::CBlockFileInfo& info{m_files[position.nFile]};
        info.AddBlock(height, block.GetBlockTime());
        info.nSize = std::max(
            info.nSize,
            position.nPos + static_cast<uint32_t>(GetSerializeSize(TX_WITH_WITNESS(block))));
    }

    FlatFilePos AddBlock(const CBlock& block, unsigned int height, node::BlockfileType type)
    {
        auto& cursor{m_cursors[type]};
        if (!cursor) cursor = MaxFile() + 1;

        int file{*cursor};
        const uint32_t add_size{static_cast<uint32_t>(
            GetSerializeSize(TX_WITH_WITNESS(block)) + node::STORAGE_HEADER_BYTES)};
        assert(add_size < FAST_BLOCKFILE_SIZE);
        while (m_files[file].nSize + add_size >= FAST_BLOCKFILE_SIZE) {
            file = MaxFile() + 1;
            cursor = file;
        }
        cursor = file;
        assert(m_file_types.emplace(file, type).second || m_file_types.at(file) == type);

        kernel::CBlockFileInfo& info{m_files[file]};
        const FlatFilePos result{file, info.nSize + node::STORAGE_HEADER_BYTES};
        info.AddBlock(height, block.GetBlockTime());
        info.nSize += add_size;
        return result;
    }

    FlatFilePos AddUndo(int file, const CBlockUndo& undo)
    {
        kernel::CBlockFileInfo& info{m_files.at(file)};
        const FlatFilePos result{file, info.nUndoSize + node::STORAGE_HEADER_BYTES};
        info.nUndoSize += static_cast<uint32_t>(
            GetSerializeSize(undo) + node::UNDO_DATA_DISK_OVERHEAD);
        return result;
    }

    const std::map<int, kernel::CBlockFileInfo>& Files() const { return m_files; }

    uint64_t Usage() const
    {
        uint64_t result{0};
        for (const auto& [_, info] : m_files) result += info.nSize + info.nUndoSize;
        return result;
    }
};

DataStream SerializeBlock(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return stream;
}

DataStream SerializeUndo(const CBlockUndo& undo)
{
    DataStream stream;
    stream << undo;
    return stream;
}

template <typename First, typename Second>
void AssertBytesEqual(const First& first, const Second& second)
{
    assert(first.size() == second.size());
    assert(std::equal(first.begin(), first.end(), second.begin(), second.end()));
}

size_t BlockPadding(FuzzedDataProvider& provider, size_t index)
{
    if (index < 4) {
        // Two writes for each blockfile type must cross the fast-prune file boundary.
        return provider.ConsumeIntegralInRange<size_t>(34'000, 38'000);
    }
    if (index < 6) return provider.ConsumeIntegralInRange<size_t>(0, 253);
    if (index < 8) return provider.ConsumeIntegralInRange<size_t>(58'000, 60'000);
    return provider.PickValueInArray<size_t>({
        0,
        1,
        252,
        253,
        16'383,
        16'384,
        32'000,
        48'000,
        60'000,
    });
}

CBlock MakeBlock(FuzzedDataProvider& provider, const uint256& previous_hash,
                 unsigned int height, size_t padding, uint8_t unique_id)
{
    CMutableTransaction coinbase;
    coinbase.version = provider.ConsumeBool() ? CTransaction::CURRENT_VERSION : 1;
    coinbase.nLockTime = height;
    coinbase.vin.resize(1);
    coinbase.vin.front().prevout.SetNull();
    coinbase.vin.front().scriptSig = CScript{} << static_cast<int64_t>(height) << unique_id;
    coinbase.vin.front().nSequence = provider.ConsumeIntegral<uint32_t>();
    if (provider.ConsumeBool()) {
        coinbase.vin.front().scriptWitness.stack.push_back(
            ConsumeRandomLengthByteVector(provider, 128));
    }

    const uint8_t fill{provider.ConsumeIntegral<uint8_t>()};
    std::vector<uint8_t> script_bytes(padding, fill);
    const std::vector<uint8_t> prefix{
        ConsumeRandomLengthByteVector(provider, std::min<size_t>(padding, 64))};
    std::copy(prefix.begin(), prefix.end(), script_bytes.begin());
    coinbase.vout.emplace_back(
        provider.ConsumeIntegralInRange<CAmount>(0, 100 * COIN),
        CScript{script_bytes.begin(), script_bytes.end()});

    CBlock block;
    block.nVersion = provider.ConsumeIntegral<int32_t>();
    block.hashPrevBlock = previous_hash;
    block.nTime = 1'600'000'000 + height + provider.ConsumeIntegralInRange<uint32_t>(0, 60);
    block.nBits = Params().GenesisBlock().nBits;
    block.nNonce = provider.ConsumeIntegral<uint32_t>();
    block.vtx = {MakeTransactionRef(std::move(coinbase))};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    return block;
}

CBlockUndo MakeUndo(FuzzedDataProvider& provider, unsigned int block_height)
{
    CBlockUndo undo;
    const size_t transaction_count{provider.ConsumeIntegralInRange<size_t>(0, 3)};
    undo.vtxundo.resize(transaction_count);
    for (CTxUndo& tx_undo : undo.vtxundo) {
        const size_t input_count{provider.ConsumeIntegralInRange<size_t>(1, 3)};
        for (size_t input{0}; input < input_count; ++input) {
            const std::vector<uint8_t> script_bytes{ConsumeRandomLengthByteVector(provider, 128)};
            const int height{provider.ConsumeBool()
                    ? 0
                    : provider.ConsumeIntegralInRange<int>(1, static_cast<int>(block_height))};
            tx_undo.vprevout.emplace_back(
                CTxOut{
                    provider.ConsumeIntegralInRange<CAmount>(0, 100 * COIN),
                    CScript{script_bytes.begin(), script_bytes.end()}},
                height,
                provider.ConsumeBool());
        }
    }
    return undo;
}

void AssertBlockReads(const node::BlockManager& blockman, const CBlock& expected,
                      const FlatFilePos& position, FuzzedDataProvider* provider = nullptr)
{
    const DataStream serialized{SerializeBlock(expected)};
    const auto raw{blockman.ReadRawBlock(position)};
    assert(raw);
    AssertBytesEqual(*raw, serialized);

    CBlock decoded;
    assert(blockman.ReadBlock(decoded, position, expected.GetHash()));
    AssertBytesEqual(SerializeBlock(decoded), serialized);

    uint256 wrong_hash{expected.GetHash()};
    wrong_hash.begin()[0] ^= 1;
    assert(!blockman.ReadBlock(decoded, position, wrong_hash));
    assert(blockman.ReadBlock(decoded, position, expected.GetHash()));
    AssertBytesEqual(SerializeBlock(decoded), serialized);

    if (provider) {
        const size_t offset{provider->ConsumeIntegralInRange<size_t>(0, serialized.size() - 1)};
        const size_t size{provider->ConsumeIntegralInRange<size_t>(1, serialized.size() - offset)};
        const auto part{blockman.ReadRawBlock(position, std::pair{offset, size})};
        assert(part);
        assert(part->size() == size);
        assert(std::equal(part->begin(), part->end(), serialized.begin() + offset));

        const auto empty{blockman.ReadRawBlock(position, std::pair<size_t, size_t>{offset, 0})};
        assert(!empty && empty.error() == node::ReadRawError::BadPartRange);
        const auto past_end{blockman.ReadRawBlock(
            position, std::pair<size_t, size_t>{serialized.size(), 1})};
        assert(!past_end && past_end.error() == node::ReadRawError::BadPartRange);
        const auto overflow{blockman.ReadRawBlock(
            position,
            std::pair<size_t, size_t>{
                std::numeric_limits<size_t>::max(),
                std::numeric_limits<size_t>::max()})};
        assert(!overflow && overflow.error() == node::ReadRawError::BadPartRange);
    }
}

void AssertFileState(node::BlockManager& blockman, const BlockStorageModel& model)
{
    LOCK(::cs_main);
    assert(blockman.CalculateCurrentUsage() == model.Usage());
    for (const auto& [file, expected] : model.Files()) {
        assert(SameFileInfo(*blockman.GetBlockFileInfo(file), expected));
    }
}
} // namespace

void initialize_blockstorage()
{
    static const auto testing_setup{MakeNoLogFileContext<>(ChainType::REGTEST)};
    g_setup = testing_setup.get();
}

FUZZ_TARGET(blockstorage, .init = initialize_blockstorage)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const fs::path blocks_dir{g_setup->m_args.GetDataDirNet() / "fuzz_blockstorage"};
    if (fs::exists(blocks_dir)) fs::remove_all(blocks_dir);
    assert(fs::create_directories(blocks_dir));

    const bool use_xor{provider.ConsumeBool()};
    const bool prune_mode{provider.ConsumeBool()};
    constexpr int SNAPSHOT_HEIGHT{1'000};
    kernel::Notifications notifications;
    const node::BlockManager::Options options{
        .chainparams = Params(),
        .use_xor = use_xor,
        .prune_target = prune_mode ? uint64_t{1} << 30 : 0,
        .fast_prune = true,
        .blocks_dir = blocks_dir,
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = "",
            .cache_bytes = 1_MiB,
            .memory_only = true,
        },
    };

    BlockStorageModel model;
    std::vector<CBlock> blocks;
    std::vector<unsigned int> heights;
    std::vector<node::BlockfileType> types;
    std::vector<FlatFilePos> positions;
    std::vector<CBlockIndex*> indexes;
    std::vector<CBlockUndo> undos;
    std::map<uint256, CBlockIndex> block_index;

    uint256 normal_root_hash{uint256::ONE};
    uint256 assumed_root_hash;
    assumed_root_hash.begin()[0] = 2;
    CBlockIndex normal_root;
    normal_root.phashBlock = &normal_root_hash;
    normal_root.nHeight = 0;
    CBlockIndex assumed_root;
    assumed_root.phashBlock = &assumed_root_hash;
    assumed_root.nHeight = SNAPSHOT_HEIGHT - 1;
    std::array<CBlockIndex*, node::BlockfileType::NUM_TYPES> parents{&normal_root, &assumed_root};
    std::array<uint256, node::BlockfileType::NUM_TYPES> previous_hashes{normal_root_hash, assumed_root_hash};
    std::array<unsigned int, node::BlockfileType::NUM_TYPES> next_heights{1, SNAPSHOT_HEIGHT};

    const size_t block_count{provider.ConsumeIntegralInRange<size_t>(8, 10)};
    blocks.reserve(block_count);
    heights.reserve(block_count);
    types.reserve(block_count);
    positions.reserve(block_count);
    indexes.reserve(block_count);
    undos.reserve(block_count);

    {
        node::BlockManager blockman{*Assert(g_setup->m_node.shutdown_signal), options};

        for (size_t index{0}; index < block_count; ++index) {
            // A snapshot can activate at runtime after normal block files already exist.
            if (index == 1) blockman.m_snapshot_height = SNAPSHOT_HEIGHT;
            const node::BlockfileType type{index < 8
                    ? (index % 2 == 0 ? node::BlockfileType::NORMAL : node::BlockfileType::ASSUMED)
                    : (provider.ConsumeBool() ? node::BlockfileType::NORMAL : node::BlockfileType::ASSUMED)};
            const unsigned int height{next_heights[type]++};
            types.push_back(type);
            heights.push_back(height);
            blocks.push_back(MakeBlock(
                provider,
                previous_hashes[type],
                height,
                BlockPadding(provider, index),
                static_cast<uint8_t>(index + 1)));
            previous_hashes[type] = blocks.back().GetHash();

            const FlatFilePos expected_position{model.AddBlock(blocks.back(), height, type)};
            FlatFilePos actual_position;
            {
                LOCK(::cs_main);
                actual_position = blockman.WriteBlock(blocks.back(), height);
            }
            assert(actual_position == expected_position);
            positions.push_back(actual_position);
            assert(fs::is_regular_file(blockman.GetBlockPosFilename(actual_position)));
            FuzzedDataProvider read_provider{buffer.data(), buffer.size()};
            for (size_t skip{0}; skip <= index; ++skip) {
                (void)read_provider.ConsumeIntegral<uint8_t>();
            }
            AssertBlockReads(blockman, blocks.back(), actual_position, &read_provider);
            AssertFileState(blockman, model);

            auto [block_it, inserted]{block_index.try_emplace(blocks.back().GetHash(), blocks.back())};
            assert(inserted);
            CBlockIndex& block{block_it->second};
            block.phashBlock = &block_it->first;
            block.pprev = parents[type];
            block.nHeight = height;
            {
                LOCK(::cs_main);
                block.nFile = actual_position.nFile;
                block.nDataPos = actual_position.nPos;
                block.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
            }
            parents[type] = &block;
            indexes.push_back(&block);
            assert(block.GetBlockHash() == blocks.back().GetHash());
            CBlock indexed_read;
            assert(blockman.ReadBlock(indexed_read, block));
            AssertBytesEqual(SerializeBlock(indexed_read), SerializeBlock(blocks.back()));
            FuzzedDataProvider undo_provider{buffer.data(), buffer.size()};
            for (size_t skip{0}; skip <= index; ++skip) {
                (void)undo_provider.ConsumeIntegral<uint16_t>();
            }
            undos.push_back(MakeUndo(undo_provider, height));
        }

        std::vector<size_t> undo_order(block_count);
        std::iota(undo_order.begin(), undo_order.end(), 0);
        if (provider.ConsumeBool()) std::reverse(undo_order.begin(), undo_order.end());
        if (!undo_order.empty()) {
            std::rotate(
                undo_order.begin(),
                undo_order.begin() + provider.ConsumeIntegral<size_t>() % undo_order.size(),
                undo_order.end());
        }

        for (const size_t index : undo_order) {
            CBlockIndex& block{*indexes[index]};
            const int block_file{WITH_LOCK(::cs_main, return block.nFile)};
            const FlatFilePos expected_position{model.AddUndo(block_file, undos[index])};
            BlockValidationState state;
            {
                LOCK(::cs_main);
                assert(blockman.WriteBlockUndo(undos[index], state, block));
            }
            assert(state.IsValid());
            {
                LOCK(::cs_main);
                assert(block.GetUndoPos() == expected_position);
                assert(block.nStatus & BLOCK_HAVE_UNDO);
            }
            AssertFileState(blockman, model);

            CBlockUndo decoded;
            assert(blockman.ReadBlockUndo(decoded, block));
            AssertBytesEqual(SerializeUndo(decoded), SerializeUndo(undos[index]));

            const uint64_t usage_before{model.Usage()};
            const FlatFilePos undo_position_before{
                WITH_LOCK(::cs_main, return block.GetUndoPos())};
            {
                LOCK(::cs_main);
                assert(blockman.WriteBlockUndo(undos[index], state, block));
            }
            assert(WITH_LOCK(::cs_main, return block.GetUndoPos()) == undo_position_before);
            assert(model.Usage() == usage_before);
            AssertFileState(blockman, model);
        }

        const auto underflow{blockman.ReadRawBlock(FlatFilePos{0, node::STORAGE_HEADER_BYTES - 1})};
        assert(!underflow && underflow.error() == node::ReadRawError::IO);
    }

    // Reopening the block directory must preserve the XOR key and every exact block/undo byte.
    // Reindexing the existing files must reconstruct their metadata and both file cursors.
    {
        node::BlockManager reopened{*Assert(g_setup->m_node.shutdown_signal), options};
        reopened.m_snapshot_height = SNAPSHOT_HEIGHT;
        BlockStorageModel reindex_model;
        std::vector<size_t> file_order(block_count);
        std::iota(file_order.begin(), file_order.end(), 0);
        std::sort(file_order.begin(), file_order.end(), [&](size_t first, size_t second) {
            if (positions[first].nFile != positions[second].nFile) {
                return positions[first].nFile < positions[second].nFile;
            }
            return positions[first].nPos < positions[second].nPos;
        });

        for (const size_t index : file_order) {
            reindex_model.UpdateBlock(blocks[index], heights[index], types[index], positions[index]);
            {
                LOCK(::cs_main);
                reopened.UpdateBlockInfo(blocks[index], heights[index], positions[index]);
            }
            AssertBlockReads(reopened, blocks[index], positions[index]);
            CBlockUndo decoded;
            assert(reopened.ReadBlockUndo(decoded, *indexes[index]));
            AssertBytesEqual(SerializeUndo(decoded), SerializeUndo(undos[index]));
        }
        AssertFileState(reopened, reindex_model);

        for (const auto& [file, original] : model.Files()) {
            const kernel::CBlockFileInfo& reconstructed{reindex_model.Files().at(file)};
            assert(reconstructed.nBlocks == original.nBlocks);
            assert(reconstructed.nSize == original.nSize);
            assert(reconstructed.nUndoSize == 0);
            assert(reconstructed.nHeightFirst == original.nHeightFirst);
            assert(reconstructed.nHeightLast == original.nHeightLast);
            assert(reconstructed.nTimeFirst == original.nTimeFirst);
            assert(reconstructed.nTimeLast == original.nTimeLast);
        }

        FuzzedDataProvider reopen_provider{buffer.data(), buffer.size()};
        const node::BlockfileType type{reopen_provider.ConsumeBool()
                ? node::BlockfileType::NORMAL
                : node::BlockfileType::ASSUMED};
        const unsigned int height{next_heights[type]++};
        const CBlock extra_block{MakeBlock(
            reopen_provider,
            previous_hashes[type],
            height,
            BlockPadding(reopen_provider, block_count),
            255)};
        const FlatFilePos expected_position{reindex_model.AddBlock(extra_block, height, type)};
        FlatFilePos actual_position;
        {
            LOCK(::cs_main);
            actual_position = reopened.WriteBlock(extra_block, height);
        }
        assert(actual_position == expected_position);
        AssertBlockReads(reopened, extra_block, actual_position, &reopen_provider);
        AssertFileState(reopened, reindex_model);
    }

    assert(fs::remove_all(blocks_dir) > 0);
}
