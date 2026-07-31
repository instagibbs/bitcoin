// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <blockencodings.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <util/translation.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace {
const TestingSetup* g_setup;

class FuzzedCBlockHeaderAndShortTxIDs : public CBlockHeaderAndShortTxIDs
{
    using CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs;

public:
    void MakePrefilledGapInvalid()
    {
        prefilledtxn.front().index = std::numeric_limits<uint16_t>::max();
    }

    void MakePrefilledOverflowInvalid()
    {
        prefilledtxn.push_back({std::numeric_limits<uint16_t>::max(), prefilledtxn.front().tx});
    }

    void AddDuplicateShortIds(size_t count)
    {
        const uint64_t short_id{GetShortID(prefilledtxn.front().tx->GetWitnessHash())};
        shorttxids.insert(shorttxids.end(), count, short_id);
    }
};
} // namespace

void initialize_pdb()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

PartiallyDownloadedBlock::IsBlockMutatedFn FuzzedIsBlockMutated(bool result)
{
    return [result](const CBlock& block, bool) {
        return result;
    };
}

FUZZ_TARGET(partially_downloaded_block, .init = initialize_pdb)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};

    auto block{ConsumeDeserializable<CBlock>(fuzzed_data_provider, TX_WITH_WITNESS)};
    if (!block || block->vtx.size() == 0 ||
        block->vtx.size() >= std::numeric_limits<uint16_t>::max()) {
        return;
    }

    const uint8_t mutation{fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 4)};
    if (mutation != 0 && block->IsNull()) block->nBits = 1;

    FuzzedCBlockHeaderAndShortTxIDs cmpctblock{*block, fuzzed_data_provider.ConsumeIntegral<uint64_t>()};
    std::optional<ReadStatus> expected_init_status;
    switch (mutation) {
    case 0:
        break;
    case 1:
        cmpctblock.MakePrefilledGapInvalid();
        expected_init_status = READ_STATUS_INVALID;
        break;
    case 2:
        cmpctblock.MakePrefilledOverflowInvalid();
        expected_init_status = READ_STATUS_INVALID;
        break;
    case 3:
        cmpctblock.AddDuplicateShortIds(2);
        expected_init_status = block->vtx.front()->IsNull() ? READ_STATUS_INVALID : READ_STATUS_FAILED;
        break;
    case 4:
        cmpctblock.AddDuplicateShortIds(13);
        expected_init_status = block->vtx.front()->IsNull() ? READ_STATUS_INVALID : READ_STATUS_FAILED;
        break;
    }

    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(g_setup->m_node), error};
    Assert(error.empty());
    PartiallyDownloadedBlock pdb{&pool};

    // Set of available transactions (mempool or extra_txn)
    std::set<uint16_t> available;
    // The coinbase is always available
    available.insert(0);

    std::vector<std::pair<Wtxid, CTransactionRef>> extra_txn;
    for (size_t i = 1; i < block->vtx.size(); ++i) {
        auto tx{block->vtx[i]};

        bool add_to_extra_txn{fuzzed_data_provider.ConsumeBool()};
        bool add_to_mempool{fuzzed_data_provider.ConsumeBool()};

        if (add_to_extra_txn) {
            extra_txn.emplace_back(tx->GetWitnessHash(), tx);
            available.insert(i);
        }

        if (add_to_mempool && !pool.exists(tx->GetHash())) {
            LOCK2(cs_main, pool.cs);
            TryAddToMempool(pool, ConsumeTxMemPoolEntry(fuzzed_data_provider, *tx));
            available.insert(i);
        }
    }

    // Exercise an extra-pool short ID collision without needing to brute-force
    // a 48-bit SipHash collision. The announced wtxid is the same, but the
    // second transaction does not match it.
    if (block->vtx.size() > 1 && fuzzed_data_provider.ConsumeBool()) {
        const size_t index{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, block->vtx.size() - 1)};
        const CTransactionRef& tx{block->vtx[index]};
        CMutableTransaction conflicting_tx{*tx};
        conflicting_tx.version ^= 1;
        extra_txn.emplace_back(tx->GetWitnessHash(), tx);
        extra_txn.emplace_back(tx->GetWitnessHash(), MakeTransactionRef(std::move(conflicting_tx)));
        available.insert(index);
    }

    auto init_status{pdb.InitData(cmpctblock, extra_txn)};

    if (expected_init_status) {
        assert(init_status == *expected_init_status);
        CBlock unused;
        assert(pdb.FillBlock(unused, {}, /*segwit_active=*/false) == READ_STATUS_INVALID);
        return;
    }

    std::vector<CTransactionRef> missing;
    std::vector<size_t> missing_indexes;
    for (size_t i = 0; i < cmpctblock.BlockTxCount(); i++) {
        // If init_status == READ_STATUS_OK then a available transaction in the
        // compact block (i.e. IsTxAvailable(i) == true) implies that we marked
        // that transaction as available above (i.e. available.contains(i)).
        // The reverse is not true, due to possible compact block short id
        // collisions (i.e. available.contains(i) does not imply
        // IsTxAvailable(i) == true).
        if (init_status == READ_STATUS_OK) {
            assert(!pdb.IsTxAvailable(i) || available.contains(i));
        }

        const bool is_available{pdb.IsTxAvailable(i)};
        if (!is_available) {
            missing_indexes.push_back(i);
            if (!fuzzed_data_provider.ConsumeBool()) missing.push_back(block->vtx[i]);
        }
    }

    if (fuzzed_data_provider.ConsumeBool()) missing.push_back(block->vtx.front());

    bool segwit_active{fuzzed_data_provider.ConsumeBool()};

    const bool mock_block_mutated{fuzzed_data_provider.ConsumeBool()};
    const bool fail_block_mutated{fuzzed_data_provider.ConsumeBool()};
    if (mock_block_mutated) pdb.m_check_block_mutated_mock = FuzzedIsBlockMutated(fail_block_mutated);

    std::optional<CBlock> expected_block;
    std::optional<bool> expected_block_mutated;
    if (missing.size() == missing_indexes.size()) {
        expected_block = *block;
        for (size_t i = 0; i < missing.size(); ++i) {
            expected_block->vtx[missing_indexes[i]] = missing[i];
        }
        expected_block_mutated = mock_block_mutated ? fail_block_mutated : IsBlockMutated(*expected_block, segwit_active);
    }

    CBlock reconstructed_block;
    auto fill_status{pdb.FillBlock(reconstructed_block, missing, segwit_active)};
    switch (fill_status) {
    case READ_STATUS_OK:
        assert(expected_block);
        assert(expected_block_mutated && !*expected_block_mutated);
        assert(expected_block->GetHash() == reconstructed_block.GetHash());
        assert(expected_block->vtx.size() == reconstructed_block.vtx.size());
        for (size_t i = 0; i < expected_block->vtx.size(); ++i) {
            assert(*expected_block->vtx[i] == *reconstructed_block.vtx[i]);
            assert(!pdb.IsTxAvailable(i));
        }
        break;
    case READ_STATUS_FAILED:
        assert(expected_block_mutated && *expected_block_mutated);
        break;
    case READ_STATUS_INVALID:
        break;
    }

    if (fill_status != READ_STATUS_INVALID) {
        CBlock unused;
        assert(pdb.FillBlock(unused, {}, segwit_active) == READ_STATUS_INVALID);
    }
}
