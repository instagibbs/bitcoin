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
#include <vector>

namespace {
const TestingSetup* g_setup;
} // namespace

void initialize_pdb()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

struct FuzzedPartiallyDownloadedBlock : PartiallyDownloadedBlock {
    using PartiallyDownloadedBlock::PartiallyDownloadedBlock;

    size_t GetPrefilledCount() const { return prefilled_count; }
    size_t GetMempoolCount() const { return mempool_count; }
    size_t GetExtraCount() const { return extra_count; }
};

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

    CBlockHeaderAndShortTxIDs cmpctblock{*block, fuzzed_data_provider.ConsumeIntegral<uint64_t>()};

    bilingual_str error;
    CTxMemPool pool{MemPoolOptionsForTest(g_setup->m_node), error};
    Assert(error.empty());
    FuzzedPartiallyDownloadedBlock pdb{&pool};

    // Set of available transactions (mempool or extra_txn)
    std::set<uint16_t> available;
    // The coinbase is always available
    available.insert(0);

    std::vector<std::pair<Wtxid, CTransactionRef>> extra_txn;
    // Indices whose slot will be filled from the mempool or extra_txn, and can
    // therefore be targeted by a short ID collision.
    std::vector<size_t> collidable;
    size_t mempool_adds{0};
    size_t extra_adds{0};
    for (size_t i = 1; i < block->vtx.size(); ++i) {
        auto tx{block->vtx[i]};

        bool add_to_extra_txn{fuzzed_data_provider.ConsumeBool()};
        bool add_to_mempool{fuzzed_data_provider.ConsumeBool()};
        bool add_collision{fuzzed_data_provider.ConsumeBool()};

        if (add_to_extra_txn) {
            extra_txn.emplace_back(tx->GetWitnessHash(), tx);
            if (available.insert(i).second) collidable.push_back(i);
            extra_adds++;
        }

        if (add_to_mempool && !pool.exists(tx->GetHash())) {
            LOCK2(cs_main, pool.cs);
            TryAddToMempool(pool, ConsumeTxMemPoolEntry(fuzzed_data_provider, *tx));
            // The addition may fail policy limits, so only treat the slot as
            // occupied if the transaction actually made it into the pool.
            if (pool.exists(tx->GetHash())) {
                if (available.insert(i).second) collidable.push_back(i);
                mempool_adds++;
            }
        }

        if (add_collision && !collidable.empty()) {
            // Pair an occupied slot's wtxid with a different transaction, so
            // that InitData sees a short ID collision instead of filling the
            // slot. Occupied slots stay occupied or become unavailable, keeping
            // the available/reconstruction checks below valid.
            const size_t target{collidable[fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, collidable.size() - 1)]};
            auto foreign_mtx{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS)};
            CTransactionRef foreign_tx{foreign_mtx ? MakeTransactionRef(std::move(*foreign_mtx)) : block->vtx[0]};
            extra_txn.emplace_back(block->vtx[target]->GetWitnessHash(), foreign_tx);
        }
    }

    auto init_status{pdb.InitData(cmpctblock, extra_txn)};

    std::vector<CTransactionRef> missing;
    // Whether we skipped a transaction that should be included in `missing`.
    // FillBlock should never return READ_STATUS_OK if that is the case.
    bool skipped_missing{false};
    size_t available_count{0};
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
        available_count += pdb.IsTxAvailable(i);

        bool skip{fuzzed_data_provider.ConsumeBool()};
        if (!pdb.IsTxAvailable(i) && !skip) {
            missing.push_back(block->vtx[i]);
        }

        skipped_missing |= (!pdb.IsTxAvailable(i) && skip);
    }

    if (init_status == READ_STATUS_OK) {
        // Every available transaction is accounted to exactly one source, and
        // collisions decrement the counter their slot was filled from.
        assert(pdb.GetPrefilledCount() + pdb.GetMempoolCount() + pdb.GetExtraCount() == available_count);
        assert(pdb.GetMempoolCount() <= mempool_adds);
        assert(pdb.GetExtraCount() <= extra_adds);
    }

    bool segwit_active{fuzzed_data_provider.ConsumeBool()};

    // Mock IsBlockMutated
    bool fail_block_mutated{fuzzed_data_provider.ConsumeBool()};
    pdb.m_check_block_mutated_mock = FuzzedIsBlockMutated(fail_block_mutated);

    CBlock reconstructed_block;
    auto fill_status{pdb.FillBlock(reconstructed_block, missing, segwit_active)};
    switch (fill_status) {
    case READ_STATUS_OK:
        assert(!skipped_missing);
        assert(!fail_block_mutated);
        assert(block->GetHash() == reconstructed_block.GetHash());
        break;
    case READ_STATUS_FAILED:
        assert(fail_block_mutated);
        break;
    case READ_STATUS_INVALID:
        break;
    }
}
