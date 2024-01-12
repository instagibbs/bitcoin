// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mempool_args.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {
const BasicTestingSetup* g_setup;
} // namespace

void initialize_rbf()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(rbf, .init = initialize_rbf)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
    if (!mtx) {
        return;
    }

    CTxMemPool pool{MemPoolOptionsForTest(g_setup->m_node)};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        const std::optional<CMutableTransaction> another_mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
        if (!another_mtx) {
            break;
        }
        const CTransaction another_tx{*another_mtx};
        if (fuzzed_data_provider.ConsumeBool() && !mtx->vin.empty()) {
            mtx->vin[0].prevout = COutPoint{another_tx.GetHash(), 0};
        }
        LOCK2(cs_main, pool.cs);
        pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, another_tx));
    }
    const CTransaction tx{*mtx};
    if (fuzzed_data_provider.ConsumeBool()) {
        LOCK2(cs_main, pool.cs);
        pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, tx));
    }
    {
        LOCK(pool.cs);
        (void)IsRBFOptIn(tx, pool);
    }
}

void CheckDiagramConcave(std::vector<FeeFrac>& diagram)
{
    // Diagrams are in monotonically-decreasing feerate order.
    FeeFrac last_chunk = diagram.front();
    for (size_t i = 1; i<diagram.size(); ++i) {
        FeeFrac next_chunk = diagram[i] - diagram[i-1];
        assert(next_chunk <= last_chunk);
        last_chunk = next_chunk;
    }
}

FUZZ_TARGET(package_rbf, .init = initialize_rbf)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
    if (!mtx) return;

    CTxMemPool pool{MemPoolOptionsForTest(g_setup->m_node)};

    // Add a bunch of parent-child pairs to the mempool, and remember them.
    std::vector<CTransaction> txs;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        const std::optional<CMutableTransaction> parent = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
        if (!parent) {
            continue;
        }
        txs.emplace_back(*parent);
        LOCK2(cs_main, pool.cs);
        pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, txs.back()));
        if (fuzzed_data_provider.ConsumeBool() && !mtx->vin.empty()) {
            mtx->vin[0].prevout = COutPoint{txs.back().GetHash(), 0};
        }
        txs.emplace_back(*mtx);
        pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, txs.back()));
    }
    LOCK(pool.cs);

    // Pick some transactions at random to be the direct conflicts
    CTxMemPool::setEntries direct_conflicts;
    for (auto& tx : txs) {
        if (fuzzed_data_provider.ConsumeBool()) {
            direct_conflicts.insert(*pool.GetIter(tx.GetHash()));
        }
    }

    // Calculate all conflicts:
    CTxMemPool::setEntries all_conflicts;
    for (auto& txiter : direct_conflicts) {
        pool.CalculateDescendants(txiter, all_conflicts);
    }

    // Calculate the feerate diagrams for a replacement.
    std::vector<FeeFrac> old_diagram, new_diagram;
    CAmount replacement_fees = ConsumeMoney(fuzzed_data_provider);
    int64_t replacement_vsize = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(1, 1000000);
    auto err_string{pool.CalculateFeerateDiagramsForRBF(replacement_fees, replacement_vsize, direct_conflicts, all_conflicts, old_diagram, new_diagram)};

    if (!err_string.has_value()) {
        // Sanity checks on the diagrams.

        // Diagrams start at 0.
        assert(old_diagram.front().size == 0);
        assert(old_diagram.front().fee == 0);
        assert(new_diagram.front().size == 0);
        assert(new_diagram.front().fee == 0);

        CheckDiagramConcave(old_diagram);
        CheckDiagramConcave(new_diagram);

        CAmount replaced_fee{0};
        CAmount replaced_size{0};
        for (auto txiter : all_conflicts) {
            replaced_fee += txiter->GetModifiedFee();
            replaced_size += txiter->GetTxSize();
        }
        // The total fee of the new diagram should be the total fee of the old
        // diagram - replaced_fee + replacement_fees
        assert(old_diagram.back().fee - replaced_fee + replacement_fees == new_diagram.back().fee);
        assert(old_diagram.back().size - replaced_size + replacement_vsize == new_diagram.back().size);
    }

    // If internals report error, wrapper should too
    auto err_tuple{ImprovesFeerateDiagram(pool, direct_conflicts, all_conflicts, replacement_fees, replacement_vsize)};
    if (err_string.has_value()) assert(err_tuple.has_value());
}
