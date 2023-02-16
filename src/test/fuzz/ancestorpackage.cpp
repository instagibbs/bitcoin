#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>

#include <policy/ancestor_packages.h>

#include <set>
#include <vector>

namespace {
FUZZ_TARGET(ancestorpackage)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    std::vector<CTransactionRef> txns_in;
    // Avoid repeat coins, as they may cause transactions to conflict
    std::set<COutPoint> available_coins;
    for (auto i{0}; i < 100; ++i) {
        if (auto mtx{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider)}) {
            available_coins.insert(COutPoint{MakeTransactionRef(*mtx)->GetHash(), fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, 10)});
        }
    }
    // Create up to 50 transactions with variable inputs and outputs.
    LIMITED_WHILE(!available_coins.empty() && fuzzed_data_provider.ConsumeBool(), 50)
    {
        CMutableTransaction mtx = CMutableTransaction();
        const size_t num_inputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, available_coins.size());
        const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 50);
        for (size_t n{0}; n < num_inputs; ++n) {
            auto prevout = available_coins.begin();
            mtx.vin.push_back(CTxIn(*prevout, CScript()));
            available_coins.erase(prevout);
        }
        for (uint32_t n{0}; n < num_outputs; ++n) {
            mtx.vout.push_back(CTxOut(100, P2WSH_OP_TRUE));
        }
        CTransactionRef tx = MakeTransactionRef(mtx);

        if (txns_in.empty()) {
            txns_in.emplace_back(tx);
        } else {
            // Place tx in a random spot in the vector, swapping the existing tx at that index to the
            // back, so the package is not necessarily sorted.
            const size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, txns_in.size() - 1);
            txns_in.push_back(txns_in.at(index));
            txns_in.at(index) = tx;
        }

        // Make outputs available to spend
        for (uint32_t n{0}; n < num_outputs; ++n) {
            COutPoint new_coin{tx->GetHash(), n};
            if (fuzzed_data_provider.ConsumeBool()) {
                available_coins.insert(new_coin);
            }
        }
    }

    // AncestorPackage may need to topologically sort txns_in. Find bugs in topological sort, Skip,
    // and SkipWithDescendants.
    AncestorPackage packageified(txns_in);
    Assert(IsSorted(packageified.Txns()));
    if (packageified.IsAncestorPackage()) {
        // Optionally Skip() (submit to mempool) the first n transactions. These must be at the
        // beginning of the package as it doesn't make sense to submit a transaction without
        // submitting all of its ancestors too. The ith transaction is not necessarily an ancestor
        // of the i+1th transaction, but just skip 1...n to keep things simple.
        // For the rest of the transactions, optionally call SkipWithDescendants() (missing inputs).
        bool skipping = true;
        for (const auto& tx : packageified.Txns()) {
            if (skipping) {
                packageified.Skip(tx);
                if (fuzzed_data_provider.ConsumeBool()) {
                    skipping = false;
                }
            } else {
                // Not skipping anymore. Maybe do a SkipWithDescendants().
                if (fuzzed_data_provider.ConsumeBool()) {
                    packageified.SkipWithDescendants(tx);
                }
            }
        }
        Assert(IsSorted(packageified.FilteredTxns()));
        for (const auto& tx : packageified.FilteredTxns()) {
            assert(IsSorted(*packageified.FilteredAncestorSet(tx)));
        }
    }
}
} // namespace
