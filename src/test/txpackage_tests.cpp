// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h>
#include <policy/ancestor_packages.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txpackage_tests)
// A fee amount that is above 1sat/vB but below 5sat/vB for most transactions created within these
// unit tests.
static const CAmount low_fee_amt{200};

// Create placeholder transactions that have no meaning.
inline CTransactionRef create_placeholder_tx(size_t num_inputs, size_t num_outputs)
{
    CMutableTransaction mtx = CMutableTransaction();
    mtx.vin.resize(num_inputs);
    mtx.vout.resize(num_outputs);
    auto random_script = CScript() << ToByteVector(InsecureRand256()) << ToByteVector(InsecureRand256());
    for (size_t i{0}; i < num_inputs; ++i) {
        mtx.vin[i].prevout.hash = InsecureRand256();
        mtx.vin[i].prevout.n = 0;
        mtx.vin[i].scriptSig = random_script;
    }
    for (size_t o{0}; o < num_outputs; ++o) {
        mtx.vout[o].nValue = 1 * CENT;
        mtx.vout[o].scriptPubKey = random_script;
    }
    return MakeTransactionRef(mtx);
}
static inline CTransactionRef make_tx(const std::vector<COutPoint>& inputs, const std::vector<CAmount>& output_amounts)
{
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(output_amounts.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout = inputs[i];
    }
    for (size_t o = 0; o < output_amounts.size(); ++o) {
        tx.vout[o].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        tx.vout[o].nValue = output_amounts.at(o);
    }
    return MakeTransactionRef(tx);
}

// Context-free check that a package only contains a tx (the last tx in the package) with its
// ancestors. Not all of the tx's ancestors need to be present.
bool IsAncestorPackage(const Package& package)
{
    if (package.empty()) return false;
    if (!IsSorted(package)) return false;
    if (!IsConsistent(package)) return false;
    const auto& dependent = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> dependency_txids;
    for (auto it = package.rbegin(); it != package.rend(); ++it) {
        const auto& tx = *it;
        // Each transaction must be a dependency of the last transaction.
        if (tx->GetWitnessHash() != dependent->GetWitnessHash() &&
            dependency_txids.count(tx->GetHash()) == 0) {
            return false;
        }
        // Add each transaction's dependencies to allow transactions which are ancestors but not
        // necessarily direct parents of the last transaction.
        std::transform(tx->vin.cbegin(), tx->vin.cend(),
                       std::inserter(dependency_txids, dependency_txids.end()),
                       [](const auto& input) { return input.prevout.hash; });
    }
    return true;
}
bool PackageSorted(const Package& package_to_check, const Package& sorted)
{
    if (package_to_check.size() != sorted.size()) return false;
    for (size_t i{0}; i < sorted.size(); ++i) {
        if (package_to_check.at(i) != sorted.at(i)) return false;
    }
    return true;
}

BOOST_FIXTURE_TEST_CASE(package_sanitization_tests, TestChain100Setup)
{
    // Packages can't have more than 25 transactions.
    Package package_too_many;
    package_too_many.reserve(MAX_PACKAGE_COUNT + 1);
    for (size_t i{0}; i < MAX_PACKAGE_COUNT + 1; ++i) {
        package_too_many.emplace_back(create_placeholder_tx(1, 1));
    }
    PackageValidationState state_too_many;
    BOOST_CHECK(!IsPackageWellFormed(package_too_many, state_too_many, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_many.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_many.GetRejectReason(), "package-too-many-transactions");

    // Packages can't have a total weight of more than 404'000WU.
    CTransactionRef large_ptx = create_placeholder_tx(150, 150);
    Package package_too_large;
    auto size_large = GetTransactionWeight(*large_ptx);
    size_t total_weight{0};
    while (total_weight <= MAX_PACKAGE_WEIGHT) {
        package_too_large.push_back(large_ptx);
        total_weight += size_large;
    }
    BOOST_CHECK(package_too_large.size() <= MAX_PACKAGE_COUNT);
    PackageValidationState state_too_large;
    BOOST_CHECK(!IsPackageWellFormed(package_too_large, state_too_large, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_large.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_large.GetRejectReason(), "package-too-large");

    // Packages can't contain transactions with the same txid.
    Package package_duplicate_txids_empty;
    for (auto i{0}; i < 3; ++i) {
        CMutableTransaction empty_tx;
        package_duplicate_txids_empty.emplace_back(MakeTransactionRef(empty_tx));
    }
    PackageValidationState state_duplicates;
    BOOST_CHECK(!IsPackageWellFormed(package_duplicate_txids_empty, state_duplicates, /*require_sorted=*/false));
    BOOST_CHECK_EQUAL(state_duplicates.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_duplicates.GetRejectReason(), "package-contains-duplicates");
}
BOOST_FIXTURE_TEST_CASE(ancestorpackage, TestChain100Setup)
{
    CKey placeholder_key;
    placeholder_key.MakeNewKey(true);
    CScript spk = GetScriptForDestination(PKHash(placeholder_key.GetPubKey()));
    FastRandomContext det_rand{true};
    // Basic chain of 25 transactions
    {
        Package package;
        CTransactionRef last_tx = m_coinbase_txns[0];
        CKey signing_key = coinbaseKey;
        for (int i{0}; i < 24; ++i) {
            auto tx = MakeTransactionRef(CreateValidMempoolTransaction(last_tx, 0, 0, signing_key, spk, CAmount((49-i) * COIN), false));
            package.emplace_back(tx);
            last_tx = tx;
            if (i == 0) signing_key = placeholder_key;
        }
        BOOST_CHECK(IsAncestorPackage(package));

        Package package_copy = package;
        Shuffle(package_copy.begin(), package_copy.end(), det_rand);
        AncestorPackage packageified(package_copy);
        BOOST_CHECK(IsAncestorPackage(packageified.Txns()));
        for (auto i{0}; i < 24; ++i) {
            BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(package[i])->size(), i + 1);
            BOOST_CHECK(IsAncestorPackage(*packageified.FilteredAncestorSet(package[i])));
        }
        for (auto i{0}; i < 10; ++i) packageified.Skip(package[i]);
        packageified.SkipWithDescendants(package[20]);
        for (auto i{11}; i < 20; ++i) {
            const auto& tx = package[i];
            BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(tx)->size(), i - 9);
            BOOST_CHECK(IsAncestorPackage(*packageified.FilteredAncestorSet(tx)));
        }
        for (auto i{20}; i < 24; ++i) {
            BOOST_CHECK(!packageified.FilteredAncestorSet(package[i]));
        }
    }
    // 99 Parents and 1 Child
    {
        Package package;
        CMutableTransaction child;
        for (int parent_idx{0}; parent_idx < 99; ++parent_idx) {
            auto parent = MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[parent_idx + 1],
                                             0, 0, coinbaseKey, spk, CAmount(49 * COIN), false));
            package.emplace_back(parent);
            child.vin.push_back(CTxIn(COutPoint(parent->GetHash(), 0)));
        }
        child.vout.push_back(CTxOut(49 * COIN * 99, spk));
        package.push_back(MakeTransactionRef(child));

        Package package_copy(package);
        Shuffle(package_copy.begin(), package_copy.end(), det_rand);
        AncestorPackage packageified(package_copy);
        BOOST_CHECK(IsAncestorPackage(packageified.Txns()));
        // Note that AncestorPackage will sort the package so that parents are before the child, but
        // this does not necessarily mean that the ith parent in packageified matches the ith parent
        // in package.
        for (auto i{0}; i < 99; ++i) {
            BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(package[i])->size(), 1);
            BOOST_CHECK(IsAncestorPackage(*packageified.FilteredAncestorSet(package[i])));
            if (i < 50) packageified.Skip(package[i]);
        }
        // After excluding 50 of the parents, the child's ancestor set has size 50.
        BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(package.back())->size(), 50);
        BOOST_CHECK(IsAncestorPackage(*packageified.FilteredAncestorSet(package.back())));
        packageified.SkipWithDescendants(package[75]);
        for (auto i{50}; i < 99; ++i) {
            if (i == 75) {
                BOOST_CHECK(!packageified.FilteredAncestorSet(package[i]));
            } else {
                BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(package[i])->size(), 1);
            }
        }
        BOOST_CHECK(!packageified.FilteredAncestorSet(package.back()));
    }

    // Heavily inter-connected set of 50 transactions
    LOCK2(cs_main, m_node.mempool->cs);
    auto transactions{PopulateMempool(det_rand, /*num_transactions=*/50, /*submit=*/true)};
    Shuffle(transactions.begin(), transactions.end(), det_rand);
    AncestorPackage packageified{transactions};
    const auto sorted_transactions{packageified.Txns()};
    BOOST_CHECK(IsSorted(sorted_transactions));
    for (const auto& tx : sorted_transactions) {
        const auto packageified_ancestors{packageified.FilteredAncestorSet(tx)};
        BOOST_CHECK(IsAncestorPackage(*packageified_ancestors));
        auto mempool_ancestors{m_node.mempool->CalculateMemPoolAncestors(*m_node.mempool->GetIter(tx->GetHash()).value(),
                               CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};
        // Add 1 because CMPA doesn't include the tx itself in its ancestor set.
        BOOST_CHECK_EQUAL(mempool_ancestors->size() + 1, packageified_ancestors->size());
        std::set<uint256> packageified_ancestors_wtxids;
        for (const auto& tx : packageified_ancestors.value()) packageified_ancestors_wtxids.insert(tx->GetWitnessHash());
        for (const auto& mempool_iter : *mempool_ancestors) {
            BOOST_CHECK(packageified_ancestors_wtxids.count(mempool_iter->GetTx().GetWitnessHash()) > 0);
        }
    }
    // Skip the 20th transaction. All of its descendants should have 1 fewer tx in their ancestor sets.
    const auto& tx_20{sorted_transactions[20]};
    CTxMemPool::setEntries descendants_20;
    m_node.mempool->CalculateDescendants(m_node.mempool->GetIter(tx_20->GetHash()).value(), descendants_20);
    packageified.Skip(tx_20);
    for (const auto& desc_iter : descendants_20) {
        BOOST_CHECK_EQUAL(packageified.FilteredAncestorSet(m_node.mempool->info(GenTxid::Txid(desc_iter->GetTx().GetHash())).tx)->size(),
                          desc_iter->GetCountWithAncestors() - 1);
    }
    // SkipWithDescendants the 40th transaction. FilteredAncestorSet() for all of its descendants should return std::nullopt.
    const auto& tx_40{sorted_transactions[40]};
    CTxMemPool::setEntries descendants_40;
    m_node.mempool->CalculateDescendants(m_node.mempool->GetIter(tx_40->GetHash()).value(), descendants_40);
    packageified.SkipWithDescendants(tx_40);
    for (const auto& desc_iter : descendants_40) {
        BOOST_CHECK(!packageified.FilteredAncestorSet(m_node.mempool->info(GenTxid::Txid(desc_iter->GetTx().GetHash())).tx));
    }

    // Linearization tests.
    const CAmount coinbase_amount{50 * COIN};
    const CAmount low_fee_amt{500};
    const CAmount double_low_fee_amt{low_fee_amt * 2};
    const CAmount med_fee_amt{low_fee_amt * 10};
    const CAmount high_fee_amt{low_fee_amt * 100};
    {
        // 24 parents (each of different feerate) and 1 fee-bumping child.
        Package package;
        CMutableTransaction child;
        const auto num_parents{24};
        // The first tx pays 2400sat in fees. Each parent pays 100sat less than the previous one.
        for (int parent_idx{0}; parent_idx < num_parents; ++parent_idx) {
            auto parent = MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[parent_idx + 1],
                                             0, 0, coinbaseKey, spk, CAmount(coinbase_amount - (num_parents - parent_idx) * 100), false));
            package.emplace_back(parent);
            child.vin.push_back(CTxIn(COutPoint(parent->GetHash(), 0)));
        }
        child.vout.push_back(CTxOut(coinbase_amount * num_parents - CENT, spk));
        package.push_back(MakeTransactionRef(child));

        Package package_copy = package;
        Shuffle(package_copy.begin(), package_copy.end(), det_rand);
        AncestorPackage packageified(package_copy);
        // Before child and vsize information for all non-skipped transactions are added, we cannot linearize.
        BOOST_CHECK(!packageified.LinearizeWithFees());
        // The first tx pays 2400sat in fees. Each parent pays 100sat less than the previous one.
        for (int parent_idx{0}; parent_idx < num_parents; ++parent_idx) {
            packageified.AddFeeAndVsize(package.at(parent_idx)->GetHash(), CAmount((num_parents - parent_idx) * 100),
                                        GetVirtualTransactionSize(*package.at(parent_idx)));
        }
        BOOST_CHECK(!packageified.LinearizeWithFees());
        // Total parent fees is 100sat * (1 + ... + 24) = 100sat * (25 * 24 / 2) = 30,000sat.
        // Child pays 1,000,000sat - 30,000sat = 970,000sat.
        packageified.AddFeeAndVsize(package.back()->GetHash(), CAmount(CENT - 100 * (num_parents + 1) * num_parents / 2),
                                    GetVirtualTransactionSize(*package.back()));
        BOOST_CHECK(packageified.LinearizeWithFees());
        const auto ancestorscore_linearized = packageified.Txns();
        // Ties should be broken by a transaction's base feerate, so the order should be identical.
        for (int idx{0}; idx < num_parents + 1; ++idx) {
            BOOST_CHECK_EQUAL(package.at(idx), ancestorscore_linearized.at(idx));
        }
    }
    {
        // 2 parents (each high feerate) and 1 low-feerate child.
        auto parent_med_feerate = make_tx({{m_coinbase_txns.at(0)->GetHash(), 0}}, {coinbase_amount - med_fee_amt});
        auto parent_high_feerate = make_tx({{m_coinbase_txns.at(1)->GetHash(), 0}}, {coinbase_amount - high_fee_amt});
        auto child = make_tx({{parent_med_feerate->GetHash(), 0}, {parent_high_feerate->GetHash(), 0}},
                             {coinbase_amount * 2 - med_fee_amt - high_fee_amt - low_fee_amt});
        AncestorPackage packageified({child, parent_med_feerate, parent_high_feerate});
        packageified.AddFeeAndVsize(parent_high_feerate->GetHash(), high_fee_amt, GetVirtualTransactionSize(*parent_high_feerate));
        packageified.AddFeeAndVsize(parent_med_feerate->GetHash(), med_fee_amt, GetVirtualTransactionSize(*parent_med_feerate));
        packageified.AddFeeAndVsize(child->GetHash(), low_fee_amt, GetVirtualTransactionSize(*child));
        BOOST_CHECK(packageified.LinearizeWithFees());
        Package package_sorted{parent_high_feerate, parent_med_feerate, child};
        BOOST_CHECK(PackageSorted(packageified.Txns(), package_sorted));
        BOOST_CHECK(PackageSorted(packageified.FilteredAncestorSet(child).value(), package_sorted));
    }
    {
        // 3 pairs of fee-bumping grandparent + parent, plus 1 low-feerate child.
        // 0 fee + high fee
        auto grandparent_zero_fee = make_tx({{m_coinbase_txns.at(0)->GetHash(), 0}}, {coinbase_amount});
        auto parent_high_feerate = make_tx({{grandparent_zero_fee->GetHash(), 0}}, {coinbase_amount - high_fee_amt});
        // double low fee + med fee
        auto grandparent_double_low_feerate = make_tx({{m_coinbase_txns.at(2)->GetHash(), 0}}, {coinbase_amount - double_low_fee_amt});
        auto parent_med_feerate = make_tx({{grandparent_double_low_feerate->GetHash(), 0}}, {coinbase_amount - double_low_fee_amt - med_fee_amt});
        // low fee + med fee
        auto grandparent_low_feerate = make_tx({{m_coinbase_txns.at(1)->GetHash(), 0}}, {coinbase_amount - low_fee_amt});
        auto parent_med_feerate_add100 = make_tx({{grandparent_low_feerate->GetHash(), 0}}, {coinbase_amount - low_fee_amt - med_fee_amt - 100});
        // child is below the cpfp package feerates
        auto child = make_tx({{parent_high_feerate->GetHash(), 0}, {parent_med_feerate_add100->GetHash(), 0}, {parent_med_feerate->GetHash(), 0}},
                             {coinbase_amount * 3 - high_fee_amt - double_low_fee_amt - med_fee_amt - low_fee_amt - med_fee_amt - low_fee_amt});
        AncestorPackage packageified7({child, parent_med_feerate, grandparent_low_feerate, grandparent_zero_fee,
                                     parent_high_feerate, parent_med_feerate_add100, grandparent_double_low_feerate});
        BOOST_CHECK(packageified7.IsAncestorPackage());
        packageified7.AddFeeAndVsize(grandparent_zero_fee->GetHash(), 0, GetVirtualTransactionSize(*grandparent_zero_fee));
        packageified7.AddFeeAndVsize(parent_high_feerate->GetHash(), high_fee_amt, GetVirtualTransactionSize(*parent_high_feerate));
        packageified7.AddFeeAndVsize(grandparent_low_feerate->GetHash(), low_fee_amt, GetVirtualTransactionSize(*grandparent_low_feerate));
        packageified7.AddFeeAndVsize(parent_med_feerate_add100->GetHash(), med_fee_amt + 100, GetVirtualTransactionSize(*parent_med_feerate_add100));
        packageified7.AddFeeAndVsize(grandparent_double_low_feerate->GetHash(), double_low_fee_amt, GetVirtualTransactionSize(*grandparent_double_low_feerate));
        packageified7.AddFeeAndVsize(parent_med_feerate->GetHash(), med_fee_amt, GetVirtualTransactionSize(*parent_med_feerate));
        packageified7.AddFeeAndVsize(child->GetHash(), low_fee_amt, GetVirtualTransactionSize(*child));

        BOOST_CHECK(packageified7.LinearizeWithFees());
        Package package_sorted{grandparent_zero_fee, parent_high_feerate, grandparent_double_low_feerate, parent_med_feerate,
                               grandparent_low_feerate, parent_med_feerate_add100, child};
        BOOST_CHECK(PackageSorted(packageified7.Txns(), package_sorted));
        BOOST_CHECK(PackageSorted(packageified7.FilteredAncestorSet(child).value(), package_sorted));

        // Packageify 1 grandparent_low_feerate, the parents, and the child.
        // If grandparent_low_feerate is included, parent_med_feerate comes before
        // parent_med_feerate_add100.
        AncestorPackage packageified5({child, parent_med_feerate, parent_med_feerate_add100, grandparent_low_feerate, parent_high_feerate});
        packageified5.AddFeeAndVsize(parent_high_feerate->GetHash(), high_fee_amt, GetVirtualTransactionSize(*parent_high_feerate));
        packageified5.AddFeeAndVsize(parent_med_feerate_add100->GetHash(), med_fee_amt + 1000, GetVirtualTransactionSize(*parent_med_feerate_add100));
        packageified5.AddFeeAndVsize(parent_med_feerate->GetHash(), med_fee_amt, GetVirtualTransactionSize(*parent_med_feerate));
        packageified5.AddFeeAndVsize(child->GetHash(), low_fee_amt, GetVirtualTransactionSize(*child));
        BOOST_CHECK(!packageified5.LinearizeWithFees());

        // If grandparent_low_feerate is skipped, parent_med_feerate_add100 comes before parent_med_feerate.
        packageified5.Skip(grandparent_low_feerate);
        BOOST_CHECK(packageified5.LinearizeWithFees());

        Package package5_sorted{grandparent_low_feerate, parent_high_feerate, parent_med_feerate_add100, parent_med_feerate, child};
        BOOST_CHECK(PackageSorted(packageified5.Txns(), package5_sorted));

        Package package_sorted_with_skip{parent_high_feerate, parent_med_feerate_add100, parent_med_feerate, child};
        BOOST_CHECK(PackageSorted(packageified5.FilteredAncestorSet(child).value(), package_sorted_with_skip));
        BOOST_CHECK(PackageSorted(packageified5.FilteredTxns(), package_sorted_with_skip));
    }
}

BOOST_FIXTURE_TEST_CASE(package_validation_tests, TestChain100Setup)
{
    LOCK(cs_main);
    unsigned int initialPoolSize = m_node.mempool->size();

    // Parent and Child Package
    CKey parent_key;
    parent_key.MakeNewKey(true);
    CScript parent_locking_script = GetScriptForDestination(PKHash(parent_key.GetPubKey()));
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

    CKey child_key;
    child_key.MakeNewKey(true);
    CScript child_locking_script = GetScriptForDestination(PKHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(48 * COIN), /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    const auto result_parent_child = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, {tx_parent, tx_child}, /*test_accept=*/true);
    BOOST_CHECK_MESSAGE(result_parent_child.m_state.IsValid(),
                        "Package validation unexpectedly failed: " << result_parent_child.m_state.GetRejectReason());
    BOOST_CHECK(result_parent_child.m_tx_results.size() == 2);
    auto it_parent = result_parent_child.m_tx_results.find(tx_parent->GetWitnessHash());
    auto it_child = result_parent_child.m_tx_results.find(tx_child->GetWitnessHash());
    BOOST_CHECK(it_parent != result_parent_child.m_tx_results.end());
    BOOST_CHECK_MESSAGE(it_parent->second.m_state.IsValid(),
                        "Package validation unexpectedly failed: " << it_parent->second.m_state.GetRejectReason());
    BOOST_CHECK(it_parent->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_parent)) == COIN);
    BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
    BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());
    BOOST_CHECK(it_child != result_parent_child.m_tx_results.end());
    BOOST_CHECK_MESSAGE(it_child->second.m_state.IsValid(),
                        "Package validation unexpectedly failed: " << it_child->second.m_state.GetRejectReason());
    BOOST_CHECK(it_child->second.m_effective_feerate.value().GetFee(GetVirtualTransactionSize(*tx_child)) == COIN);
    BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
    BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());

    // A single, giant transaction submitted through ProcessNewPackage fails on single tx policy.
    CTransactionRef giant_ptx = create_placeholder_tx(999, 999);
    BOOST_CHECK(GetVirtualTransactionSize(*giant_ptx) > DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * 1000);
    auto result_single_large = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, {giant_ptx}, /*test_accept=*/true);
    BOOST_CHECK(result_single_large.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result_single_large.m_state.GetResult(), PackageValidationResult::PCKG_TX);
    BOOST_CHECK_EQUAL(result_single_large.m_state.GetRejectReason(), "transaction failed");
    BOOST_CHECK(result_single_large.m_tx_results.size() == 1);
    auto it_giant_tx = result_single_large.m_tx_results.find(giant_ptx->GetWitnessHash());
    BOOST_CHECK(it_giant_tx != result_single_large.m_tx_results.end());
    BOOST_CHECK_EQUAL(it_giant_tx->second.m_state.GetRejectReason(), "tx-size");

    // Check that mempool size hasn't changed.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);
}

BOOST_FIXTURE_TEST_CASE(noncontextual_package_tests, TestChain100Setup)
{
    // The signatures won't be verified so we can just use a placeholder
    CKey placeholder_key;
    placeholder_key.MakeNewKey(true);
    CScript spk = GetScriptForDestination(PKHash(placeholder_key.GetPubKey()));
    CKey placeholder_key_2;
    placeholder_key_2.MakeNewKey(true);
    CScript spk2 = GetScriptForDestination(PKHash(placeholder_key_2.GetPubKey()));

    // Parent and Child Package
    {
        auto mtx_parent = CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 0, coinbaseKey, spk,
                                                        CAmount(49 * COIN), /*submit=*/false);
        CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

        auto mtx_child = CreateValidMempoolTransaction(tx_parent, 0, 101, placeholder_key, spk2,
                                                       CAmount(48 * COIN), /*submit=*/false);
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);

        PackageValidationState state;
        BOOST_CHECK(IsPackageWellFormed({tx_parent, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK(!IsPackageWellFormed({tx_child, tx_parent}, state, /*require_sorted=*/true));
        BOOST_CHECK_EQUAL(state.GetResult(), PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "package-not-sorted");
    }

    // 24 Parents and 1 Child
    {
        Package package;
        CMutableTransaction child;
        for (int i{0}; i < 24; ++i) {
            auto parent = MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[i + 1],
                                             0, 0, coinbaseKey, spk, CAmount(48 * COIN), false));
            package.emplace_back(parent);
            child.vin.push_back(CTxIn(COutPoint(parent->GetHash(), 0)));
        }
        child.vout.push_back(CTxOut(47 * COIN, spk2));

        // The parents can be in any order.
        FastRandomContext rng;
        Shuffle(package.begin(), package.end(), rng);
        package.push_back(MakeTransactionRef(child));

        PackageValidationState state;
        BOOST_CHECK(IsPackageWellFormed(package, state, /*require_sorted=*/true));
    }

    // 2 Parents and 1 Child where one parent depends on the other.
    {
        CMutableTransaction mtx_parent;
        mtx_parent.vin.push_back(CTxIn(COutPoint(m_coinbase_txns[0]->GetHash(), 0)));
        mtx_parent.vout.push_back(CTxOut(20 * COIN, spk));
        mtx_parent.vout.push_back(CTxOut(20 * COIN, spk2));
        CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);

        CMutableTransaction mtx_parent_also_child;
        mtx_parent_also_child.vin.push_back(CTxIn(COutPoint(tx_parent->GetHash(), 0)));
        mtx_parent_also_child.vout.push_back(CTxOut(20 * COIN, spk));
        CTransactionRef tx_parent_also_child = MakeTransactionRef(mtx_parent_also_child);

        CMutableTransaction mtx_child;
        mtx_child.vin.push_back(CTxIn(COutPoint(tx_parent->GetHash(), 1)));
        mtx_child.vin.push_back(CTxIn(COutPoint(tx_parent_also_child->GetHash(), 0)));
        mtx_child.vout.push_back(CTxOut(39 * COIN, spk));
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);

        PackageValidationState state;
        BOOST_CHECK(!IsSorted({tx_parent_also_child, tx_parent, tx_child}));
        BOOST_CHECK(IsPackageWellFormed({tx_parent, tx_parent_also_child, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK(!IsPackageWellFormed({tx_parent_also_child, tx_parent, tx_child}, state, /*require_sorted=*/true));
        BOOST_CHECK_EQUAL(state.GetResult(), PackageValidationResult::PCKG_POLICY);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "package-not-sorted");
    }
}

BOOST_FIXTURE_TEST_CASE(package_submission_tests, TestChain100Setup)
{
    LOCK(cs_main);
    unsigned int expected_pool_size = m_node.mempool->size();
    CKey parent_key;
    parent_key.MakeNewKey(true);
    CScript parent_locking_script = GetScriptForDestination(PKHash(parent_key.GetPubKey()));

    // Unrelated transactions are not allowed in package submission.
    Package package_unrelated;
    for (size_t i{0}; i < 10; ++i) {
        auto mtx = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[i + 25], /*input_vout=*/0,
                                                 /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                 /*output_destination=*/parent_locking_script,
                                                 /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
        package_unrelated.emplace_back(MakeTransactionRef(mtx));
    }
    auto result_unrelated_submit = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                     package_unrelated, /*test_accept=*/false);
    BOOST_CHECK(result_unrelated_submit.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result_unrelated_submit.m_state.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(result_unrelated_submit.m_state.GetRejectReason(), "not-ancestor-package");
    BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

    // Parent and Child (and Grandchild) Package
    Package package_parent_child;
    Package package_3gen;
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_locking_script,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    package_parent_child.push_back(tx_parent);
    package_3gen.push_back(tx_parent);

    CKey child_key;
    child_key.MakeNewKey(true);
    CScript child_locking_script = GetScriptForDestination(PKHash(child_key.GetPubKey()));
    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/parent_key,
                                                   /*output_destination=*/child_locking_script,
                                                   /*output_amount=*/CAmount(48 * COIN), /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_parent_child.push_back(tx_child);
    package_3gen.push_back(tx_child);

    CKey grandchild_key;
    grandchild_key.MakeNewKey(true);
    CScript grandchild_locking_script = GetScriptForDestination(PKHash(grandchild_key.GetPubKey()));
    auto mtx_grandchild = CreateValidMempoolTransaction(/*input_transaction=*/tx_child, /*input_vout=*/0,
                                                       /*input_height=*/101, /*input_signing_key=*/child_key,
                                                       /*output_destination=*/grandchild_locking_script,
                                                       /*output_amount=*/CAmount(47 * COIN), /*submit=*/false);
    CTransactionRef tx_grandchild = MakeTransactionRef(mtx_grandchild);
    package_3gen.push_back(tx_grandchild);

    // Parent and child package where transactions are invalid for reasons other than fee and
    // missing inputs, so the package validation isn't expected to happen.
    {
        CScriptWitness bad_witness;
        bad_witness.stack.push_back(std::vector<unsigned char>(1));
        CMutableTransaction mtx_parent_invalid{mtx_parent};
        mtx_parent_invalid.vin[0].scriptWitness = bad_witness;
        CTransactionRef tx_parent_invalid = MakeTransactionRef(mtx_parent_invalid);
        auto result_quit_early = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   {tx_parent_invalid, tx_child}, /*test_accept=*/ false);
        BOOST_CHECK(result_quit_early.m_state.IsInvalid());
        BOOST_CHECK_EQUAL(result_quit_early.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK(!result_quit_early.m_tx_results.empty());
        BOOST_CHECK_EQUAL(result_quit_early.m_tx_results.size(), 2);
        auto it_parent = result_quit_early.m_tx_results.find(tx_parent_invalid->GetWitnessHash());
        auto it_child = result_quit_early.m_tx_results.find(tx_child->GetWitnessHash());
        BOOST_CHECK(it_parent != result_quit_early.m_tx_results.end());
        BOOST_CHECK(it_child != result_quit_early.m_tx_results.end());
        BOOST_CHECK_EQUAL(it_parent->second.m_state.GetResult(), TxValidationResult::TX_WITNESS_MUTATED);
        BOOST_CHECK_EQUAL(it_parent->second.m_state.GetRejectReason(), "bad-witness-nonstandard");
        BOOST_CHECK_EQUAL(it_child->second.m_state.GetResult(), TxValidationResult::TX_UNKNOWN);
        BOOST_CHECK_EQUAL(it_child->second.m_state.GetRejectReason(), "unknown-not-validated");
    }

    // Submit package parent + child + grandchild.
    {
        auto result_3gen_submit = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                    package_3gen, /*test_accept=*/false);
        expected_pool_size += 3;
        BOOST_CHECK_MESSAGE(result_3gen_submit.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << result_3gen_submit.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(result_3gen_submit.m_tx_results.size(), package_3gen.size());
        auto it_parent = result_3gen_submit.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child = result_3gen_submit.m_tx_results.find(tx_child->GetWitnessHash());
        auto it_grandchild = result_3gen_submit.m_tx_results.find(tx_grandchild->GetWitnessHash());

        BOOST_CHECK(it_parent->second.m_effective_feerate == CFeeRate(1 * COIN, GetVirtualTransactionSize(*tx_parent)));
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_parent->second.m_wtxids_fee_calculations.value().front(), tx_parent->GetWitnessHash());

        BOOST_CHECK(it_child->second.m_state.IsValid());
        BOOST_CHECK(it_child->second.m_effective_feerate == CFeeRate(1 * COIN, GetVirtualTransactionSize(*tx_child)));
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_child->second.m_wtxids_fee_calculations.value().front(), tx_child->GetWitnessHash());

        BOOST_CHECK(it_grandchild->second.m_effective_feerate == CFeeRate(1 * COIN, GetVirtualTransactionSize(*tx_grandchild)));
        BOOST_CHECK_EQUAL(it_grandchild->second.m_wtxids_fee_calculations.value().size(), 1);
        BOOST_CHECK_EQUAL(it_grandchild->second.m_wtxids_fee_calculations.value().front(), tx_grandchild->GetWitnessHash());

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_parent->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_child->GetHash())));
    }

    // Already-in-mempool transactions should be detected and de-duplicated.
    {
        const auto submit_deduped = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                      package_parent_child, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_deduped.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_deduped.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_deduped.m_tx_results.size(), package_parent_child.size());
        auto it_parent_deduped = submit_deduped.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child_deduped = submit_deduped.m_tx_results.find(tx_child->GetWitnessHash());
        BOOST_CHECK(it_parent_deduped != submit_deduped.m_tx_results.end());
        BOOST_CHECK(it_parent_deduped->second.m_state.IsValid());
        BOOST_CHECK(it_parent_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        BOOST_CHECK(it_child_deduped != submit_deduped.m_tx_results.end());
        BOOST_CHECK(it_child_deduped->second.m_state.IsValid());
        BOOST_CHECK(it_child_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_parent->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_child->GetHash())));
    }
}

// Tests for packages containing transactions that have same-txid-different-witness equivalents in
// the mempool.
BOOST_FIXTURE_TEST_CASE(package_witness_swap_tests, TestChain100Setup)
{
    // Mine blocks to mature coinbases.
    mineBlocks(5);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(cs_main);

    // Transactions with a same-txid-different-witness transaction in the mempool should be ignored,
    // and the mempool entry's wtxid returned.
    CScript witnessScript = CScript() << OP_DROP << OP_TRUE;
    CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/scriptPubKey,
                                                    /*output_amount=*/CAmount(49 * COIN), /*submit=*/false);
    CTransactionRef ptx_parent = MakeTransactionRef(mtx_parent);

    // Make two children with the same txid but different witnesses.
    CScriptWitness witness1;
    witness1.stack.push_back(std::vector<unsigned char>(1));
    witness1.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

    CScriptWitness witness2(witness1);
    witness2.stack.push_back(std::vector<unsigned char>(2));
    witness2.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

    CKey child_key;
    child_key.MakeNewKey(true);
    CScript child_locking_script = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    CMutableTransaction mtx_child1;
    mtx_child1.nVersion = 1;
    mtx_child1.vin.resize(1);
    mtx_child1.vin[0].prevout.hash = ptx_parent->GetHash();
    mtx_child1.vin[0].prevout.n = 0;
    mtx_child1.vin[0].scriptSig = CScript();
    mtx_child1.vin[0].scriptWitness = witness1;
    mtx_child1.vout.resize(1);
    mtx_child1.vout[0].nValue = CAmount(48 * COIN);
    mtx_child1.vout[0].scriptPubKey = child_locking_script;

    CMutableTransaction mtx_child2{mtx_child1};
    mtx_child2.vin[0].scriptWitness = witness2;

    CTransactionRef ptx_child1 = MakeTransactionRef(mtx_child1);
    CTransactionRef ptx_child2 = MakeTransactionRef(mtx_child2);

    // child1 and child2 have the same txid
    BOOST_CHECK_EQUAL(ptx_child1->GetHash(), ptx_child2->GetHash());
    // child1 and child2 have different wtxids
    BOOST_CHECK(ptx_child1->GetWitnessHash() != ptx_child2->GetWitnessHash());

    // Try submitting Package1{parent, child1} and Package2{parent, child2} where the children are
    // same-txid-different-witness.
    {
        const auto submit_witness1 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                       {ptx_parent, ptx_child1}, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_witness1.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_witness1.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_witness1.m_tx_results.size(), 2);
        auto it_parent1 = submit_witness1.m_tx_results.find(ptx_parent->GetWitnessHash());
        auto it_child1 = submit_witness1.m_tx_results.find(ptx_child1->GetWitnessHash());
        BOOST_CHECK(it_parent1 != submit_witness1.m_tx_results.end());
        BOOST_CHECK_MESSAGE(it_parent1->second.m_state.IsValid(),
                            "Transaction unexpectedly failed: " << it_parent1->second.m_state.GetRejectReason());
        BOOST_CHECK(it_child1 != submit_witness1.m_tx_results.end());
        BOOST_CHECK_MESSAGE(it_child1->second.m_state.IsValid(),
                            "Transaction unexpectedly failed: " << it_child1->second.m_state.GetRejectReason());

        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_parent->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_child1->GetHash())));

        // Child2 would have been validated individually.
        const auto submit_witness2 = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                       {ptx_parent, ptx_child2}, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_witness2.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_witness2.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_witness2.m_tx_results.size(), 2);
        auto it_parent2_deduped = submit_witness2.m_tx_results.find(ptx_parent->GetWitnessHash());
        auto it_child2 = submit_witness2.m_tx_results.find(ptx_child2->GetWitnessHash());
        BOOST_CHECK(it_parent2_deduped != submit_witness2.m_tx_results.end());
        BOOST_CHECK(it_parent2_deduped->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        BOOST_CHECK(it_child2 != submit_witness2.m_tx_results.end());
        BOOST_CHECK(it_child2->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
        BOOST_CHECK_EQUAL(ptx_child1->GetWitnessHash(), it_child2->second.m_other_wtxid.value());

        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_child2->GetHash())));
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Wtxid(ptx_child2->GetWitnessHash())));

        // Deduplication should work when wtxid != txid. Submit package with the already-in-mempool
        // transactions again, which should not fail.
        const auto submit_segwit_dedup = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                           {ptx_parent, ptx_child1}, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_segwit_dedup.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_segwit_dedup.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_segwit_dedup.m_tx_results.size(), 2);
        auto it_parent_dup = submit_segwit_dedup.m_tx_results.find(ptx_parent->GetWitnessHash());
        auto it_child_dup = submit_segwit_dedup.m_tx_results.find(ptx_child1->GetWitnessHash());
        BOOST_CHECK(it_parent_dup->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        BOOST_CHECK(it_child_dup->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
    }

    // Try submitting Package1{child2, grandchild} where child2 is same-txid-different-witness as
    // the in-mempool transaction, child1. Since child1 exists in the mempool and its outputs are
    // available, child2 should be ignored and grandchild should be accepted.
    //
    // This tests a potential censorship vector in which an attacker broadcasts a competing package
    // where a parent's witness is mutated. The honest package should be accepted despite the fact
    // that we don't allow witness replacement.
    CKey grandchild_key;
    grandchild_key.MakeNewKey(true);
    CScript grandchild_locking_script = GetScriptForDestination(WitnessV0KeyHash(grandchild_key.GetPubKey()));
    auto mtx_grandchild = CreateValidMempoolTransaction(/*input_transaction=*/ptx_child2, /*input_vout=*/0,
                                                        /*input_height=*/0, /*input_signing_key=*/child_key,
                                                        /*output_destination=*/grandchild_locking_script,
                                                        /*output_amount=*/CAmount(47 * COIN), /*submit=*/false);
    CTransactionRef ptx_grandchild = MakeTransactionRef(mtx_grandchild);

    // We already submitted child1 above.
    {
        const auto submit_spend_ignored = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                            {ptx_child2, ptx_grandchild}, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_spend_ignored.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_spend_ignored.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_spend_ignored.m_tx_results.size(), 2);
        auto it_child2_ignored = submit_spend_ignored.m_tx_results.find(ptx_child2->GetWitnessHash());
        auto it_grandchild = submit_spend_ignored.m_tx_results.find(ptx_grandchild->GetWitnessHash());
        BOOST_CHECK(it_child2_ignored != submit_spend_ignored.m_tx_results.end());
        BOOST_CHECK(it_child2_ignored->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
        BOOST_CHECK(it_grandchild != submit_spend_ignored.m_tx_results.end());
        BOOST_CHECK(it_grandchild->second.m_result_type == MempoolAcceptResult::ResultType::VALID);

        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_child2->GetHash())));
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Wtxid(ptx_child2->GetWitnessHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Wtxid(ptx_grandchild->GetWitnessHash())));
    }

    // A package Package{parent1, parent2, parent3, child} where the parents are a mixture of
    // identical-tx-in-mempool, same-txid-different-witness-in-mempool, and new transactions.
    Package package_mixed;

    // Give all the parents anyone-can-spend scripts so we don't have to deal with signing the child.
    CScript acs_script = CScript() << OP_TRUE;
    CScript acs_spk = GetScriptForDestination(WitnessV0ScriptHash(acs_script));
    CScriptWitness acs_witness;
    acs_witness.stack.push_back(std::vector<unsigned char>(acs_script.begin(), acs_script.end()));

    // parent1 will already be in the mempool
    auto mtx_parent1 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                     /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                     /*output_destination=*/acs_spk,
                                                     /*output_amount=*/CAmount(49 * COIN), /*submit=*/true);
    CTransactionRef ptx_parent1 = MakeTransactionRef(mtx_parent1);
    package_mixed.push_back(ptx_parent1);

    // parent2 will have a same-txid-different-witness tx already in the mempool
    CScript grandparent2_script = CScript() << OP_DROP << OP_TRUE;
    CScript grandparent2_spk = GetScriptForDestination(WitnessV0ScriptHash(grandparent2_script));
    CScriptWitness parent2_witness1;
    parent2_witness1.stack.push_back(std::vector<unsigned char>(1));
    parent2_witness1.stack.push_back(std::vector<unsigned char>(grandparent2_script.begin(), grandparent2_script.end()));
    CScriptWitness parent2_witness2;
    parent2_witness2.stack.push_back(std::vector<unsigned char>(2));
    parent2_witness2.stack.push_back(std::vector<unsigned char>(grandparent2_script.begin(), grandparent2_script.end()));

    // Create grandparent2 creating an output with multiple spending paths. Submit to mempool.
    auto mtx_grandparent2 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[2], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/grandparent2_spk,
                                                          /*output_amount=*/CAmount(49 * COIN), /*submit=*/true);
    CTransactionRef ptx_grandparent2 = MakeTransactionRef(mtx_grandparent2);

    CMutableTransaction mtx_parent2_v1;
    mtx_parent2_v1.nVersion = 1;
    mtx_parent2_v1.vin.resize(1);
    mtx_parent2_v1.vin[0].prevout.hash = ptx_grandparent2->GetHash();
    mtx_parent2_v1.vin[0].prevout.n = 0;
    mtx_parent2_v1.vin[0].scriptSig = CScript();
    mtx_parent2_v1.vin[0].scriptWitness = parent2_witness1;
    mtx_parent2_v1.vout.resize(1);
    mtx_parent2_v1.vout[0].nValue = CAmount(48 * COIN);
    mtx_parent2_v1.vout[0].scriptPubKey = acs_spk;

    CMutableTransaction mtx_parent2_v2{mtx_parent2_v1};
    mtx_parent2_v2.vin[0].scriptWitness = parent2_witness2;

    CTransactionRef ptx_parent2_v1 = MakeTransactionRef(mtx_parent2_v1);
    CTransactionRef ptx_parent2_v2 = MakeTransactionRef(mtx_parent2_v2);
    // Put parent2_v1 in the package, submit parent2_v2 to the mempool.
    const MempoolAcceptResult parent2_v2_result = m_node.chainman->ProcessTransaction(ptx_parent2_v2);
    BOOST_CHECK(parent2_v2_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    package_mixed.push_back(ptx_parent2_v1);

    // parent3 will be a new transaction. Put a low feerate to make it invalid on its own.
    auto mtx_parent3 = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                     /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                     /*output_destination=*/acs_spk,
                                                     /*output_amount=*/CAmount(50 * COIN - low_fee_amt), /*submit=*/false);
    CTransactionRef ptx_parent3 = MakeTransactionRef(mtx_parent3);
    package_mixed.push_back(ptx_parent3);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*ptx_parent3)) > low_fee_amt);
    BOOST_CHECK(m_node.mempool->m_min_relay_feerate.GetFee(GetVirtualTransactionSize(*ptx_parent3)) <= low_fee_amt);

    // child spends parent1, parent2, and parent3
    CKey mixed_grandchild_key;
    mixed_grandchild_key.MakeNewKey(true);
    CScript mixed_child_spk = GetScriptForDestination(WitnessV0KeyHash(mixed_grandchild_key.GetPubKey()));

    CMutableTransaction mtx_mixed_child;
    mtx_mixed_child.vin.push_back(CTxIn(COutPoint(ptx_parent1->GetHash(), 0)));
    mtx_mixed_child.vin.push_back(CTxIn(COutPoint(ptx_parent2_v1->GetHash(), 0)));
    mtx_mixed_child.vin.push_back(CTxIn(COutPoint(ptx_parent3->GetHash(), 0)));
    mtx_mixed_child.vin[0].scriptWitness = acs_witness;
    mtx_mixed_child.vin[1].scriptWitness = acs_witness;
    mtx_mixed_child.vin[2].scriptWitness = acs_witness;
    mtx_mixed_child.vout.push_back(CTxOut((48 + 49 + 50 - 1) * COIN, mixed_child_spk));
    CTransactionRef ptx_mixed_child = MakeTransactionRef(mtx_mixed_child);
    package_mixed.push_back(ptx_mixed_child);

    // Submit package:
    // parent1 should be ignored
    // parent2_v1 should be ignored (and v2 wtxid returned)
    // parent3 should be accepted
    // child should be accepted
    {
        const auto mixed_result = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_mixed, false);
        BOOST_CHECK_MESSAGE(mixed_result.m_state.IsValid(), mixed_result.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(mixed_result.m_tx_results.size(), package_mixed.size());
        auto it_parent1 = mixed_result.m_tx_results.find(ptx_parent1->GetWitnessHash());
        auto it_parent2 = mixed_result.m_tx_results.find(ptx_parent2_v1->GetWitnessHash());
        auto it_parent3 = mixed_result.m_tx_results.find(ptx_parent3->GetWitnessHash());
        auto it_child = mixed_result.m_tx_results.find(ptx_mixed_child->GetWitnessHash());
        BOOST_CHECK(it_parent1 != mixed_result.m_tx_results.end());
        BOOST_CHECK(it_parent2 != mixed_result.m_tx_results.end());
        BOOST_CHECK(it_parent3 != mixed_result.m_tx_results.end());
        BOOST_CHECK(it_child != mixed_result.m_tx_results.end());

        BOOST_CHECK(it_parent1->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
        BOOST_CHECK(it_parent2->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
        BOOST_CHECK(it_parent3->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK_EQUAL(ptx_parent2_v2->GetWitnessHash(), it_parent2->second.m_other_wtxid.value());

        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_parent1->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_parent2_v1->GetHash())));
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Wtxid(ptx_parent2_v1->GetWitnessHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_parent3->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(ptx_mixed_child->GetHash())));

        // package feerate should include parent3 and child. It should not include parent1 or parent2_v1.
        const CFeeRate expected_feerate(1 * COIN, GetVirtualTransactionSize(*ptx_parent3) + GetVirtualTransactionSize(*ptx_mixed_child));
        BOOST_CHECK(it_parent3->second.m_effective_feerate.value() == expected_feerate);
        BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
        std::vector<uint256> expected_wtxids({ptx_parent3->GetWitnessHash(), ptx_mixed_child->GetWitnessHash()});
        BOOST_CHECK(it_parent3->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
    }
}

BOOST_FIXTURE_TEST_CASE(package_cpfp_tests, TestChain100Setup)
{
    mineBlocks(5);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(::cs_main);
    size_t expected_pool_size = m_node.mempool->size();
    CKey child_key;
    child_key.MakeNewKey(true);
    CScript parent_spk = GetScriptForDestination(WitnessV0KeyHash(child_key.GetPubKey()));
    CKey grandchild_key;
    grandchild_key.MakeNewKey(true);
    CScript child_spk = GetScriptForDestination(WitnessV0KeyHash(grandchild_key.GetPubKey()));

    // low-fee parent and high-fee child package
    const CAmount coinbase_value{50 * COIN};
    const CAmount parent_value{coinbase_value - low_fee_amt};
    const CAmount child_value{parent_value - COIN};

    Package package_cpfp;
    auto mtx_parent = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/parent_spk,
                                                    /*output_amount=*/parent_value, /*submit=*/false);
    CTransactionRef tx_parent = MakeTransactionRef(mtx_parent);
    package_cpfp.push_back(tx_parent);

    auto mtx_child = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent, /*input_vout=*/0,
                                                   /*input_height=*/101, /*input_signing_key=*/child_key,
                                                   /*output_destination=*/child_spk,
                                                   /*output_amount=*/child_value, /*submit=*/false);
    CTransactionRef tx_child = MakeTransactionRef(mtx_child);
    package_cpfp.push_back(tx_child);

    // Package feerate is calculated using modified fees, and prioritisetransaction accepts negative
    // fee deltas. This should be taken into account. De-prioritise the parent transaction
    // to bring the package feerate to 0.
    m_node.mempool->PrioritiseTransaction(tx_parent->GetHash(), child_value - coinbase_value);
    {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_cpfp_deprio = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_cpfp, /*test_accept=*/ false);
        BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK(submit_cpfp_deprio.m_state.IsInvalid());
        BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_tx_results.find(tx_parent->GetWitnessHash())->second.m_state.GetResult(),
                          TxValidationResult::TX_MEMPOOL_POLICY);
        // Package validation is aborted because the parent feerate is below min relay feerate. The
        // child result is filled with TX_UNKNOWN.
        BOOST_CHECK_EQUAL(submit_cpfp_deprio.m_tx_results.find(tx_child->GetWitnessHash())->second.m_state.GetResult(),
                          TxValidationResult::TX_UNKNOWN);
        BOOST_CHECK(submit_cpfp_deprio.m_tx_results.find(tx_parent->GetWitnessHash())->second.m_state.GetRejectReason() == "min relay fee not met");
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const CFeeRate expected_feerate(0, GetVirtualTransactionSize(*tx_parent) + GetVirtualTransactionSize(*tx_child));
    }

    // Clear the prioritisation of the parent transaction.
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->ClearPrioritisation(tx_parent->GetHash()));

    // Package CPFP: Even though the parent's feerate is below the mempool minimum feerate, the
    // child pays enough for the package feerate to meet the threshold.
    {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_cpfp = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_cpfp, /*test_accept=*/ false);
        expected_pool_size += 2;
        BOOST_CHECK_MESSAGE(submit_cpfp.m_state.IsValid(),
                            "Package validation unexpectedly failed: " << submit_cpfp.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(submit_cpfp.m_tx_results.size(), package_cpfp.size());
        auto it_parent = submit_cpfp.m_tx_results.find(tx_parent->GetWitnessHash());
        auto it_child = submit_cpfp.m_tx_results.find(tx_child->GetWitnessHash());
        BOOST_CHECK(it_parent != submit_cpfp.m_tx_results.end());
        BOOST_CHECK(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_parent->second.m_base_fees.value() == coinbase_value - parent_value);
        BOOST_CHECK(it_child != submit_cpfp.m_tx_results.end());
        BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_child->second.m_base_fees.value() == COIN);

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_parent->GetHash())));
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_child->GetHash())));

        const CFeeRate expected_feerate(coinbase_value - child_value,
                                        GetVirtualTransactionSize(*tx_parent) + GetVirtualTransactionSize(*tx_child));
        BOOST_CHECK(it_parent->second.m_effective_feerate.value() == expected_feerate);
        BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
        std::vector<uint256> expected_wtxids({tx_parent->GetWitnessHash(), tx_child->GetWitnessHash()});
        BOOST_CHECK(it_parent->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        BOOST_CHECK(expected_feerate.GetFeePerK() > 1000);
    }

    // Just because we allow low-fee parents doesn't mean we allow low-feerate packages.
    // The mempool minimum feerate is 5sat/vB, but this package just pays 800 satoshis total.
    // The child fees would be able to pay for itself, but isn't enough for the entire package.
    Package package_still_too_low;
    const CAmount parent_fee{200};
    const CAmount child_fee{600};
    auto mtx_parent_cheap = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[1], /*input_vout=*/0,
                                                          /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                          /*output_destination=*/parent_spk,
                                                          /*output_amount=*/coinbase_value - parent_fee, /*submit=*/false);
    CTransactionRef tx_parent_cheap = MakeTransactionRef(mtx_parent_cheap);
    package_still_too_low.push_back(tx_parent_cheap);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_parent_cheap)) > parent_fee);
    BOOST_CHECK(m_node.mempool->m_min_relay_feerate.GetFee(GetVirtualTransactionSize(*tx_parent_cheap)) <= parent_fee);

    auto mtx_child_cheap = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent_cheap, /*input_vout=*/0,
                                                         /*input_height=*/101, /*input_signing_key=*/child_key,
                                                         /*output_destination=*/child_spk,
                                                         /*output_amount=*/coinbase_value - parent_fee - child_fee, /*submit=*/false);
    CTransactionRef tx_child_cheap = MakeTransactionRef(mtx_child_cheap);
    package_still_too_low.push_back(tx_child_cheap);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_child_cheap)) <= child_fee);
    BOOST_CHECK(m_node.mempool->GetMinFee().GetFee(GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap)) > parent_fee + child_fee);

    // Cheap package should fail for being too low fee.
    {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_package_too_low = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                   package_still_too_low, /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(submit_package_too_low.m_state.IsInvalid(), "Package validation unexpectedly succeeded");
        BOOST_CHECK_EQUAL(submit_package_too_low.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK_EQUAL(submit_package_too_low.m_state.GetRejectReason(), "transaction failed");
        // Individual feerate of parent is too low.
        BOOST_CHECK_EQUAL(submit_package_too_low.m_tx_results.at(tx_parent_cheap->GetWitnessHash()).m_state.GetResult(),
                          TxValidationResult::TX_SINGLE_FAILURE);
        BOOST_CHECK(submit_package_too_low.m_tx_results.at(tx_parent_cheap->GetWitnessHash()).m_effective_feerate.value() ==
                    CFeeRate(parent_fee, GetVirtualTransactionSize(*tx_parent_cheap)));
        // Package feerate of parent + child is too low.
        BOOST_CHECK_EQUAL(submit_package_too_low.m_tx_results.at(tx_child_cheap->GetWitnessHash()).m_state.GetResult(),
                          TxValidationResult::TX_SINGLE_FAILURE);
        BOOST_CHECK(submit_package_too_low.m_tx_results.at(tx_child_cheap->GetWitnessHash()).m_effective_feerate.value() ==
                    CFeeRate(parent_fee + child_fee, GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap)));
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
    }

    // Package feerate includes the modified fees of the transactions.
    // This means a child with its fee delta from prioritisetransaction can pay for a parent.
    m_node.mempool->PrioritiseTransaction(tx_child_cheap->GetHash(), 1 * COIN);
    // Now that the child's fees have "increased" by 1 BTC, the cheap package should succeed.
    {
        const auto submit_prioritised_package = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                                  package_still_too_low, /*test_accept=*/false);
        expected_pool_size += 2;
        BOOST_CHECK_MESSAGE(submit_prioritised_package.m_state.IsValid(),
                "Package validation unexpectedly failed" << submit_prioritised_package.m_state.GetRejectReason());
        const CFeeRate expected_feerate(1 * COIN + parent_fee + child_fee,
            GetVirtualTransactionSize(*tx_parent_cheap) + GetVirtualTransactionSize(*tx_child_cheap));
        BOOST_CHECK_EQUAL(submit_prioritised_package.m_tx_results.size(), package_still_too_low.size());
        auto it_parent = submit_prioritised_package.m_tx_results.find(tx_parent_cheap->GetWitnessHash());
        auto it_child = submit_prioritised_package.m_tx_results.find(tx_child_cheap->GetWitnessHash());
        BOOST_CHECK(it_parent != submit_prioritised_package.m_tx_results.end());
        BOOST_CHECK(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_parent->second.m_base_fees.value() == parent_fee);
        BOOST_CHECK(it_parent->second.m_effective_feerate.value() == expected_feerate);
        BOOST_CHECK(it_child != submit_prioritised_package.m_tx_results.end());
        BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_child->second.m_base_fees.value() == child_fee);
        BOOST_CHECK(it_child->second.m_effective_feerate.value() == expected_feerate);
        std::vector<uint256> expected_wtxids({tx_parent_cheap->GetWitnessHash(), tx_child_cheap->GetWitnessHash()});
        BOOST_CHECK(it_parent->second.m_wtxids_fee_calculations.value() == expected_wtxids);
        BOOST_CHECK(it_child->second.m_wtxids_fee_calculations.value() == expected_wtxids);
    }

    // Package feerate is calculated without topology in mind; it's just aggregating fees and sizes.
    // However, this should not allow parents to pay for children. Each transaction should be
    // validated individually first, eliminating sufficient-feerate parents before they are unfairly
    // included in the package feerate. It's also important that the low-fee child doesn't prevent
    // the parent from being accepted.
    Package package_rich_parent;
    const CAmount high_parent_fee{1 * COIN};
    auto mtx_parent_rich = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[2], /*input_vout=*/0,
                                                         /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                         /*output_destination=*/parent_spk,
                                                         /*output_amount=*/coinbase_value - high_parent_fee, /*submit=*/false);
    CTransactionRef tx_parent_rich = MakeTransactionRef(mtx_parent_rich);
    package_rich_parent.push_back(tx_parent_rich);

    auto mtx_child_poor = CreateValidMempoolTransaction(/*input_transaction=*/tx_parent_rich, /*input_vout=*/0,
                                                        /*input_height=*/101, /*input_signing_key=*/child_key,
                                                        /*output_destination=*/child_spk,
                                                        /*output_amount=*/coinbase_value - high_parent_fee - low_fee_amt, /*submit=*/false);
    CTransactionRef tx_child_poor = MakeTransactionRef(mtx_child_poor);
    package_rich_parent.push_back(tx_child_poor);

    // Parent pays 1 BTC and child pays below mempool minimum feerate. The parent should be accepted without the child.
    {
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        const auto submit_rich_parent = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool,
                                                          package_rich_parent, /*test_accept=*/false);
        expected_pool_size += 1;
        BOOST_CHECK_MESSAGE(submit_rich_parent.m_state.IsInvalid(), "Package validation unexpectedly succeeded");

        // The child would have been validated on its own and failed.
        BOOST_CHECK_EQUAL(submit_rich_parent.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        BOOST_CHECK_EQUAL(submit_rich_parent.m_state.GetRejectReason(), "transaction failed");

        auto it_parent = submit_rich_parent.m_tx_results.find(tx_parent_rich->GetWitnessHash());
        auto it_child = submit_rich_parent.m_tx_results.find(tx_child_poor->GetWitnessHash());
        BOOST_CHECK(it_parent != submit_rich_parent.m_tx_results.end());
        BOOST_CHECK(it_child != submit_rich_parent.m_tx_results.end());
        BOOST_CHECK(it_parent->second.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(it_child->second.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK(it_parent->second.m_state.GetRejectReason() == "");
        BOOST_CHECK_MESSAGE(it_parent->second.m_base_fees.value() == high_parent_fee,
                strprintf("rich parent: expected fee %s, got %s", high_parent_fee, it_parent->second.m_base_fees.value()));
        BOOST_CHECK(it_parent->second.m_effective_feerate == CFeeRate(high_parent_fee, GetVirtualTransactionSize(*tx_parent_rich)));
        BOOST_CHECK(it_child != submit_rich_parent.m_tx_results.end());
        BOOST_CHECK_EQUAL(it_child->second.m_result_type, MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(it_child->second.m_state.GetResult(), TxValidationResult::TX_SINGLE_FAILURE);
        BOOST_CHECK(it_child->second.m_state.GetRejectReason() == "mempool min fee not met");

        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Txid(tx_parent_rich->GetHash())));
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Txid(tx_child_poor->GetHash())));
    }

    {
        // Package in which one of the transactions replaces something (by itself, without requiring
        // package RBF).
        const CAmount low_fee{1000};
        const CAmount med_fee{2000};
        const CAmount high_fee{3000};
        CTransactionRef txA_mempool = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                                                       /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                       /*output_destination=*/parent_spk,
                                                                                       /*output_amount=*/coinbase_value - low_fee, /*submit=*/true));
        expected_pool_size += 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        Package package_with_rbf;
        // Conflicts with txA_mempool and can replace it.
        CTransactionRef txA_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[3], /*input_vout=*/0,
                                                                                       /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                       /*output_destination=*/parent_spk,
                                                                                       /*output_amount=*/coinbase_value - med_fee, /*submit=*/false));
        CTransactionRef txB_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[4], /*input_vout=*/0,
                                                                                       /*input_height=*/102, /*input_signing_key=*/coinbaseKey,
                                                                                       /*output_destination=*/parent_spk,
                                                                                       /*output_amount=*/coinbase_value - low_fee, /*submit=*/false));
        package_with_rbf.push_back(txA_package);
        package_with_rbf.push_back(txB_package);

        CTransactionRef txC_package = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transactions=*/package_with_rbf,
                                                                                       /*inputs=*/{COutPoint{txA_package->GetHash(), 0},
                                                                                                   COutPoint{txB_package->GetHash(), 0}},
                                                                                       /*input_height=*/102,
                                                                                       /*input_signing_keys=*/{child_key},
                                                                                       /*outputs=*/{CTxOut{coinbase_value * 2 - low_fee - med_fee - high_fee, child_spk}},
                                                                                       /*submit=*/false));
        package_with_rbf.push_back(txC_package);
        const auto result_rbf = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_with_rbf, /*test_accept=*/false);
        expected_pool_size += 3 - 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK_EQUAL(result_rbf.m_tx_results.size(), package_with_rbf.size());
        BOOST_CHECK(result_rbf.m_state.IsValid());
        BOOST_CHECK(!m_node.mempool->exists(GenTxid::Wtxid(txA_mempool->GetWitnessHash())));
        for (size_t idx{0}; idx < package_with_rbf.size(); ++idx) {
            BOOST_CHECK(m_node.mempool->exists(GenTxid::Wtxid(package_with_rbf.at(idx)->GetWitnessHash())));
        }
    }
}
BOOST_FIXTURE_TEST_CASE(linearization_tests, TestChain100Setup)
{
    mineBlocks(5);
    MockMempoolMinFee(CFeeRate(5000));
    LOCK(::cs_main);
    size_t expected_pool_size = m_node.mempool->size();
    CKey key1;
    CKey key2;
    CKey key3;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);

    CScript spk1 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key1.GetPubKey())));
    CScript spk2 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key2.GetPubKey())));
    CScript spk3 = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(key3.GetPubKey())));

    const CAmount coinbase_value{50 * COIN};
    {
        // A package that exceeds descendant limits, but we should take the highest feerate one:
        //
        //          gen1
        //            ^
        //            .
        //            .
        //
        //            ^
        //          gen24
        //
        //       ^^^^^^^^^^
        //       10 parents
        //            ^
        //          child
        //
        // There are 10 parents with different feerates. Only 1 transaction can be accepted.
        // It should be the highest feerate one.

        // chain of 24 mempool transactions, each paying 1000sat
        const CAmount fee_per_mempool_tx{1000};
        CTransactionRef gen1_tx = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                                                  /*input_height=*/101, /*input_signing_key=*/coinbaseKey,
                                                                                  /*output_destination=*/spk1,
                                                                                  /*output_amount=*/coinbase_value - fee_per_mempool_tx, /*submit=*/true));
        CTransactionRef& last_tx = gen1_tx;
        for (auto i{2}; i <= 23; ++i) {
            last_tx = MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/last_tx, /*input_vout=*/0,
                                                                       /*input_height=*/101, /*input_signing_key=*/key1,
                                                                       /*output_destination=*/spk1,
                                                                       /*output_amount=*/coinbase_value - (fee_per_mempool_tx * i),
                                                                       /*submit=*/true));
        }
        // The 24th transaction has 10 outputs, pays 3000sat fees.
        const CAmount amount_per_output{(coinbase_value - (23 * fee_per_mempool_tx) - 3000) / 10};

        std::vector<CKey> parent_keys;
        std::vector<CTxOut> gen24_outputs;
        for (auto o{0}; o < 10; ++o) {
            CKey parent_key;
            parent_key.MakeNewKey(true);
            CScript parent_spk = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(parent_key.GetPubKey())));
            gen24_outputs.push_back(CTxOut{amount_per_output, parent_spk});
            parent_keys.push_back(parent_key);
        }
        auto gen24_tx{MakeTransactionRef(CreateValidMempoolTransaction(/*input_transactions=*/{last_tx}, /*inputs=*/{COutPoint{last_tx->GetHash(), 0}},
                                                                       /*input_height=*/101, /*input_signing_keys=*/{key1},
                                                                       /*outputs=*/gen24_outputs, /*submit=*/true))};
        expected_pool_size += 24;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);

        Package package_desc_limits;
        std::vector<COutPoint> grandchild_outpoints;
        // Each parent pays 1000sat more than the previous one.
        for (auto parent_num{0}; parent_num < 10; ++parent_num) {
            auto parent_tx{MakeTransactionRef(CreateValidMempoolTransaction(/*input_transaction=*/gen24_tx,
                                                                            /*input_vout=*/parent_num,
                                                                            /*input_height=*/101,
                                                                            /*input_signing_key=*/parent_keys.at(parent_num),
                                                                            /*output_destination=*/spk3,
                                                                            /*output_amount=*/amount_per_output - 1000 * (parent_num + 1),
                                                                            /*submit=*/false))};
            package_desc_limits.push_back(parent_tx);
            grandchild_outpoints.push_back(COutPoint{parent_tx->GetHash(), 0});
        }
        const auto& highest_feerate_parent_wtxid = package_desc_limits.back()->GetWitnessHash();
        // Child pays insanely high fee
        const CAmount child_value{COIN};
        auto mtx_child{CreateValidMempoolTransaction(/*input_transactions=*/package_desc_limits,
                                                     /*inputs=*/grandchild_outpoints,
                                                     /*input_height=*/101,
                                                     /*input_signing_keys=*/{key3},
                                                     /*outputs=*/{CTxOut{child_value, spk1}},
                                                     /*submit=*/false)};
        CTransactionRef tx_child = MakeTransactionRef(mtx_child);
        package_desc_limits.push_back(tx_child);

        const auto result_desc_limits = ProcessNewPackage(m_node.chainman->ActiveChainstate(), *m_node.mempool, package_desc_limits, /*test_accept=*/false);
        BOOST_CHECK_EQUAL(result_desc_limits.m_tx_results.size(), package_desc_limits.size());
        BOOST_CHECK_EQUAL(result_desc_limits.m_state.GetResult(), PackageValidationResult::PCKG_TX);
        for (size_t idx{0}; idx < package_desc_limits.size(); ++idx) {
            const auto& txresult = result_desc_limits.m_tx_results.at(package_desc_limits.at(idx)->GetWitnessHash());
            if (idx == 9) {
                // The last parent had the highest feerate and was accepted.
                BOOST_CHECK(txresult.m_state.IsValid());
            } else if (idx == 8) {
                // The second-highest feerate parent hit too-long-mempool-chain for exceeding
                // gen1_tx's descendant limit.
                BOOST_CHECK_EQUAL(txresult.m_state.GetResult(), TxValidationResult::TX_MEMPOOL_POLICY);
                BOOST_CHECK(txresult.m_state.GetRejectReason() == "too-long-mempool-chain");
            } else {
                // The rest of the parents and the child were skipped.
                BOOST_CHECK_EQUAL(txresult.m_state.GetResult(), TxValidationResult::TX_UNKNOWN);
            }
        }
        expected_pool_size += 1;
        BOOST_CHECK_EQUAL(m_node.mempool->size(), expected_pool_size);
        BOOST_CHECK(m_node.mempool->exists(GenTxid::Wtxid(highest_feerate_parent_wtxid)));
    }
}
BOOST_AUTO_TEST_SUITE_END()
