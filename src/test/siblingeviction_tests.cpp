// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txgraph.h>
#include <cluster_linearize.h>
#include <test/util/setup_common.h>
#include <util/bitset.h>
#include <util/feefrac.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(siblingeviction_tests, TestingSetup)

BOOST_FIXTURE_TEST_CASE(siblingeviction, TestChain100Setup)
{
    /** Variable used whenever an empty TxGraph::Ref is needed. */
    TxGraph::Ref empty_ref;

    const int32_t max_count = 3;

    auto graph = MakeTxGraph(max_count);

    graph->StartStaging();

    const FeeFrac feerate1{1, 2};
    const FeeFrac feerate2{4, 2};
    const FeeFrac feerate3{1, 20};

    TxGraph::Ref ref1 = graph->AddTransaction(feerate1);
    TxGraph::Ref ref2 = graph->AddTransaction(feerate2);

    graph->AddDependency(ref1, ref2);

    graph->SetTransactionFeerate(ref1, feerate3);

    BOOST_CHECK(!graph->IsOversized(true));

    bool exists = graph->Exists(ref1, /*main_only=*/false);
    BOOST_CHECK(exists);

    auto indfeerate = graph->GetIndividualFeerate(ref1);
    BOOST_CHECK(indfeerate != FeeFrac{});

    auto chunkfeerate = graph->GetMainChunkFeerate(ref1);
    // Not in main, returns 0
    BOOST_CHECK(chunkfeerate == FeeFrac{});

    auto desc1 = graph->GetDescendants(ref1, false);
    auto desc2 = graph->GetDescendants(ref2, false);

    auto anc1 = graph->GetAncestors(ref1, false);
    auto anc2 = graph->GetAncestors(ref2, false);

    auto cluster1 = graph->GetCluster(ref1, false);
    auto cluster2 = graph->GetCluster(ref2, false);

    BOOST_CHECK(graph->HaveStaging());

    graph->CommitStaging();
    BOOST_CHECK(!graph->HaveStaging());

    auto cmp = graph->CompareMainOrder(ref1, ref2);
    BOOST_CHECK(cmp != 0);

    graph->StartStaging();
    graph->AbortStaging();

    graph->SanityCheck();

    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 2);

    chunkfeerate = graph->GetMainChunkFeerate(ref1);
    // Now in main
    BOOST_CHECK(chunkfeerate == feerate3 + feerate2);

    // Removes directly from main
    graph->RemoveTransaction(ref1);
    graph->RemoveTransaction(ref2);

    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 0);

    std::vector<TxGraph::Ref*> removed = graph->Cleanup();
    BOOST_CHECK_EQUAL(removed.size(), 2);

    // Parent with two children, one a cpfp, one dead weight
    BOOST_CHECK(!graph->HaveStaging());
    TxGraph::Ref parent = graph->AddTransaction(feerate1);
    TxGraph::Ref child_cpfp = graph->AddTransaction(feerate2);
    TxGraph::Ref child_moocher = graph->AddTransaction(feerate3);

    graph->AddDependency(parent, child_cpfp);
    graph->AddDependency(child_cpfp, child_moocher);
    graph->AddDependency(parent, child_moocher);

    // Just at size.
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/true));

    // New package of 2 comes in
    const FeeFrac feerate_high{20, 1};
    auto pkg_graph = MakeTxGraph(max_count);

    TxGraph::Ref child_low_fee = pkg_graph->AddTransaction(feerate3);
    TxGraph::Ref grandchild_cpfp = pkg_graph->AddTransaction(feerate_high);
    pkg_graph->AddDependency(child_low_fee, grandchild_cpfp);
    BOOST_CHECK(!pkg_graph->IsOversized(/*main_only=*/true));

    // Per-chunk processing ???
    // No great way to introspect which chunks are made
    // We "just know" this package is good, so let's
    // try and add to main graph

    // We will attempt to add to staging
    graph->StartStaging();

    TxGraph::Ref child_low_fee_2 = graph->AddTransaction(feerate3);
    TxGraph::Ref grandchild_cpfp_2 = graph->AddTransaction(feerate_high);
    graph->AddDependency(parent, child_low_fee_2);
    graph->AddDependency(child_low_fee_2, grandchild_cpfp_2);
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/false), 5);
    BOOST_CHECK(graph->IsOversized(/*main_only=*/false));

    // Oversized, time to figure out what we can do to propose an RBF

    // Can we do this with staging going the entire time?

    // Gather all in-main parents of package (parent ref already held)
    auto ancestors = graph->GetAncestors(parent, /*main_only=*/true);
    std::set<TxGraph::Ref*> all_ancestors(ancestors.begin(), ancestors.end());
    BOOST_CHECK_EQUAL(all_ancestors.size(), 1);

    // Loop over all in-main parents of package, gather Clusters (only one parent here)
    std::vector<TxGraph::Ref*> affected_cluster{graph->GetCluster(parent, /*main_only=*/true)};

    // STRATEGY 1: Evict any non-ancestors from effected clusters
    FeeFrac last_feerate;
    do {
        const auto ref = affected_cluster.back();
        affected_cluster.pop_back();

        // We can't evict our package ancestors
        if (all_ancestors.contains(ref)) continue;

        graph->RemoveTransaction(*ref);

        // If I remove the child does it immediately cause recomputing of the chunk?
        auto cfr{graph->GetMainChunkFeerate(*ref)};
        if (last_feerate.IsEmpty()) {
            last_feerate = cfr;
        } else {
            BOOST_CHECK(last_feerate <= cfr);
            last_feerate = cfr;
        }
    } while (!affected_cluster.empty() && graph->IsOversized(/*main_only=*/false));

    // We're good to go
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/false));
    graph->CommitStaging();

    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 3);

}

BOOST_AUTO_TEST_SUITE_END()
