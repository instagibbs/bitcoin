// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txgraph.h>
#include <cluster_linearize.h>
#include <test/util/setup_common.h>
#include <util/bitset.h>
#include <util/feefrac.h>

#include <queue>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(siblingeviction_tests, TestingSetup)

BOOST_FIXTURE_TEST_CASE(siblingeviction, TestChain100Setup)
{
    /** Variable used whenever an empty TxGraph::Ref is needed. */
    TxGraph::Ref empty_ref;

    const int32_t max_count = 6;

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

    BOOST_CHECK(!graph->HaveStaging());

    // Parent with two children, one a cpfp, one dead weight
    TxGraph::Ref parent_1 = graph->AddTransaction(feerate1);
    TxGraph::Ref child_cpfp = graph->AddTransaction(feerate2);
    TxGraph::Ref child_moocher = graph->AddTransaction(feerate3);

    graph->AddDependency(parent_1, child_cpfp);
    graph->AddDependency(child_cpfp, child_moocher);
    graph->AddDependency(parent_1, child_moocher);

    // Second parent to cpfp and child_low_fee
    TxGraph::Ref parent_2 = graph->AddTransaction(feerate1);
    TxGraph::Ref child_low_fee = graph->AddTransaction(feerate3);

    graph->AddDependency(parent_2, child_cpfp);
    graph->AddDependency(parent_2, child_low_fee);

    // Third parent to its own cluster which will be joined
    // via new package
    TxGraph::Ref parent_3 = graph->AddTransaction(feerate1);

    // Just at size.
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/true));

    const FeeFrac feerate_high{20, 1};
    // New package of 2 comes in, we make a graph for just itself
    {
        auto pkg_graph = MakeTxGraph(max_count);

        // Conflicts with child_moocher under the hood
        TxGraph::Ref new_child_low_fee = pkg_graph->AddTransaction(feerate3);
        TxGraph::Ref grandchild_cpfp = pkg_graph->AddTransaction(feerate_high);
        pkg_graph->AddDependency(new_child_low_fee, grandchild_cpfp);
        BOOST_CHECK(!pkg_graph->IsOversized(/*main_only=*/true));

        // TODO Per-chunk processing: Could use mining interface here
        // on fresh and tiny graph. Each package just thrown in here
        // then run acceptance sub-routine for each chunk or ditch
        // on failure.
        auto builder = pkg_graph->GetBlockBuilder();
        //BOOST_CHECK(builder);
        auto cfr = builder->GetCurrentChunkFeerate();
        auto chunk = builder->GetCurrentChunk();
        BOOST_CHECK_EQUAL(chunk.size(), 2);
        BOOST_CHECK(feerate3 + feerate_high == cfr);
    }

    // We will attempt to add to staging
    graph->StartStaging();

    // RBFs: We remove from staging area
    // Things we need to RemoveTransaction for due to direct conflicts
    // and all the conflicted descendants
    // Only one RBF, simulated for now. Moocher out.
    graph->RemoveTransaction(child_moocher);

    // New child has two parents and one grandchild
    TxGraph::Ref new_child_low_fee_2 = graph->AddTransaction(feerate3);
    TxGraph::Ref grandchild_cpfp_2 = graph->AddTransaction(feerate_high);
    graph->AddDependency(parent_1, new_child_low_fee_2);
    graph->AddDependency(parent_3, new_child_low_fee_2);
    graph->AddDependency(new_child_low_fee_2, grandchild_cpfp_2);

    // Staged area is now oversized, time to inspect main graph
    // to decide what to remove before attempting RBF since it has
    // access to chunk feerates
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/false), 7);
    BOOST_CHECK(graph->IsOversized(/*main_only=*/false));
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 6);

    std::vector<TxGraph::Ref> parents;

    // Gather all in-main parents of package (parent ref already held)
    // Only one parent for now
    parents.push_back(std::move(parent_1));
    parents.push_back(std::move(parent_3));

    std::set<TxGraph::Ref*> all_ancestors;

    // One tx could be joining MAX_CLUSTER_COUNT_LIMIT - 1 clusters
    // each with MAX_CLUSTER_COUNT_LIMIT txns themselves
    // where removing MAX_CLUSTER_COUNT_LIMIT - 1 transactions,
    // one from each cluster, would result in properly sized
    // clusters. Roughly MAX_CLUSTER_COUNT_LIMIT^2 may get
    // removed if greedily removing 
    // That's 4032 possible removals vs 100*64 total RBFs.
    // Needs to be computed in same bucket of conflicts before
    // asking for diagrams.

    // GetCluster will return think in CFR order, so we can
    // walk each vector backwards, deleting transactions
    // via a minheap until no oversized. We should stop
    // after MAX_CLUSTER_COUNT_LIMIT removals; 
    std::vector<std::vector<TxGraph::Ref*>> affected_clusters;

    using RefCmp = std::pair<TxGraph::Ref*, uint32_t>;
    auto ref_cmp = [&graph](RefCmp lhs, RefCmp rhs) {
        const auto lhs_prio = graph->GetMainChunkFeerate(*lhs.first);
        const auto rhs_prio = graph->GetMainChunkFeerate(*rhs.first);
        return lhs_prio > rhs_prio || (lhs_prio == rhs_prio && lhs.second > rhs.second); // Min-heap: smallest priority first
    };

    // Set with first entry of GetCluster result to ensure uniqueness in heap_refs
    std::set<TxGraph::Ref*> affected_clusters_prefix;

    // We're building a topo-valid heap, could also just
    // build a heap that keeps track of tail of clusters
    std::vector<RefCmp> heap_refs;

    for (const auto& parent : parents) {
        // Gather all ancestors (they can not be evicted)
        auto ancestors = graph->GetAncestors(parent, /*main_only=*/true);
        all_ancestors.insert(ancestors.begin(), ancestors.end());

        const auto& cluster = graph->GetCluster(parent, /*main_only=*/true);
        // If new cluster, append to cluster list
        if (!cluster.empty() && affected_clusters_prefix.insert(cluster[0]).second) {
            affected_clusters.push_back(cluster);
            for (const auto& ref : cluster) {
                // Add size to give topo-valid tie-breaker in heap
                heap_refs.emplace_back(ref, heap_refs.size());
            }
        }
    }

    // 2 parents with just themselves
    BOOST_CHECK_EQUAL(all_ancestors.size(), 2);

    std::make_heap(heap_refs.begin(), heap_refs.end(), ref_cmp);

    BOOST_CHECK(graph->HaveStaging());

    // Nothing possible so exit with "failure"
    if (heap_refs.empty()) return;

    // STRATEGY 1: Evict any non-ancestors from effected clusters
    FeeFrac last_feerate;
    do {
        std::pop_heap(heap_refs.begin(), heap_refs.end(), ref_cmp);
        TxGraph::Ref* ref = heap_refs.back().first;
        heap_refs.pop_back();

        // TODO Could check if ref is a descendant of any all_ancestors, and continue if not

        // We can't evict our package ancestors
        if (all_ancestors.count(ref) > 0) continue;

        // The tx might already be removed in staging from direct conflict, no-op in that case
        graph->RemoveTransaction(*ref);

        auto cfr{graph->GetMainChunkFeerate(*ref)};
        if (last_feerate.IsEmpty()) {
            last_feerate = cfr;
        } else {
            BOOST_CHECK(last_feerate <= cfr);
            last_feerate = cfr;
        }
    } while (!heap_refs.empty() && graph->IsOversized(/*main_only=*/false));

    // We're good to go
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/false));

    // Do we want it regardless?
    const auto diagrams = graph->GetMainStagingDiagrams();

    graph->CommitStaging();

    // One cluster remaining since package joined everything
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 6);
    BOOST_CHECK_EQUAL(graph->GetCluster(parents[0]).size(), 6);
}

BOOST_AUTO_TEST_SUITE_END()
