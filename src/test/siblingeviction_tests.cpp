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
    const uint max_count = 6;
    const uint64_t max_size = 100'000;

    auto graph = MakeTxGraph(max_count, max_size);

    graph->StartStaging();


    const FeeFrac low_feerate{1, 20};
    const FeeFrac med_feerate{1, 2};
    const FeeFrac high_feerate{2, 1};
    const FeeFrac highest_feerate{20, 1};

    // Parent with two children, one a cpfp, one dead weight
    TxGraph::Ref parent_1 = graph->AddTransaction(med_feerate);
    TxGraph::Ref child_cpfp = graph->AddTransaction(high_feerate);
    TxGraph::Ref child_parent_1_moocher = graph->AddTransaction(low_feerate);

    graph->AddDependency(parent_1, child_cpfp);
    graph->AddDependency(child_cpfp, child_parent_1_moocher);
    graph->AddDependency(parent_1, child_parent_1_moocher);

    // Second parent, parent to cpfp and second moocher
    TxGraph::Ref parent_2 = graph->AddTransaction(med_feerate);
    TxGraph::Ref child_parent_2_moocher = graph->AddTransaction(low_feerate);

    graph->AddDependency(parent_2, child_cpfp);
    graph->AddDependency(parent_2, child_parent_2_moocher);

    // Third parent to its own cluster which will be joined
    // via new package
    TxGraph::Ref parent_3 = graph->AddTransaction(med_feerate);

    // Just at size.
    graph->CommitStaging();
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/true));

    // New package of 2 comes in, we make a graph for just itself
    // Would need to fetch utxos, fill in feerates
    {
        auto pkg_graph = MakeTxGraph(max_count, 100'000);

        // RBF conflicts with child_parent_1_moocher under the hood
        TxGraph::Ref new_child_low_fee = pkg_graph->AddTransaction(low_feerate);
        TxGraph::Ref grandchild_cpfp = pkg_graph->AddTransaction(highest_feerate);
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
        BOOST_CHECK(low_feerate + highest_feerate == cfr);
    }

    // We will attempt to add to staging
    graph->StartStaging();

    // Set of detected conflicts in main graph
    std::set<TxGraph::Ref*> all_conflicts;

    // RBFs: We remove from staging area
    // Things we need to RemoveTransaction for due to direct conflicts
    // and all the conflicted descendants
    // Only one RBF, simulated for now. Moocher out.
    graph->RemoveTransaction(child_parent_1_moocher);
    all_conflicts.insert(&child_parent_1_moocher);

    // New child has two parents and one grandchild
    TxGraph::Ref new_child_low_fee = graph->AddTransaction(low_feerate);
    TxGraph::Ref grandchild_cpfp = graph->AddTransaction(highest_feerate);
    graph->AddDependency(parent_1, new_child_low_fee);
    graph->AddDependency(parent_3, new_child_low_fee);
    graph->AddDependency(new_child_low_fee, grandchild_cpfp);

    // Staged area is now oversized, time to inspect main graph
    // to decide what to remove before attempting RBF since it has
    // access to chunk feerates
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/false), 7);
    BOOST_CHECK(graph->IsOversized(/*main_only=*/false));
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 6);

    // Gather all in-main parents of package (parent ref already held)
    std::vector<TxGraph::Ref> parents;
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

    using Chunk = std::vector<TxGraph::Ref*>;

    auto ref_cmp = [&graph](Chunk lhs, Chunk rhs) {
        return std::is_lt(graph->CompareMainOrder(*lhs[0], *rhs[0]));
    };

    // Set with first entry of GetCluster result to ensure uniqueness in heap_refs
    std::set<TxGraph::Ref*> affected_clusters_prefix;

    // We're building a topo-valid heap, could also just
    // build a heap that keeps track of tail of clusters
    std::vector<Chunk> heap_refs;

    for (const auto& parent : parents) {
        // Gather all ancestors (they can not be evicted)
        // N.B. we may not have access to this call in future?
        auto ancestors = graph->GetAncestors(parent, /*main_only=*/true);
        all_ancestors.insert(ancestors.begin(), ancestors.end());

        const auto& cluster = graph->GetCluster(parent, /*main_only=*/true);
        // If new cluster, append to cluster list
        if (!cluster.empty() && affected_clusters_prefix.insert(cluster[0]).second) {
            affected_clusters.push_back(cluster);

            // Accumulates transactions until package feerate matches measured chunkfeerate
            // since that implies that is the chunk.
            Chunk current_chunk;
            FeeFrac current_feerate;
            for (const auto& ref : cluster) {
                const auto ifr = graph->GetIndividualFeerate(*ref);
                const auto cfr = graph->GetMainChunkFeerate(*ref);

                current_chunk.emplace_back(ref);
                current_feerate += ifr;

                if (cfr == current_feerate) {
                    heap_refs.emplace_back(current_chunk);
                    current_chunk.clear();
                    current_feerate = FeeFrac{};
                }
            }
            BOOST_CHECK_EQUAL(current_chunk.size(), 0);
            BOOST_CHECK(current_feerate == FeeFrac{});
        }
    }

    // 2 parents with just themselves
    BOOST_CHECK_EQUAL(all_ancestors.size(), 2);

    std::set<TxGraph::Ref*> all_ancestors_descendants;
    for (const auto ancestor : all_ancestors) {
        const auto desc = graph->GetDescendants(*ancestor, /*main_only=*/true);
        all_ancestors_descendants.insert(desc.begin(), desc.end());
    }
    // Two parents, two children
    BOOST_CHECK_EQUAL(all_ancestors_descendants.size(), 4);

    std::make_heap(heap_refs.begin(), heap_refs.end(), ref_cmp);

    BOOST_CHECK(graph->HaveStaging());

    // Nothing possible so exit with "failure"
    if (heap_refs.empty()) return;

    std::vector<TxGraph::Ref*> sibling_evicted;

    // Switch this to change eviction strategy
    // We may not have fast access to these sets in future.
    bool filter_for_desc_of_anc = false;

    do {
        std::pop_heap(heap_refs.begin(), heap_refs.end(), ref_cmp);
        Chunk popped_chunk = heap_refs.back();
        //TxGraph::Ref* ref = heap_refs.back();
        heap_refs.pop_back();

        // Walk backwards over chunk transactions; we might not have to evict all of it
        for (size_t i{0}; i < popped_chunk.size() ; ++i) {
            const auto ref = popped_chunk[popped_chunk.size() - 1 - i];

            // Only evict things that are descendants of ancestors of package
            // This results in a slightly more "local" eviction, which may
            // or may not be cheaper.
            if (filter_for_desc_of_anc && !all_ancestors_descendants.contains(ref)) continue;

            // We can't evict our package ancestors
            if (all_ancestors.count(ref) > 0) continue;

            // The tx might already be removed in staging from direct conflict, no-op in that case
            // For logging purposes we skip
            if (all_conflicts.contains(ref)) continue;

            graph->RemoveTransaction(*ref);
            sibling_evicted.push_back(std::move(ref));

            if (!graph->IsOversized(/*main_only=*/false)) break;
        }
    } while (!heap_refs.empty() && graph->IsOversized(/*main_only=*/false));

    // Now that we fit, we may be able to re-add some transactions
    // Walk backwards over sibling_evicted, and attempt
    // to re-add them. If still oversized, add to sibling_skip
    // list and continue. For each considered re-add,
    // we skip them if you already skipped their ancestor
    // by finding it in the sibling_skip set.

    // We're good to go
    BOOST_CHECK(!graph->IsOversized(/*main_only=*/false));

    // Do we want it regardless?
    const auto diagrams = graph->GetMainStagingDiagrams();

    graph->CommitStaging();

    // One cluster remaining since package joined everything
    BOOST_CHECK_EQUAL(graph->GetTransactionCount(/*main_only=*/true), 6);
    const auto parent_1_cluster = graph->GetCluster(parents[0]);
    BOOST_CHECK_EQUAL(parent_1_cluster.size(), filter_for_desc_of_anc ? 4 : 6);
    BOOST_CHECK_EQUAL(sibling_evicted.size(), 1);
    BOOST_CHECK(filter_for_desc_of_anc ? sibling_evicted[0] == &child_cpfp : sibling_evicted[0] == &child_parent_2_moocher);
}

BOOST_AUTO_TEST_SUITE_END()
