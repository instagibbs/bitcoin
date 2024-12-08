// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txgraph.h>
#include <cluster_linearize.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <util/bitset.h>
#include <util/feefrac.h>

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <stdint.h>
#include <utility>

using namespace cluster_linearize;

namespace {

/** Data type representing a naive simulated TxGraph, keeping all transactions (even from
 *  disconnected components) in a single DepGraph. Unlike the real TxGraph, this only models
 *  a single graph, and multiple instances are used to simulate main/staging. */
struct SimTxGraph
{
    /** Maximum number of transactions to support simultaneously. Set this higher than txgraph's
     *  cluster count, so we can exercise situations with more transactions than fit in one
     *  cluster. */
    static constexpr unsigned MAX_TRANSACTIONS = MAX_CLUSTER_COUNT_LIMIT * 2;
    /** Set type to use in the simulation. */
    using SetType = BitSet<MAX_TRANSACTIONS>;
    /** Data type for representing positions within SimTxGraph::graph. */
    using Pos = ClusterIndex;
    /** Constant to mean "missing in this graph". */
    static constexpr auto MISSING = Pos(-1);

    /** The dependency graph (for all transactions in the simulation, regardless of
     *  connectivity/clustering). */
    DepGraph<SetType> graph;
    /** For each position in graph, which TxGraph::Ref it corresponds with (if any). Use shared_ptr
     *  so that a SimTxGraph can be copied to create a staging one, while sharing Refs with
     *  the main graph. */
    std::array<std::shared_ptr<TxGraph::Ref>, MAX_TRANSACTIONS> simmap;
    /** For each TxGraph::Ref in graph, the position it corresponds with. */
    std::map<const TxGraph::Ref*, Pos> simrevmap;
    /** The set of TxGraph::Ref entries that have been removed, but not yet Cleanup()'ed in
     *  the real TxGraph. */
    std::vector<std::shared_ptr<TxGraph::Ref>> removed;
    /** Whether the graph is oversized (true = yes, false = no, std::nullopt = unknown). */
    std::optional<bool> oversized;
    /** The configured maximum number of transactions per cluster. */
    ClusterIndex max_cluster_count;

    /** Construct a new SimTxGraph with the specified maximum cluster count. */
    explicit SimTxGraph(ClusterIndex max_cluster) : max_cluster_count(max_cluster) {}

    // Permit copying and moving.
    SimTxGraph(const SimTxGraph&) noexcept = default;
    SimTxGraph& operator=(const SimTxGraph&) noexcept = default;
    SimTxGraph(SimTxGraph&&) noexcept = default;
    SimTxGraph& operator=(SimTxGraph&&) noexcept = default;

    /** Check whether this graph is oversized (contains a connected component whose number of
     *  transactions exceeds max_cluster_count. */
    bool IsOversized()
    {
        if (!oversized.has_value()) {
            // Only recompute when oversized isn't already known.
            oversized = false;
            auto todo = graph.Positions();
            // Iterate over all connected components of the graph.
            while (todo.Any()) {
                auto component = graph.FindConnectedComponent(todo);
                if (component.Count() > max_cluster_count) oversized = true;
                todo -= component;
            }
        }
        return *oversized;
    }

    /** Determine the number of (non-removed) transactions in the graph. */
    ClusterIndex GetTransactionCount() const { return graph.TxCount(); }

    /** Get the sum of all fees/sizes in the graph. */
    FeeFrac SumAll() const
    {
        FeeFrac ret;
        for (auto i : graph.Positions()) {
            ret += graph.FeeRate(i);
        }
        return ret;
    }

    /** Get the position where ref occurs in this simulated graph, or -1 if it does not. */
    Pos Find(const TxGraph::Ref& ref) const
    {
        if (!ref) return MISSING;
        auto it = simrevmap.find(&ref);
        if (it != simrevmap.end()) return it->second;
        return MISSING;
    }

    /** Given a position in this simulated graph, get the corresponding TxGraph::Ref. */
    TxGraph::Ref& GetRef(Pos pos)
    {
        assert(graph.Positions()[pos]);
        assert(simmap[pos]);
        return *simmap[pos].get();
    }

    /** Add a new transaction to the simulation. */
    TxGraph::Ref& AddTransaction(const FeeFrac& feerate)
    {
        assert(graph.TxCount() < MAX_TRANSACTIONS);
        auto simpos = graph.AddTransaction(feerate);
        assert(graph.Positions()[simpos]);
        simmap[simpos] = std::make_shared<TxGraph::Ref>();
        auto ptr = simmap[simpos].get();
        simrevmap[ptr] = simpos;
        return *ptr;
    }

    /** Add a dependency between two positions in this graph. */
    void AddDependency(TxGraph::Ref& parent, TxGraph::Ref& child)
    {
        auto par_pos = Find(parent);
        if (par_pos == MISSING) return;
        auto chl_pos = Find(child);
        if (chl_pos == MISSING) return;
        graph.AddDependencies(SetType::Singleton(par_pos), chl_pos);
        // This may invalidate our cached oversized value.
        if (oversized.has_value() && !*oversized) oversized = std::nullopt;
    }

    /** Modify the transaction feerate of a ref, if it exists. */
    void SetTransactionFeerate(TxGraph::Ref& ref, const FeeFrac& feerate)
    {
        auto pos = Find(ref);
        if (pos == MISSING) return;
        graph.FeeRate(pos) = feerate;
    }

    /** Remove the transaction in the specified position from the graph. */
    void RemoveTransaction(TxGraph::Ref& ref)
    {
        auto pos = Find(ref);
        if (pos == MISSING) return;
        graph.RemoveTransactions(SetType::Singleton(pos));
        simrevmap.erase(simmap[pos].get());
        // Remember the TxGraph::Ref corresponding to this position, because we still expect
        // to see it when calling Cleanup().
        removed.push_back(std::move(simmap[pos]));
        simmap[pos].reset();
        // This may invalidate our cached oversized value.
        if (oversized.has_value() && *oversized) oversized = std::nullopt;
    }

    /** Destroy the transaction from the graph, including from the removed set. This will
     *  trigger TxGraph::Ref::~Ref. reset_oversize controls whether the cached oversized
     *  value is cleared (destroying does not clear oversizedness in TxGraph of the main
     *  graph while staging exists). */
    void DestroyTransaction(TxGraph::Ref& ref, bool reset_oversize)
    {
        // Special case the empty Ref.
        if (!ref) return;
        auto pos = Find(ref);
        if (pos == MISSING) {
            // Wipe the ref, if it exists, from the removed vector. Use std::partition rather
            // than std::erase because we don't care about the order of the entries that
            // remain.
            auto remove = std::partition(removed.begin(), removed.end(), [&](auto& arg) { return arg.get() != &ref; });
            removed.erase(remove, removed.end());
        } else {
            graph.RemoveTransactions(SetType::Singleton(pos));
            simrevmap.erase(simmap[pos].get());
            simmap[pos].reset();
            // This may invalidate our cached oversized value.
            if (reset_oversize && oversized.has_value() && *oversized) {
                oversized = std::nullopt;
            }
        }
    }

    /** Construct the set with all positions in this graph corresponding to the specified
     *  TxGraph::Refs. All of them must occur in this graph and not be removed. */
    SetType MakeSet(std::span<TxGraph::Ref* const> arg)
    {
        SetType ret;
        for (TxGraph::Ref* ptr : arg) {
            auto pos = Find(*ptr);
            assert(pos != Pos(-1));
            ret.Set(pos);
        }
        return ret;
    }

    /** Get the set of ancestors (desc=false) or descendants (desc=true) in this graph. */
    SetType GetAncDesc(TxGraph::Ref& arg, bool desc)
    {
        auto pos = Find(arg);
        if (pos == MISSING) return {};
        return desc ? graph.Descendants(pos) : graph.Ancestors(pos);
    }

    /** Given a set of Refs (given as a vector of pointers), expand the set to include all its
     *  ancestors (desc=false) or all its descendants (desc=true) in this graph. */
    void IncludeAncDesc(std::vector<TxGraph::Ref*>& arg, bool desc)
    {
        std::vector<TxGraph::Ref*> ret;
        for (auto ptr : arg) {
            auto simpos = Find(*ptr);
            if (simpos != MISSING) {
                for (auto i : desc ? graph.Descendants(simpos) : graph.Ancestors(simpos)) {
                    ret.push_back(simmap[i].get());
                }
            } else {
                ret.push_back(ptr);
            }
        }
        // Deduplicate.
        std::sort(ret.begin(), ret.end());
        ret.erase(std::unique(ret.begin(), ret.end()), ret.end());
        // Replace input.
        arg = std::move(ret);
    }
};

} // namespace

FUZZ_TARGET(txgraph)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    /** Internal test RNG, used only for decisions which would require significant amount of data
     *  to be read from the provider, without realistically impacting test sensitivity. */
    InsecureRandomContext rng(0xdecade2009added + buffer.size());

    /** Variable used whenever an empty TxGraph::Ref is needed. */
    TxGraph::Ref empty_ref;

    // Decide the maximum number of transactions per cluster we will use in this simulation.
    auto max_count = provider.ConsumeIntegralInRange<ClusterIndex>(1, MAX_CLUSTER_COUNT_LIMIT);

    // Construct a real graph, and a vector of simulated graphs (main, and possibly staging).
    auto real = MakeTxGraph(max_count);
    std::vector<SimTxGraph> sims;
    sims.reserve(2);
    sims.emplace_back(max_count);

    /** Function to pick any Ref (in either sim graph, either sim.removed, or empty). */
    auto pick_fn = [&]() noexcept -> TxGraph::Ref& {
        size_t tx_count[2] = {sims[0].GetTransactionCount(), 0};
        /** The number of possible choices. */
        size_t choices = tx_count[0] + sims[0].removed.size() + 1;
        if (sims.size() == 2) {
            tx_count[1] = sims[1].GetTransactionCount();
            choices += tx_count[1] + sims[1].removed.size();
        }
        /** Pick one of them. */
        auto choice = provider.ConsumeIntegralInRange<size_t>(0, choices - 1);
        // Consider both main and (if it exists) staging.
        for (size_t level = 0; level < sims.size(); ++level) {
            auto& sim = sims[level];
            if (choice < tx_count[level]) {
                // Return from graph.
                for (auto i : sim.graph.Positions()) {
                    if (choice == 0) return sim.GetRef(i);
                    --choice;
                }
                assert(false);
            } else {
                choice -= tx_count[level];
            }
            if (choice < sim.removed.size()) {
                // Return from removed.
                return *sim.removed[choice];
            } else {
                choice -= sim.removed.size();
            }
        }
        // Return empty.
        assert(choice == 0);
        return empty_ref;
    };

    /** Function to construct the full diagram for a simulated graph. This works by fetching the
     *  clusters and chunking them manually, so it works for both main and staging
     *  (GetMainChunkFeerate only works for main). */
    auto get_diagram_fn = [&](bool main_only) -> std::vector<FeeFrac> {
        int level = main_only ? 0 : sims.size() - 1;
        auto& sim = sims[level];
        // For every transaction in the graph, request its cluster, and throw them into a set.
        std::set<std::vector<TxGraph::Ref*>> clusters;
        for (auto i : sim.graph.Positions()) {
            auto& ref = sim.GetRef(i);
            clusters.insert(real->GetCluster(ref, main_only));
        }
        // Compute the chunkings of each (deduplicated) cluster.
        size_t num_tx{0};
        std::vector<FeeFrac> ret;
        for (const auto& cluster : clusters) {
            num_tx += cluster.size();
            std::vector<SimTxGraph::Pos> linearization;
            linearization.reserve(cluster.size());
            for (auto refptr : cluster) linearization.push_back(sim.Find(*refptr));
            for (const FeeFrac& chunk_feerate : ChunkLinearization(sim.graph, linearization)) {
                ret.push_back(chunk_feerate);
            }
        }
        // Verify the number of transactions after deduplicating clusters. This implicitly verifies
        // that GetCluster on each element of a cluster reports the cluster transactions in the same
        // order.
        assert(num_tx == sim.GetTransactionCount());
        // Sort by feerate (we don't care about respecting ordering within clusters, as these are
        // just feerates).
        std::sort(ret.begin(), ret.end(), std::greater{});
        return ret;
    };

    LIMITED_WHILE(provider.remaining_bytes() > 0, 200) {
        // Read a one-byte command.
        int command = provider.ConsumeIntegral<uint8_t>();
        // Treat the lowest bit of a command as a flag (which selects a variant of some of the
        // operations), and the second-lowest bit as a way of selecting main vs. staging, and leave
        // the rest of the bits in command.
        bool alt = command & 1;
        bool use_main = command & 2;
        command >>= 2;

        // Provide convenient aliases for the top simulated graph (main, or staging if it exists),
        // one for the simulated graph selected based on use_main (for operations that can operate
        // on both graphs), and one that always refers to the main graph.
        auto& top_sim = sims.back();
        auto& sel_sim = use_main ? sims[0] : top_sim;
        auto& main_sim = sims[0];

        // Keep decrementing command for each applicable operation, until one is hit. Multiple
        // iterations may be necessary.
        while (true) {
            if (top_sim.GetTransactionCount() < SimTxGraph::MAX_TRANSACTIONS && command-- == 0) {
                // AddTransaction.
                auto fee = provider.ConsumeIntegralInRange<int64_t>(-0x8000000000000, 0x7ffffffffffff);
                auto size = provider.ConsumeIntegralInRange<int32_t>(1, 0x3fffff);
                FeeFrac feerate{fee, size};
                // Create a real TxGraph::Ref.
                auto ref = real->AddTransaction(feerate);
                // Create a shared_ptr place in the simulation to put the Ref in.
                auto& ref_loc = top_sim.AddTransaction(feerate);
                // Move it in place.
                ref_loc = std::move(ref);
                break;
            } else if (top_sim.GetTransactionCount() + top_sim.removed.size() > 1 && command-- == 0) {
                // AddDependency.
                auto& par = pick_fn();
                auto& chl = pick_fn();
                auto pos_par = top_sim.Find(par);
                auto pos_chl = top_sim.Find(chl);
                if (pos_par != SimTxGraph::MISSING && pos_chl != SimTxGraph::MISSING) {
                    // Determine if adding this would introduce a cycle (not allowed by TxGraph),
                    // and if so, skip.
                    if (top_sim.graph.Ancestors(pos_par)[pos_chl]) break;
                }
                top_sim.AddDependency(par, chl);
                real->AddDependency(par, chl);
                break;
            } else if (top_sim.removed.size() < 100 && command-- == 0) {
                // RemoveTransaction. Either all its ancestors or all its descendants are also
                // removed (if any), to comply with TxGraph's requirements.
                std::vector<TxGraph::Ref*> to_remove;
                to_remove.push_back(&pick_fn());
                top_sim.IncludeAncDesc(to_remove, alt);
                // The order in which these ancestors/descendants are removed should not matter;
                // randomly shuffle them.
                std::shuffle(to_remove.begin(), to_remove.end(), rng);
                for (TxGraph::Ref* ptr : to_remove) {
                    real->RemoveTransaction(*ptr);
                    top_sim.RemoveTransaction(*ptr);
                }
                break;
            } else if (sel_sim.GetTransactionCount() > 0 && command-- == 0) {
                // SetTransactionFeerate.
                auto fee = provider.ConsumeIntegralInRange<int64_t>(-0x8000000000000, 0x7ffffffffffff);
                auto size = provider.ConsumeIntegralInRange<int32_t>(1, 0x3fffff);
                FeeFrac feerate{fee, size};
                auto& ref = pick_fn();
                real->SetTransactionFeerate(ref, feerate);
                for (auto& sim : sims) {
                    sim.SetTransactionFeerate(ref, feerate);
                }
                break;
            } else if (command-- == 0) {
                // ~Ref.
                std::vector<TxGraph::Ref*> to_destroy;
                to_destroy.push_back(&pick_fn());
                while (true) {
                    // Keep adding either the ancestors or descendants the already picked
                    // transactions have in both graphs (main and staging) combined. Destroying
                    // will trigger deletions in both, so to have consistent TxGraph behavior, the
                    // set must be closed under ancestors, or descendants, in both graphs.
                    auto old_size = to_destroy.size();
                    for (auto& sim : sims) sim.IncludeAncDesc(to_destroy, alt);
                    if (to_destroy.size() == old_size) break;
                }
                // The order in which these ancestors/descendants are destroyed should not matter;
                // randomly shuffle them.
                std::shuffle(to_destroy.begin(), to_destroy.end(), rng);
                for (TxGraph::Ref* ptr : to_destroy) {
                    for (size_t level = 0; level < sims.size(); ++level) {
                        sims[level].DestroyTransaction(*ptr, level == sims.size() - 1);
                    }
                }
                break;
            } else if (command-- == 0) {
                // Cleanup.
                auto cleaned = real->Cleanup();
                if (sims.size() == 1 && !top_sim.IsOversized()) {
                    assert(top_sim.removed.size() == cleaned.size());
                    std::sort(cleaned.begin(), cleaned.end());
                    std::sort(top_sim.removed.begin(), top_sim.removed.end());
                    for (size_t i = 0; i < top_sim.removed.size(); ++i) {
                        assert(cleaned[i] == top_sim.removed[i].get());
                    }
                    top_sim.removed.clear();
                } else {
                    assert(cleaned.empty());
                }
                break;
            } else if (command-- == 0) {
                // GetTransactionCount.
                assert(real->GetTransactionCount(use_main) == sel_sim.GetTransactionCount());
                break;
            } else if (command-- == 0) {
                // Exists.
                auto& ref = pick_fn();
                bool exists = real->Exists(ref, use_main);
                bool should_exist = sel_sim.Find(ref) != SimTxGraph::MISSING;
                assert(exists == should_exist);
                break;
            } else if (command-- == 0) {
                // IsOversized.
                assert(sel_sim.IsOversized() == real->IsOversized(use_main));
                break;
            } else if (command-- == 0) {
                // GetIndividualFeerate.
                auto& ref = pick_fn();
                auto feerate = real->GetIndividualFeerate(ref);
                bool found{false};
                for (auto& sim : sims) {
                    auto simpos = sim.Find(ref);
                    if (simpos != SimTxGraph::MISSING) {
                        found = true;
                        assert(feerate == sim.graph.FeeRate(simpos));
                    }
                }
                if (!found) assert(feerate.IsEmpty());
                break;
            } else if (!main_sim.IsOversized() && command-- == 0) {
                // GetMainChunkFeerate.
                auto& ref = pick_fn();
                auto feerate = real->GetMainChunkFeerate(ref);
                auto simpos = main_sim.Find(ref);
                if (simpos == SimTxGraph::MISSING) {
                    assert(feerate.IsEmpty());
                } else {
                    // Just do some quick checks that the reported value is in range. A full
                    // recomputation of expected chunk feerates is done at the end.
                    assert(feerate.size >= main_sim.graph.FeeRate(simpos).size);
                    assert(feerate.size <= main_sim.SumAll().size);
                }
                break;
            } else if (!sel_sim.IsOversized() && command-- == 0) {
                // GetAncestors/GetDescendants.
                auto& ref = pick_fn();
                auto result = alt ? real->GetDescendants(ref, use_main)
                                  : real->GetAncestors(ref, use_main);
                assert(result.size() <= max_count);
                auto result_set = sel_sim.MakeSet(result);
                assert(result.size() == result_set.Count());
                auto expect_set = sel_sim.GetAncDesc(ref, alt);
                assert(result_set == expect_set);
                break;
            } else if (!sel_sim.IsOversized() && command-- == 0) {
                // GetCluster.
                auto& ref = pick_fn();
                auto result = real->GetCluster(ref, use_main);
                // Check cluster count limit.
                assert(result.size() <= max_count);
                // Require the result to be topologically valid and not contain duplicates.
                auto left = sel_sim.graph.Positions();
                for (auto refptr : result) {
                    auto simpos = sel_sim.Find(*refptr);
                    assert(simpos != SimTxGraph::MISSING);
                    assert(left[simpos]);
                    left.Reset(simpos);
                    assert(!sel_sim.graph.Ancestors(simpos).Overlaps(left));
                }
                // Require the set to be connected.
                auto result_set = sel_sim.MakeSet(result);
                assert(sel_sim.graph.IsConnected(result_set));
                // If ref exists, the result must contain it. If not, it must be empty.
                auto simpos = sel_sim.Find(ref);
                if (simpos != SimTxGraph::MISSING) {
                    assert(result_set[simpos]);
                } else {
                    assert(result_set.None());
                }
                // Require the set not to have ancestors or descendants outside of it.
                for (auto i : result_set) {
                    assert(sel_sim.graph.Ancestors(i).IsSubsetOf(result_set));
                    assert(sel_sim.graph.Descendants(i).IsSubsetOf(result_set));
                }
                break;
            } else if (command-- == 0) {
                // HaveStaging.
                assert((sims.size() == 2) == real->HaveStaging());
                break;
            } else if (sims.size() < 2 && command-- == 0) {
                // StartStaging.
                sims.emplace_back(sims.back());
                real->StartStaging();
                break;
            } else if (sims.size() > 1 && command-- == 0) {
                // AbortStaging/CommitStaging.
                if (alt) {
                    real->AbortStaging();
                    sims.pop_back();
                    // Reset the cached oversized value (if TxGraph::Ref destructions triggered
                    // removals of main transactions while staging was active, then aborting will
                    // cause it to be re-evaluated in TxGraph).
                    sims.back().oversized = std::nullopt;
                } else {
                    real->CommitStaging();
                    sims.erase(sims.begin());
                }
                break;
            } else if (main_sim.GetTransactionCount() > 0 && !main_sim.IsOversized() && command-- == 0) {
                // CompareMainOrder.
                auto& ref_a = pick_fn();
                auto& ref_b = pick_fn();
                auto sim_a = main_sim.Find(ref_a);
                auto sim_b = main_sim.Find(ref_b);
                // Both transactions must exist in the main graph.
                if (sim_a == SimTxGraph::MISSING || sim_b == SimTxGraph::MISSING) break;
                auto cmp = real->CompareMainOrder(ref_a, ref_b);
                // Distinct transactions have distinct places.
                if (sim_a != sim_b) assert(cmp != 0);
                // Ancestors go before descendants.
                if (main_sim.graph.Ancestors(sim_a)[sim_b]) assert(cmp >= 0);
                if (main_sim.graph.Descendants(sim_a)[sim_b]) assert(cmp <= 0);
                // Do not verify consistency with chunk feerates, as we cannot easily determine
                // these here without making more calls to real, which could affect its internal
                // state. A full comparison is done at the end.
                break;
            } else if (sims.size() == 2 && !sims[0].IsOversized() && !sims[1].IsOversized() && command-- == 0) {
                // GetMainStagingDiagrams()
                auto [main_diagram, staged_diagram] = real->GetMainStagingDiagrams();
                auto sum_main = std::accumulate(main_diagram.begin(), main_diagram.end(), FeeFrac{});
                auto sum_staged = std::accumulate(staged_diagram.begin(), staged_diagram.end(), FeeFrac{});
                auto diagram_gain = sum_staged - sum_main;
                auto real_gain = sims[1].SumAll() - sims[0].SumAll();
                // Just check that the total fee gained/lost and size gained/lost according to the
                // diagram matches the difference in these values in the simulated graph. A more
                // complete check of the GetMainStagingDiagrams result is performed at the end.
                assert(diagram_gain == real_gain);
                // Check that the feerates in each diagram are monotonically decreasing.
                for (size_t i = 1; i < main_diagram.size(); ++i) {
                    assert(FeeRateCompare(main_diagram[i], main_diagram[i - 1]) <= 0);
                }
                for (size_t i = 1; i < staged_diagram.size(); ++i) {
                    assert(FeeRateCompare(staged_diagram[i], staged_diagram[i - 1]) <= 0);
                }
                break;
            } else if (!main_sim.IsOversized() && command-- == 0) {
                // GetBlockBuilder.
                uint8_t frac = provider.ConsumeIntegral<uint8_t>();
                auto builder = real->GetBlockBuilder();
                SimTxGraph::SetType done;
                FeeFrac prev_chunk_feerate;
                while (*builder) {
                    // Chunk feerates must be monotonously decreasing.
                    if (!prev_chunk_feerate.IsEmpty()) {
                        assert(FeeRateCompare(builder->GetCurrentChunkFeerate(), prev_chunk_feerate) <= 0);
                    }
                    prev_chunk_feerate = builder->GetCurrentChunkFeerate();
                    // Only include a fraction of frac/255 out of all chunks.
                    if (rng.randrange(255) <= frac) {
                        FeeFrac sum_feerate;
                        for (TxGraph::Ref* ref : builder->GetCurrentChunk()) {
                            // Each transaction in the chunk must exist in the main graph.
                            auto simpos = main_sim.Find(*ref);
                            assert(simpos != SimTxGraph::MISSING);
                            // Verify the claimed chunk feerate.
                            sum_feerate += main_sim.graph.FeeRate(simpos);
                            // Make sure the chunk contains no duplicate transactions.
                            assert(!done[simpos]);
                            done.Set(simpos);
                            // The concatenation of all included chunks, in order, must be
                            // topologically valid.
                            assert(main_sim.graph.Ancestors(simpos).IsSubsetOf(done));
                        }
                        assert(sum_feerate == builder->GetCurrentChunkFeerate());
                        builder->Include();
                    } else {
                        builder->Skip();
                    }
                }
                break;
            } else if (/*sims.size() == 1 &&*/ !main_sim.IsOversized() && command-- == 0) {
                // GetEvictor.
                auto num_to_evict = provider.ConsumeIntegralInRange<int32_t>(0, main_sim.GetTransactionCount());
                auto evictor = real->GetEvictor();
                SimTxGraph::SetType done;
                FeeFrac prev_chunk_feerate;
                while (*evictor && num_to_evict >= 0) {
                    // Chunk feerates must be monotonously increasing.
                    if (!prev_chunk_feerate.IsEmpty()) {
                        assert(FeeRateCompare(evictor->GetCurrentChunkFeerate(), prev_chunk_feerate) >= 0);
                    }
                    prev_chunk_feerate = evictor->GetCurrentChunkFeerate();
                    FeeFrac sum_feerate;
                    for (TxGraph::Ref* ref : evictor->GetCurrentChunk()) {
                        // Each transaction in the chunk must exist in the main graph.
                        auto simpos = main_sim.Find(*ref);
                        assert(simpos != SimTxGraph::MISSING);
                        // Verify the claimed chunk feerate.
                        sum_feerate += main_sim.graph.FeeRate(simpos);
                        // Make sure the chunk contains no duplicate transactions.
                        assert(!done[simpos]);
                        done.Set(simpos);
                        // The concatenation of all reported transaction, in order, must be
                        // anti-topologically valid (all children before parents).
                        assert(main_sim.graph.Descendants(simpos).IsSubsetOf(done));
                        if (num_to_evict > 0) {
                            // Before destroying Ref, also remove any descendants it may have in
                            // staging, so that dependencies are consistent.
                            if (sims.size() == 2) {
                                auto stage_simpos = top_sim.Find(*ref);
                                if (stage_simpos != SimTxGraph::MISSING) {
                                    for (auto desc : top_sim.graph.Descendants(stage_simpos)) {
                                        auto& desc_ref = top_sim.GetRef(desc);
                                        top_sim.RemoveTransaction(desc_ref);
                                        real->RemoveTransaction(desc_ref);
                                    }
                                }
                            }
                            // Destroy the Ref for both sims.
                            for (auto& sim : sims) sim.DestroyTransaction(*ref, true);
                            --num_to_evict;
                        }
                    }
                    assert(sum_feerate == evictor->GetCurrentChunkFeerate());
                    evictor->Next();
                }
                break;
            }
        }
    }

    // After running all modifications, perform an internal sanity check (before invoking
    // inspectors that may modify the internal state).
    real->SanityCheck();

    if (!sims[0].IsOversized()) {
        // If the main graph is not oversized, verify the total ordering implied by
        // CompareMainOrder.
        // First construct two distinct randomized permutations of the positions in sims[0].
        std::vector<SimTxGraph::Pos> vec1;
        for (auto i : sims[0].graph.Positions()) vec1.push_back(i);
        std::shuffle(vec1.begin(), vec1.end(), rng);
        auto vec2 = vec1;
        std::shuffle(vec2.begin(), vec2.end(), rng);
        if (vec1 == vec2) std::next_permutation(vec2.begin(), vec2.end());
        // Sort both according to CompareMainOrder. By having randomized starting points, the order
        // of CompareMainOrder invocations is somewhat randomized as well.
        auto cmp = [&](SimTxGraph::Pos a, SimTxGraph::Pos b) noexcept {
            return real->CompareMainOrder(sims[0].GetRef(a), sims[0].GetRef(b)) < 0;
        };
        std::sort(vec1.begin(), vec1.end(), cmp);
        std::sort(vec2.begin(), vec2.end(), cmp);

        // Verify the resulting orderings are identical. This could only fail if the ordering was
        // not total.
        assert(vec1 == vec2);

        // Verify that the ordering is topological.
        auto todo = sims[0].graph.Positions();
        for (auto i : vec1) {
            todo.Reset(i);
            assert(!sims[0].graph.Ancestors(i).Overlaps(todo));
        }
        assert(todo.None());

        // For every transaction in the total ordering, find a random one before it and after it,
        // and compare their chunk feerates, which must be consistent with the ordering.
        for (size_t pos = 0; pos < vec1.size(); ++pos) {
            auto pos_feerate = real->GetMainChunkFeerate(sims[0].GetRef(vec1[pos]));
            if (pos > 0) {
                size_t before = rng.randrange<size_t>(pos);
                auto before_feerate = real->GetMainChunkFeerate(sims[0].GetRef(vec1[before]));
                assert(FeeRateCompare(before_feerate, pos_feerate) >= 0);
            }
            if (pos + 1 < vec1.size()) {
                size_t after = pos + 1 + rng.randrange<size_t>(vec1.size() - 1 - pos);
                auto after_feerate = real->GetMainChunkFeerate(sims[0].GetRef(vec1[after]));
                assert(FeeRateCompare(after_feerate, pos_feerate) <= 0);
            }
        }

        // The same order should be obtained through a BlockBuilder, if nothing is skipped.
        auto builder = real->GetBlockBuilder();
        std::vector<SimTxGraph::Pos> vec_builder;
        while (*builder) {
            FeeFrac sum;
            for (TxGraph::Ref* ref : builder->GetCurrentChunk()) {
                // The reported chunk feerate must match the chunk feerate obtained by asking
                // it for each of the chunk's transactions individually.
                assert(real->GetMainChunkFeerate(*ref) == builder->GetCurrentChunkFeerate());
                // Verify the chunk feerate matches the sum of the reported individual feerates.
                sum += real->GetIndividualFeerate(*ref);
                // Chunks must contain transactions that exist in the graph.
                auto simpos = sims[0].Find(*ref);
                assert(simpos != SimTxGraph::MISSING);
                vec_builder.push_back(simpos);
            }
            assert(sum == builder->GetCurrentChunkFeerate());
            builder->Include();
        }
        assert(vec_builder == vec1);
        builder.reset();

        // The reverse order should be obtained through an Evictor, if nothing is destroyed.
        auto evictor = real->GetEvictor();
        std::vector<SimTxGraph::Pos> vec_evictor;
        while (*evictor) {
            FeeFrac sum;
            for (TxGraph::Ref* ref : evictor->GetCurrentChunk()) {
                // The reported chunk feerate must match the chunk feerate obtained by asking
                // it for each of the chunk's transactions individually.
                assert(real->GetMainChunkFeerate(*ref) == evictor->GetCurrentChunkFeerate());
                // Verify the chunk feerate matches the sum of the reported individual feerates.
                sum += real->GetIndividualFeerate(*ref);
                // Chunks must contain transactions that exist in the graph.
                auto simpos = sims[0].Find(*ref);
                assert(simpos != SimTxGraph::MISSING);
                vec_evictor.push_back(simpos);
            }
            assert(sum == evictor->GetCurrentChunkFeerate());
            evictor->Next();
        }
        std::reverse(vec_evictor.begin(), vec_evictor.end());
        assert(vec_evictor == vec1);
        evictor.reset();

        // Check that the implied ordering gives rise to a combined diagram that matches the
        // diagram constructed from the individual cluster linearization chunkings.
        auto main_diagram = get_diagram_fn(true);
        auto expected_main_diagram = ChunkLinearization(sims[0].graph, vec1);
        assert(CompareChunks(main_diagram, expected_main_diagram) == 0);

        if (sims.size() >= 2 && !sims[1].IsOversized()) {
            // When the staging graph is not oversized as well, call GetMainStagingDiagrams, and
            // fully verify the result.
            auto [main_cmp_diagram, stage_cmp_diagram] = real->GetMainStagingDiagrams();
            // Check that the feerates in each diagram are monotonically decreasing.
            for (size_t i = 1; i < main_cmp_diagram.size(); ++i) {
                assert(FeeRateCompare(main_cmp_diagram[i], main_cmp_diagram[i - 1]) <= 0);
            }
            for (size_t i = 1; i < stage_cmp_diagram.size(); ++i) {
                assert(FeeRateCompare(stage_cmp_diagram[i], stage_cmp_diagram[i - 1]) <= 0);
            }
            // Apply total ordering on the feerate diagrams to make them comparable (the exact
            // tie breaker among equal-feerate FeeFracs does not matter, but it has to be
            // consistent with the one used in main_diagram and stage_diagram).
            std::sort(main_cmp_diagram.begin(), main_cmp_diagram.end(), std::greater{});
            std::sort(stage_cmp_diagram.begin(), stage_cmp_diagram.end(), std::greater{});
            // Find the chunks that appear in main_diagram but are missing from main_cmp_diagram.
            // This is allowed, because GetMainStagingDiagrams omits clusters in main unaffected
            // by staging.
            std::vector<FeeFrac> missing_main_cmp;
            std::set_difference(main_diagram.begin(), main_diagram.end(),
                                main_cmp_diagram.begin(), main_cmp_diagram.end(),
                                std::inserter(missing_main_cmp, missing_main_cmp.end()),
                                std::greater{});
            assert(main_cmp_diagram.size() + missing_main_cmp.size() == main_diagram.size());
            // Do the same for chunks in stage_diagram missign from stage_cmp_diagram.
            auto stage_diagram = get_diagram_fn(false);
            std::vector<FeeFrac> missing_stage_cmp;
            std::set_difference(stage_diagram.begin(), stage_diagram.end(),
                                stage_cmp_diagram.begin(), stage_cmp_diagram.end(),
                                std::inserter(missing_stage_cmp, missing_stage_cmp.end()),
                                std::greater{});
            assert(stage_cmp_diagram.size() + missing_stage_cmp.size() == stage_diagram.size());
            // The missing chunks must be equal across main & staging (otherwise they couldn't have
            // been omitted).
            assert(missing_main_cmp == missing_stage_cmp);
        }
    }

    assert(real->HaveStaging() == (sims.size() > 1));

    // Try to run a full comparison, for both main_only=false and main_only=true in TxGraph
    // inspector functions that support both.
    for (int main_only = 0; main_only < 2; ++main_only) {
        auto& sim = main_only ? sims[0] : sims.back();
        // Compare simple properties of the graph with the simulation.
        assert(real->IsOversized(main_only) == sim.IsOversized());
        assert(real->GetTransactionCount(main_only) == sim.GetTransactionCount());
        // If the graph (and the simulation) are not oversized, perform a full comparison.
        if (!sim.IsOversized()) {
            auto todo = sim.graph.Positions();
            // Iterate over all connected components of the resulting (simulated) graph, each of which
            // should correspond to a cluster in the real one.
            while (todo.Any()) {
                auto component = sim.graph.FindConnectedComponent(todo);
                todo -= component;
                // Iterate over the transactions in that component.
                for (auto i : component) {
                    // Check its individual feerate against simulation.
                    assert(sim.graph.FeeRate(i) == real->GetIndividualFeerate(sim.GetRef(i)));
                    // Check its ancestors against simulation.
                    auto expect_anc = sim.graph.Ancestors(i);
                    auto anc = sim.MakeSet(real->GetAncestors(sim.GetRef(i), main_only));
                    assert(anc.Count() <= max_count);
                    assert(anc == expect_anc);
                    // Check its descendants against simulation.
                    auto expect_desc = sim.graph.Descendants(i);
                    auto desc = sim.MakeSet(real->GetDescendants(sim.GetRef(i), main_only));
                    assert(desc.Count() <= max_count);
                    assert(desc == expect_desc);
                    // Check the cluster the transaction is part of.
                    auto cluster = real->GetCluster(sim.GetRef(i), main_only);
                    assert(cluster.size() <= max_count);
                    assert(sim.MakeSet(cluster) == component);
                    // Check that the cluster is reported in a valid topological order (its
                    // linearization).
                    std::vector<ClusterIndex> simlin;
                    SimTxGraph::SetType done;
                    for (TxGraph::Ref* ptr : cluster) {
                        auto simpos = sim.Find(*ptr);
                        done.Set(simpos);
                        assert(sim.graph.Ancestors(simpos).IsSubsetOf(done));
                        simlin.push_back(simpos);
                    }
                    // Construct a chunking object for the simulated graph, using the reported cluster
                    // linearization as ordering, and compare it against the reported chunk feerates.
                    if (sims.size() == 1 || main_only) {
                        cluster_linearize::LinearizationChunking simlinchunk(sim.graph, simlin);
                        ClusterIndex idx{0};
                        for (unsigned chunknum = 0; chunknum < simlinchunk.NumChunksLeft(); ++chunknum) {
                            auto chunk = simlinchunk.GetChunk(chunknum);
                            // Require that the chunks of cluster linearizations are connected (this must
                            // be the case as all linearizations inside are PostLinearized).
                            assert(sim.graph.IsConnected(chunk.transactions));
                            // Check the chunk feerates of all transactions in the cluster.
                            while (chunk.transactions.Any()) {
                                assert(chunk.transactions[simlin[idx]]);
                                chunk.transactions.Reset(simlin[idx]);
                                assert(chunk.feerate == real->GetMainChunkFeerate(*cluster[idx]));
                                ++idx;
                            }
                        }
                    }
                }
            }
        }
    }

    // Sanity check again (because invoking inspectors may modify internal unobservable state).
    real->SanityCheck();
}
