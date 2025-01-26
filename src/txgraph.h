// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compare>
#include <memory>
#include <optional>
#include <stdint.h>
#include <vector>
#include <utility>

#include <util/feefrac.h>

#ifndef BITCOIN_TXGRAPH_H
#define BITCOIN_TXGRAPH_H

static constexpr unsigned MAX_CLUSTER_COUNT_LIMIT{64};

/** Data structure to encapsulate fees, sizes, and dependencies for a set of transactions. */
class TxGraph
{
public:
    /** Internal identifier for a transaction within a TxGraph. */
    using GraphIndex = uint32_t;

    /** Data type used to reference transactions within a TxGraph.
     *
     * Every transaction within a TxGraph has exactly one corresponding TxGraph::Ref, held by users
     * of the class. Destroying the TxGraph::Ref removes the corresponding transaction.
     *
     * Users of the class can inherit from TxGraph::Ref. If all Refs are inherited this way, the
     * Ref* pointers returned by TxGraph functions can be used as this inherited type.
     */
    class Ref
    {
        // Allow TxGraph's GetRefGraph and GetRefIndex to access internals.
        friend class TxGraph;
        /** Which Graph the Entry lives in. nullptr if this Ref is empty. */
        TxGraph* m_graph = nullptr;
        /** Index into the Graph's m_entries. Only used if m_graph != nullptr. */
        GraphIndex m_index = GraphIndex(-1);
    public:
        /** Construct an empty Ref. Non-empty Refs can only be created using
         *  TxGraph::AddTransaction. */
        Ref() noexcept = default;
        /** Destroy this Ref. If it is not empty, the corresponding transaction is removed (in both
         *  main and staging, if it exists). */
        virtual ~Ref();
        // Support moving a Ref.
        Ref& operator=(Ref&& other) noexcept;
        Ref(Ref&& other) noexcept;
        // Do not permit copy constructing or copy assignment. A TxGraph entry can have at most one
        // Ref pointing to it.
        Ref& operator=(const Ref&) = delete;
        Ref(const Ref&) = delete;
    };

    /** Interface returned by GetBlockBuilder. */
    class BlockBuilder
    {
    protected:
        /** The next chunk, in topological order plus feerate, or std::nullopt if done. */
        std::optional<std::pair<std::span<Ref*>, FeeFrac>> m_current_chunk;
        /** Make constructor non-public (use TxGraph::GetBlockBuilder()). */
        BlockBuilder() noexcept = default;
    public:
        /** Support safe inheritance. */
        virtual ~BlockBuilder() = default;
        /** Determine whether there are more transactions to be included. */
        explicit operator bool() noexcept { return m_current_chunk.has_value(); }
        /** Get the chunk that is currently suggested to be included. */
        const std::span<Ref*>& GetCurrentChunk() noexcept { return m_current_chunk->first; }
        /** Get the feerate of the currently suggested chunk. */
        const FeeFrac& GetCurrentChunkFeerate() noexcept { return m_current_chunk->second; }
        /** Mark the current chunk as included, and progress to the next one. */
        virtual void Include() noexcept = 0;
        /** Mark the current chunk as skipped, and progress to the next one. */
        virtual void Skip() noexcept = 0;
    };

protected:
    // Allow TxGraph::Ref to call UpdateRef and UnlinkRef.
    friend class TxGraph::Ref;
    /** Inform the TxGraph implementation that a TxGraph::Ref has moved. */
    virtual void UpdateRef(GraphIndex index, Ref& new_location) noexcept = 0;
    /** Inform the TxGraph implementation that a TxGraph::Ref was destroyed. */
    virtual void UnlinkRef(GraphIndex index) noexcept = 0;
    // Allow TxGraph implementations (inheriting from it) to access Ref internals.
    static TxGraph*& GetRefGraph(Ref& arg) noexcept { return arg.m_graph; }
    static TxGraph* GetRefGraph(const Ref& arg) noexcept { return arg.m_graph; }
    static GraphIndex& GetRefIndex(Ref& arg) noexcept { return arg.m_index; }
    static GraphIndex GetRefIndex(const Ref& arg) noexcept { return arg.m_index; }

public:
    /** Virtual destructor, so inheriting is safe. */
    virtual ~TxGraph() = default;
    /** Construct a new transaction with the specified feerate, and return a Ref to it.
     *  If a staging graph exists, the new transaction is only created there. */
    [[nodiscard]] virtual Ref AddTransaction(const FeeFrac& feerate) noexcept = 0;
    /** Remove the specified transaction. If a staging graph exists, the removal only happens
     *  there. This is a no-op if the transaction was already removed.
     *
     * TxGraph may internally reorder transaction removals with dependency additions for
     * performance reasons. If together with any transaction removal all its descendants, or all
     * its ancestors, are removed as well (which is what always happens in realistic scenarios),
     * this reordering will not affect the behavior of TxGraph.
     *
     * As an example, imagine 3 transactions A,B,C where B depends on A. If a dependency of C on B
     * is added, and then B is deleted, C will still depend on A. If the deletion of B is reordered
     * before the C->B dependency is added, it has no effect instead. If, together with the
     * deletion of B also either A or C is deleted, there is no distinction.
     */
    virtual void RemoveTransaction(const Ref& arg) noexcept = 0;
    /** Add a dependency between two specified transactions. If a staging graph exists, the
     *  dependency is only added there. Parent may not be a descendant of child already (but may
     *  be an ancestor of it already, in which case this is a no-op). If either transaction is
     *  already removed, this is a no-op. */
    virtual void AddDependency(const Ref& parent, const Ref& child) noexcept = 0;
    /** Modify the fee of the specified transaction, in both the main graph and the staging
     *  graph if it exists. Wherever the transaction does not exist (or was removed), this has no
     *  effect. */
    virtual void SetTransactionFee(const Ref& arg, int64_t fee) noexcept = 0;

    /** TxGraph is internally lazy, and will not compute many things until they are needed.
     *  Calling DoWork will compute everything now, so that future operations are fast. This can be
     *  invoked while oversized. */
    virtual void DoWork() noexcept = 0;

    /** Create a staging graph (which cannot exist already). This acts as if a full copy of
     *  the transaction graph is made, upon which further modifications are made. This copy can
     *  be inspected, and then either discarded, or the main graph can be replaced by it by
     *  commiting it. */
    virtual void StartStaging() noexcept = 0;
    /** Discard the existing active staging graph (which must exist). */
    virtual void AbortStaging() noexcept = 0;
    /** Replace the main graph with the staging graph (which must exist). */
    virtual void CommitStaging() noexcept = 0;
    /** Check whether a staging graph exists. */
    virtual bool HaveStaging() const noexcept = 0;

    /** Determine whether arg exists in the graph (i.e., was not removed). If main_only is false
     *  and a staging graph exists, it is queried; otherwise the main graph is queried. */
    virtual bool Exists(const Ref& arg, bool main_only = false) noexcept = 0;
    /** Determine whether the graph is oversized (contains a connected component of more than the
     *  configured maximum cluster count). If main_only is false and a staging graph exists, it is
     *  queried; otherwise the main graph is queried. Some of the functions below are not available
     *  for oversized graphs. The mutators above are always available. Removing a transaction by
     *  destroying its Ref while staging exists will not clear main's oversizedness until staging
     *  is aborted or committed. */
    virtual bool IsOversized(bool main_only = false) noexcept = 0;
    /** Get the feerate of the chunk which transaction arg is in the main graph. Returns the empty
     *  FeeFrac if arg does not exist in the main graph. The main graph must not be oversized. */
    virtual FeeFrac GetMainChunkFeerate(const Ref& arg) noexcept = 0;
    /** Get the individual transaction feerate of transaction arg. Returns the empty FeeFrac if
     *  arg does not exist in either main or staging. This is available even for oversized
     *  graphs. */
    virtual FeeFrac GetIndividualFeerate(const Ref& arg) noexcept = 0;
    /** Get pointers to all transactions in the connected component ("cluster") which arg is in.
     *  The transactions will be returned in a topologically-valid order of acceptable quality.
     *  If main_only is false and a staging graph exists, it is queried; otherwise the main graph
     *  is queried. The queried graph must not be oversized. Returns {} if arg does not exist in
     *  the queried graph. */
    virtual std::vector<Ref*> GetCluster(const Ref& arg, bool main_only = false) noexcept = 0;
    /** Get pointers to all ancestors of the specified transaction. If main_only is false and a
     *  staging graph exists, it is queried; otherwise the main graph is queried. The queried
     *  graph must not be oversized. Returns {} if arg does not exist in the queried graph. */
    virtual std::vector<Ref*> GetAncestors(const Ref& arg, bool main_only = false) noexcept = 0;
    /** Get pointers to all descendants of the specified transaction. If main_only is false and a
     *  staging graph exists, it is queried; otherwise the main graph is queried. The queried
     *  graph must not be oversized. Returns {} if arg does not exist in the queried graph. */
    virtual std::vector<Ref*> GetDescendants(const Ref& arg, bool main_only = false) noexcept = 0;
    /** Get the total number of transactions in the graph. If main_only is false and a staging
     *  graph exists, it is queried; otherwise the main graph is queried. This is available even
     *  for oversized graphs. */
    virtual GraphIndex GetTransactionCount(bool main_only = false) noexcept = 0;
    /** Compare two transactions according to the total order in the main graph (topological, and
     *  from high to low chunk feerate). Both transactions must be in the main graph. The main
     *  graph must not be oversized. */
    virtual std::strong_ordering CompareMainOrder(const Ref& a, const Ref& b) noexcept = 0;
    /** Count the number of distinct clusters that the specified transactions belong to. If
     *  main_only is false and a staging graph exists, staging clusters are counted. Otherwise,
     *  main clusters are counted. Refs that do not exist in the graph are not counted. The
     *  queried graph must not be oversized. */
    virtual GraphIndex CountDistinctClusters(std::span<const Ref* const>, bool main_only = false) noexcept = 0;
    /** Get feerate diagrams (comparable using CompareChunks()) for both main and staging (which
     *  must both exist and not be oversized), ignoring unmodified components in both. */
    virtual std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>> GetMainStagingDiagrams() noexcept = 0;

    /** Construct a block builder, drawing from the main graph, which cannot be oversized. While
     *  the returned object exists, no mutators on the main graph are allowed. */
    virtual std::unique_ptr<BlockBuilder> GetBlockBuilder() noexcept = 0;
    /** Get the worst chunk overall in the main graph, i.e., the last chunk that would be returned
     *  by a BlockBuilder created now. The chunk is returned in reversed order, so every element is
     *  preceded by all its descendants. If the graph is empty, {} is returned. */
    virtual std::pair<std::vector<Ref*>, FeeFrac> GetWorstMainChunk() noexcept = 0;

    /** Perform an internal consistency check on this object. */
    virtual void SanityCheck() const = 0;
};

/** Construct a new TxGraph with the specified limit on transactions within a cluster. That
 *  number cannot exceed MAX_CLUSTER_COUNT_LIMIT. */
std::unique_ptr<TxGraph> MakeTxGraph(unsigned max_cluster_count) noexcept;

#endif // BITCOIN_TXGRAPH_H
