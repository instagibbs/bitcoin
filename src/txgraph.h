// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compare>
#include <stdint.h>
#include <memory>
#include <vector>

#include <util/feefrac.h>

#ifndef BITCOIN_TXGRAPH_H
#define BITCOIN_TXGRAPH_H

/** No connected component within TxGraph is allowed to exceed this number of transactions. */
static constexpr unsigned CLUSTER_COUNT_LIMIT{64};

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
        /** Destroy this Ref. This is only allowed when it is empty, or the transaction it refers
         *  to has been removed from the graph. */
        virtual ~Ref();
        // Support moving a Ref.
        Ref& operator=(Ref&& other) noexcept;
        Ref(Ref&& other) noexcept;
        // Do not permit copy constructing or copy assignment. A TxGraph entry can have at most one
        // Ref pointing to it.
        Ref& operator=(const Ref&) = delete;
        Ref(const Ref&) = delete;
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
    /** Construct a new transaction with the specified feerate, and return a Ref to it. */
    [[nodiscard]] virtual Ref AddTransaction(const FeeFrac& feerate) noexcept = 0;
    /** Remove the specified transaction. This is a no-op if the transaction was already removed.
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
    /** Add a dependency between two specified transactions. Parent may not be a descendant of
     *  child already (but may be an ancestor of it already, in which case this is a no-op). If
     *  either transaction is already removed, this is a no-op. */
    virtual void AddDependency(const Ref& parent, const Ref& child) noexcept = 0;
    /** Modify the fee of the specified transaction. If the transaction does not exist (or was
     *  removed), this has no effect. */
    virtual void SetTransactionFee(const Ref& arg, int64_t fee) noexcept = 0;

    /** Determine whether arg exists in this graph (i.e., was not removed). */
    virtual bool Exists(const Ref& arg) noexcept = 0;
    /** Get the feerate of the chunk which transaction arg is in. Returns the empty FeeFrac if arg
     *  does not exist. */
    virtual FeeFrac GetChunkFeerate(const Ref& arg) noexcept = 0;
    /** Get the individual transaction feerate of transaction arg. Returns the empty FeeFrac if
     *  arg does not exist. */
    virtual FeeFrac GetIndividualFeerate(const Ref& arg) noexcept = 0;
    /** Get pointers to all transactions in the connected component ("cluster") which arg is in.
     *  The transactions will be returned in a topologically-valid order of acceptable quality.
     *  Returns {} if arg does not exist in the queried graph. */
    virtual std::vector<Ref*> GetCluster(const Ref& arg) noexcept = 0;
    /** Get pointers to all ancestors of the specified transaction. Returns {} if arg does not
     *  exist. */
    virtual std::vector<Ref*> GetAncestors(const Ref& arg) noexcept = 0;
    /** Get pointers to all descendants of the specified transaction. Returns {} if arg does not
     *  exist in the graph. */
    virtual std::vector<Ref*> GetDescendants(const Ref& arg) noexcept = 0;
    /** Get the total number of transactions in the graph. */
    virtual GraphIndex GetTransactionCount() noexcept = 0;

    /** Perform an internal consistency check on this object. */
    virtual void SanityCheck() const = 0;
};

/** Construct a new TxGraph. */
std::unique_ptr<TxGraph> MakeTxGraph() noexcept;

#endif // BITCOIN_TXGRAPH_H
