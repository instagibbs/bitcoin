// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <net.h>
#include <node/txorphanage.h>
#include <policy/packages.h>
#include <protocol.h>

#include <cstdint>
#include <memory>

class CBlock;
class CRollingBloomFilter;
class CTxMemPool;
class GenTxid;
class TxRequestTracker;
struct MempoolAcceptResult;
struct PackageMempoolAcceptResult;
namespace node {
class TxDownloadManagerImpl;

/** Maximum number of in-flight transaction requests from a peer. It is not a hard limit, but the threshold at which
 *  point the OVERLOADED_PEER_TX_DELAY kicks in. */
inline constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100;
/** Maximum number of transactions to consider for requesting, per peer. It provides a reasonable DoS limit to
 *  per-peer memory usage spent on announcements, while covering peers continuously sending INVs at the maximum
 *  rate (by our own policy, see DEFAULT_TX_SEND_RATE) for several minutes, while not receiving
 *  the actual transaction (from any peer) in response to requests for them. */
inline constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 5000;
/** Maximum number of packages announced with pkginv to consider for requesting, per peer. Lower than
 *  MAX_PEER_TX_ANNOUNCEMENTS: a peer announces only some of its transactions in packages, and each
 *  package announcement takes about three times the memory of a transaction announcement. */
inline constexpr int32_t MAX_PEER_PKG_ANNOUNCEMENTS = 1000;
/** How long to delay requesting transactions via txids, if we have wtxid-relaying peers */
inline constexpr auto TXID_RELAY_DELAY{2s};
/** How long to delay requesting transactions from non-preferred peers */
inline constexpr auto NONPREF_PEER_TX_DELAY{2s};
/** How long to delay requesting transactions from overloaded peers (see MAX_PEER_TX_REQUEST_IN_FLIGHT). */
inline constexpr auto OVERLOADED_PEER_TX_DELAY{2s};
/** How long to wait before downloading a transaction from an additional peer */
inline constexpr auto GETDATA_TX_INTERVAL{60s};
struct TxDownloadOptions {
    /** Read-only reference to mempool. */
    const CTxMemPool& m_mempool;
    /** Instantiate TxRequestTracker as deterministic (used for tests). */
    bool m_deterministic_txrequest{false};
};
struct TxDownloadConnectionInfo {
    /** Whether this peer is preferred for transaction download. */
    const bool m_preferred;
    /** Whether this peer has Relay permissions. */
    const bool m_relay_permissions;
    /** Whether this peer supports wtxid relay. */
    const bool m_wtxid_relay;
};
struct PackageToValidate {
    Package m_txns;
    std::vector<NodeId> m_senders;
    /** Construct a 1-parent-1-child package. */
    explicit PackageToValidate(const CTransactionRef& parent,
                               const CTransactionRef& child,
                               NodeId parent_sender,
                               NodeId child_sender) :
        m_txns{parent, child},
        m_senders{parent_sender, child_sender}
    {}

    // Move ctor
    PackageToValidate(PackageToValidate&& other) : m_txns{std::move(other.m_txns)}, m_senders{std::move(other.m_senders)} {}
    // Copy ctor
    PackageToValidate(const PackageToValidate& other) = default;

    // Move assignment
    PackageToValidate& operator=(PackageToValidate&& other) {
        this->m_txns = std::move(other.m_txns);
        this->m_senders = std::move(other.m_senders);
        return *this;
    }

    std::string ToString() const {
        Assume(m_txns.size() == 2);
        return strprintf("parent %s (wtxid=%s, sender=%d) + child %s (wtxid=%s, sender=%d)",
                         m_txns.front()->GetHash().ToString(),
                         m_txns.front()->GetWitnessHash().ToString(),
                         m_senders.front(),
                         m_txns.back()->GetHash().ToString(),
                         m_txns.back()->GetWitnessHash().ToString(),
                         m_senders.back());
    }
};
struct RejectedTxTodo
{
    bool m_should_add_extra_compact_tx;
    std::vector<Txid> m_unique_parents;
    std::optional<PackageToValidate> m_package_to_validate;
};


/**
 * Class responsible for deciding what transactions to request and, once
 * downloaded, whether and how to validate them. It is also responsible for
 * deciding what transaction packages to validate and how to resolve orphan
 * transactions. Its data structures include TxRequestTracker for scheduling
 * requests, rolling bloom filters for remembering transactions that have
 * already been {accepted, rejected, confirmed}, an orphanage, and a registry of
 * each peer's transaction relay-related information.
 *
 * Caller needs to interact with TxDownloadManager:
 * - ValidationInterface callbacks.
 * - When a potential transaction relay peer connects or disconnects.
 * - When a transaction or package is accepted or rejected from mempool
 * - When a inv, notfound, or tx message is received
 * - To get instructions for which getdata messages to send
 *
 * This class is not thread-safe. Access must be synchronized using an
 * external mutex.
 */
class TxDownloadManager {
    const std::unique_ptr<TxDownloadManagerImpl> m_impl;

public:
    explicit TxDownloadManager(const TxDownloadOptions& options);
    ~TxDownloadManager();

    // Responses to chain events. TxDownloadManager is not an actual client of ValidationInterface, these are called through PeerManager.
    void ActiveTipChange();
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock);
    void BlockDisconnected();

    /** Creates a new PeerInfo. Saves the connection info to calculate tx announcement delays later. */
    void ConnectedPeer(NodeId nodeid, const TxDownloadConnectionInfo& info);

    /** Deletes all txrequest announcements and orphans for a given peer. */
    void DisconnectedPeer(NodeId nodeid);

    /** Consider adding this tx hash to txrequest. Should be called whenever a new inv has been received.
     * Also called internally when a transaction is missing parents so that we can request them.
     * Returns true if this was a dropped inv (p2p_inv=true and we already have the tx), false otherwise. */
    bool AddTxAnnouncement(NodeId peer, const GenTxid& gtxid, std::chrono::microseconds now);

    /** Get getdata requests to send. */
    std::vector<GenTxid> GetRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** Should be called when a notfound for a tx has been received. */
    void ReceivedNotFound(NodeId nodeid, const std::vector<GenTxid>& gtxids);

    /** Consider requesting this package from the peer. Should be called whenever a pkginv entry
     * has been received. Returns true if we already have the package (see AlreadyHavePackage).
     * Ignored if the peer has MAX_PEER_PKG_ANNOUNCEMENTS tracked already. */
    bool AddPackageAnnouncement(NodeId peer, const PkgInv& pkg, std::chrono::microseconds now);

    /** A package to request: both transactions with getpkg, or the child only with getdata. */
    struct PackageRequest {
        PkgInv pkg;
        bool child_only;
    };

    /** Get package requests to send: first the packages to request in full again after a request for
     * the child alone (see ReceivedPackageChildNotFound and RelayedChildValidated), then new requests.
     * A new request is for the child alone if the parent is in the mempool. The requests count as
     * sent, so the caller must send each. Packages we already have are forgotten instead of
     * returned. */
    std::vector<PackageRequest> GetPackageRequestsToSend(NodeId nodeid, std::chrono::microseconds current_time);

    /** Should be called when a pkgnotfound has been received. Marks the peer done with these
     * packages, so that other announcers are asked. */
    void ReceivedPackageNotFound(NodeId nodeid, const std::vector<PkgInv>& pkgs);

    /** Should be called when a pkgtxns has been received. If the peer announced the package, stops
     * requesting it from any peer, and remembers it as rejected if the child does not spend the
     * parent. Returns whether to validate it (then call RelayedPackageValidated): the peer announced
     * it, we don't already have it, and the child spends the parent. */
    bool ReceivedPackage(NodeId nodeid, const CTransactionRef& parent, const CTransactionRef& child);

    /** Should be called when a transaction has been received, before ReceivedTx. Returns the packages
     * we requested child only from this peer with this transaction as the child and don't already
     * have; those we have are forgotten. If there are any, the transaction is to be validated for
     * them instead of by ReceivedTx (then call RelayedChildValidated). */
    std::vector<PkgInv> ReceivedPackageChild(NodeId nodeid, const Wtxid& child);

    /** Should be called when a notfound has been received. Ends the child-only requests to this peer
     * it answers, unless the parent left the mempool: then the package is requested in full from the
     * same peer, which announces the parent on its own if it cannot serve the package either. */
    void ReceivedPackageChildNotFound(NodeId nodeid, const std::vector<GenTxid>& gtxids);

    /** Respond to the validation of a package from pkgtxns. Remembers the package as rejected unless
     * its child is in the mempool. Returns its transactions to keep for compact block reconstruction:
     * those not accepted, other than ones already in the mempool or stripped of their witness. */
    std::vector<CTransactionRef> RelayedPackageValidated(const Package& package, const PackageMempoolAcceptResult& result);

    /** Respond to the validation of the child of packages requested child only from this peer (see
     * ReceivedPackageChild). If it was missing inputs, the packages are requested in full from the same
     * peer and nothing is remembered about them. Otherwise they are no longer requested, and remembered
     * as rejected unless the child was accepted. Returns whether to keep the child for compact block
     * reconstruction. */
    bool RelayedChildValidated(NodeId nodeid, const std::vector<PkgInv>& pkgs, const MempoolAcceptResult& result);

    /** Respond to successful transaction submission to mempool */
    void MempoolAcceptedTx(const CTransactionRef& tx);

    /** Respond to transaction rejected from mempool */
    RejectedTxTodo MempoolRejectedTx(const CTransactionRef& ptx, const TxValidationState& state, NodeId nodeid, bool first_time_failure);

    /** Respond to package rejected from mempool */
    void MempoolRejectedPackage(const Package& package);

    /** Marks a tx as ReceivedResponse in txrequest and checks whether AlreadyHaveTx.
     * Return a bool indicating whether this tx should be validated. If false, optionally, a
     * PackageToValidate. */
    std::pair<bool, std::optional<PackageToValidate>> ReceivedTx(NodeId nodeid, const CTransactionRef& ptx);

    /** Whether there are any orphans to reconsider for this peer. */
    bool HaveMoreWork(NodeId nodeid) const;

    /** Returns next orphan tx to consider, or nullptr if none exist. */
    CTransactionRef GetTxToReconsider(NodeId nodeid);

    /** Check that all data structures are empty. */
    void CheckIsEmpty() const;

    /** Check that all data structures that track per-peer information have nothing for this peer. */
    void CheckIsEmpty(NodeId nodeid) const;

    /** Wrapper for TxOrphanage::GetOrphanTransactions */
    std::vector<TxOrphanage::OrphanInfo> GetOrphanTransactions() const;
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
