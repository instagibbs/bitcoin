// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PKGREQUEST_H
#define BITCOIN_NODE_PKGREQUEST_H

#include <net.h>
#include <primitives/transaction_identifier.h>
#include <protocol.h>
#include <txrequest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace node {
/** Requests for 1-parent-1-child packages announced with pkginv.
 *
 * A TxRequestTracker keyed by package id decides which announcer to request a package from, and when
 * (see txrequest.h). This class adds what that one does not keep:
 * - the package's wtxids, for as long as an announcer is left to request it from;
 * - how the package is requested from the peer it is in flight from: both transactions with getpkg,
 *   or the child alone with getdata, which the peer answers with tx or notfound;
 * - an index of the child-alone requests by peer and child, since their reply does not name the
 *   package.
 *
 * A child-alone request can be turned into a full one (ToFull). It stays in flight, and gets a new
 * expiry when the full request is sent (GetFullToSend).
 */
class PackageRequestTracker
{
public:
    explicit PackageRequestTracker(bool deterministic = false);

    /** Adds an announcement of the package by this peer (see TxRequestTracker::ReceivedInv). */
    void ReceivedInv(NodeId peer, const PkgInv& pkg, bool preferred, std::chrono::microseconds reqtime);

    /** Deletes all of this peer's announcements and requests, and the packages no other peer
     * announced. */
    void DisconnectedPeer(NodeId peer);

    /** The packages to request from this peer now, after expiring the requests in flight to any peer
     * (see TxRequestTracker::GetRequestable) and deleting the packages no announcer is left for. Each
     * of them is to be passed to Requested or Forget. */
    std::vector<PkgInv> GetRequestable(NodeId peer, std::chrono::microseconds now);

    /** Marks a package returned by GetRequestable as requested from this peer, both transactions or
     * the child alone, until `expiry`. Ends any request for it in flight to another peer, as
     * TxRequestTracker::RequestedTx does. */
    void Requested(NodeId peer, const PkgInv& pkg, bool child_only, std::chrono::microseconds expiry);

    /** Turns the child-alone request to this peer for the package into one for both transactions,
     * still in flight, which ChildOnlyRequests no longer returns. GetFullToSend returns it once;
     * until then it keeps its expiry. */
    void ToFull(NodeId peer, const PkgId& id);

    /** Removes and returns the packages that ToFull queued for a full request to this peer. They are
     * in flight already; their expiry becomes `expiry`. The caller must send getpkg for each. */
    std::vector<PkgInv> GetFullToSend(NodeId peer, std::chrono::microseconds expiry);

    /** The packages requested child alone from this peer with this child. */
    std::vector<PkgInv> ChildOnlyRequests(NodeId peer, const Wtxid& child) const;

    /** Whether this peer announced the package and is not done with it (see
     * TxRequestTracker::GetCandidatePeers). */
    bool IsCandidate(NodeId peer, const PkgId& id) const;

    /** Marks this peer's announcement of the package as done with (see
     * TxRequestTracker::ReceivedResponse), and deletes the package if no announcer is left. */
    void ReceivedResponse(NodeId peer, const PkgId& id);

    /** Deletes all announcements of the package (see TxRequestTracker::ForgetTxHash). */
    void Forget(const PkgId& id);

    /** Number of announcements by this peer, and of those in flight (see TxRequestTracker). */
    size_t Count(NodeId peer) const;
    size_t CountInFlight(NodeId peer) const;
    /** Number of announcements in total. */
    size_t Size() const;
    /** Number of packages kept: those with an announcement that is not done with (testing only). */
    size_t CountPackages() const;

    /** Run internal consistency checks (testing only). */
    void SanityCheck() const;

private:
    enum class Request : uint8_t {
        NONE,         //!< Not in flight.
        FULL,         //!< Both transactions, with getpkg.
        CHILD_ONLY,   //!< The child alone, with getdata.
        FULL_TO_SEND, //!< Both transactions, after ToFull; getpkg not sent yet.
    };

    struct Package {
        PkgInv pkg;
        Request request{Request::NONE};
        /** The peer the request is in flight from, unless Request::NONE. */
        NodeId peer{-1};
    };

    TxRequestTracker m_tracker;
    std::map<PkgId, Package> m_packages;
    std::multimap<std::pair<NodeId, Wtxid>, PkgId> m_child_only_requests;
    std::set<std::pair<NodeId, PkgId>> m_full_to_send;

    /** Forget the request in flight for this package. */
    void EndRequest(const PkgId& id, Package& package);
    /** Delete the package once none of its announcements is left to request it from. */
    void ForgetIfDone(const PkgId& id);
};
} // namespace node

#endif // BITCOIN_NODE_PKGREQUEST_H
