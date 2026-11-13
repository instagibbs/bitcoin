// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pkgrequest.h>

#include <util/check.h>

#include <algorithm>
#include <cassert>

namespace node {
namespace {
/** TxRequestTracker takes a GenTxid; the package id stands in for a wtxid there, and only there. */
GenTxid ToGenTxid(const PkgId& id) { return Wtxid::FromUint256(id.ToUint256()); }
} // namespace

PackageRequestTracker::PackageRequestTracker(bool deterministic) : m_tracker{deterministic} {}

void PackageRequestTracker::ReceivedInv(NodeId peer, const PkgInv& pkg, bool preferred, std::chrono::microseconds reqtime)
{
    const PkgId id{pkg.GetId()};
    m_packages.try_emplace(id, Package{pkg});
    m_tracker.ReceivedInv(peer, ToGenTxid(id), preferred, reqtime);
}

void PackageRequestTracker::DisconnectedPeer(NodeId peer)
{
    std::vector<uint256> hashes;
    m_tracker.GetAnnounced(peer, hashes);
    for (const uint256& hash : hashes) {
        const PkgId id{hash};
        if (auto it{m_packages.find(id)}; it != m_packages.end() && it->second.request != Request::NONE && it->second.peer == peer) {
            EndRequest(id, it->second);
        }
    }
    m_tracker.DisconnectedPeer(peer);
    for (const uint256& hash : hashes) ForgetIfDone(PkgId{hash});
}

std::vector<PkgInv> PackageRequestTracker::GetRequestable(NodeId peer, std::chrono::microseconds now)
{
    std::vector<std::pair<NodeId, GenTxid>> expired;
    const auto requestable{m_tracker.GetRequestable(peer, now, &expired)};
    for (const auto& [expired_peer, gtxid] : expired) {
        const PkgId id{gtxid.ToUint256()};
        if (auto it{m_packages.find(id)}; it != m_packages.end() && it->second.request != Request::NONE && it->second.peer == expired_peer) {
            EndRequest(id, it->second);
        }
        ForgetIfDone(id);
    }
    std::vector<PkgInv> pkgs;
    pkgs.reserve(requestable.size());
    for (const GenTxid& gtxid : requestable) {
        if (const auto it{m_packages.find(PkgId{gtxid.ToUint256()})}; Assume(it != m_packages.end())) pkgs.push_back(it->second.pkg);
    }
    return pkgs;
}

void PackageRequestTracker::Requested(NodeId peer, const PkgInv& pkg, bool child_only, std::chrono::microseconds expiry)
{
    const PkgId id{pkg.GetId()};
    const auto it{m_packages.find(id)};
    if (!Assume(it != m_packages.end())) return;
    Package& package{it->second};
    // Like RequestedTx, which makes any other request for the package COMPLETED. GetRequestable does
    // not return a package that is in flight from another peer.
    if (package.request != Request::NONE) {
        if (!Assume(package.peer != peer)) return;
        EndRequest(id, package);
    }
    m_tracker.RequestedTx(peer, id.ToUint256(), expiry);
    package.request = child_only ? Request::CHILD_ONLY : Request::FULL;
    package.peer = peer;
    if (child_only) m_child_only_requests.emplace(std::pair{peer, pkg.child}, id);
}

void PackageRequestTracker::ToFull(NodeId peer, const PkgId& id)
{
    const auto it{m_packages.find(id)};
    if (!Assume(it != m_packages.end() && it->second.request == Request::CHILD_ONLY && it->second.peer == peer)) return;
    EndRequest(id, it->second);
    it->second.request = Request::FULL_TO_SEND;
    it->second.peer = peer;
    m_full_to_send.emplace(peer, id);
}

std::vector<PkgInv> PackageRequestTracker::GetFullToSend(NodeId peer, std::chrono::microseconds expiry)
{
    std::vector<PkgInv> pkgs;
    const auto begin{m_full_to_send.lower_bound({peer, PkgId{uint256::ZERO}})};
    auto end{begin};
    for (; end != m_full_to_send.end() && end->first == peer; ++end) {
        const auto it{m_packages.find(end->second)};
        if (!Assume(it != m_packages.end())) continue;
        it->second.request = Request::FULL;
        m_tracker.RequestedTxAgain(peer, end->second.ToUint256(), expiry);
        pkgs.push_back(it->second.pkg);
    }
    m_full_to_send.erase(begin, end);
    return pkgs;
}

std::vector<PkgInv> PackageRequestTracker::ChildOnlyRequests(NodeId peer, const Wtxid& child) const
{
    std::vector<PkgInv> pkgs;
    const auto [begin, end]{m_child_only_requests.equal_range({peer, child})};
    for (auto it{begin}; it != end; ++it) {
        if (const auto pkg_it{m_packages.find(it->second)}; Assume(pkg_it != m_packages.end())) pkgs.push_back(pkg_it->second.pkg);
    }
    return pkgs;
}

bool PackageRequestTracker::IsCandidate(NodeId peer, const PkgId& id) const
{
    std::vector<NodeId> peers;
    m_tracker.GetCandidatePeers(id.ToUint256(), peers);
    return std::ranges::find(peers, peer) != peers.end();
}

void PackageRequestTracker::ReceivedResponse(NodeId peer, const PkgId& id)
{
    if (auto it{m_packages.find(id)}; it != m_packages.end() && it->second.request != Request::NONE && it->second.peer == peer) {
        EndRequest(id, it->second);
    }
    m_tracker.ReceivedResponse(peer, id.ToUint256());
    ForgetIfDone(id);
}

void PackageRequestTracker::Forget(const PkgId& id)
{
    const auto it{m_packages.find(id)};
    if (it == m_packages.end()) return;
    EndRequest(id, it->second);
    m_tracker.ForgetTxHash(id.ToUint256());
    m_packages.erase(it);
}

size_t PackageRequestTracker::Count(NodeId peer) const { return m_tracker.Count(peer); }
size_t PackageRequestTracker::CountInFlight(NodeId peer) const { return m_tracker.CountInFlight(peer); }
size_t PackageRequestTracker::Size() const { return m_tracker.Size(); }
size_t PackageRequestTracker::CountPackages() const { return m_packages.size(); }

void PackageRequestTracker::EndRequest(const PkgId& id, Package& package)
{
    if (package.request == Request::CHILD_ONLY) {
        const auto [begin, end]{m_child_only_requests.equal_range({package.peer, package.pkg.child})};
        const auto it{std::find_if(begin, end, [&](const auto& entry) { return entry.second == id; })};
        if (Assume(it != end)) m_child_only_requests.erase(it);
    } else if (package.request == Request::FULL_TO_SEND) {
        Assume(m_full_to_send.erase({package.peer, id}) == 1);
    }
    package.request = Request::NONE;
    package.peer = -1;
}

void PackageRequestTracker::ForgetIfDone(const PkgId& id)
{
    const auto it{m_packages.find(id)};
    if (it == m_packages.end()) return;
    std::vector<NodeId> peers;
    m_tracker.GetCandidatePeers(id.ToUint256(), peers);
    if (!peers.empty()) return;
    Assume(it->second.request == Request::NONE);
    m_packages.erase(it);
}

void PackageRequestTracker::SanityCheck() const
{
    m_tracker.SanityCheck();
    std::map<NodeId, size_t> in_flight;
    for (const auto& [id, package] : m_packages) {
        assert(package.pkg.GetId() == id);
        std::vector<NodeId> peers;
        m_tracker.GetCandidatePeers(id.ToUint256(), peers);
        assert(!peers.empty());
        if (package.request != Request::NONE) {
            assert(std::ranges::find(peers, package.peer) != peers.end());
            ++in_flight[package.peer];
        }
        const auto [begin, end]{m_child_only_requests.equal_range({package.peer, package.pkg.child})};
        const bool indexed{std::any_of(begin, end, [&](const auto& entry) { return entry.second == id; })};
        assert(indexed == (package.request == Request::CHILD_ONLY));
        assert(m_full_to_send.contains({package.peer, id}) == (package.request == Request::FULL_TO_SEND));
    }
    for (const auto& [key, id] : m_child_only_requests) {
        const auto it{m_packages.find(id)};
        assert(it != m_packages.end() && it->second.request == Request::CHILD_ONLY && it->second.peer == key.first && it->second.pkg.child == key.second);
    }
    for (const auto& [peer, id] : m_full_to_send) {
        const auto it{m_packages.find(id)};
        assert(it != m_packages.end() && it->second.request == Request::FULL_TO_SEND && it->second.peer == peer);
    }
    // Every request in flight in m_tracker was made through Requested, and its package is kept.
    for (const auto& [peer, count] : in_flight) assert(m_tracker.CountInFlight(peer) == count);
}
} // namespace node
