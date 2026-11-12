// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pkgrequest.h>
#include <primitives/transaction_identifier.h>
#include <protocol.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {
constexpr int MAX_PEERS{4};
constexpr int MAX_WTXIDS{4};

/** Packages over a few wtxids, so that several share a parent or a child. */
std::vector<PkgInv> MakePackages()
{
    std::array<Wtxid, MAX_WTXIDS> wtxids;
    for (int i{0}; i < MAX_WTXIDS; ++i) wtxids[i] = Wtxid::FromUint256(uint256{static_cast<uint8_t>(i + 1)});
    std::vector<PkgInv> pkgs;
    for (int parent{0}; parent < MAX_WTXIDS; ++parent) {
        for (int child{0}; child < MAX_WTXIDS; ++child) {
            if (parent != child) pkgs.push_back({wtxids[parent], wtxids[child]});
        }
    }
    return pkgs;
}
} // namespace

// The data structures of PackageRequestTracker stay consistent with its TxRequestTracker
// (SanityCheck), and a package is kept exactly as long as a peer announced it and is not done with
// it, whatever the sequence of calls.
FUZZ_TARGET(pkgrequest)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    static const std::vector<PkgInv> PKGS{MakePackages()};
    node::PackageRequestTracker tracker{/*deterministic=*/true};
    std::chrono::microseconds now{244466666};

    const auto consume_pkg{[&] { return PKGS[fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, PKGS.size() - 1)]; }};
    const auto consume_peer{[&] { return fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(0, MAX_PEERS - 1); }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                const std::chrono::microseconds delay{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 10'000'000)};
                tracker.ReceivedInv(consume_peer(), consume_pkg(), fuzzed_data_provider.ConsumeBool(), now + delay);
            },
            [&] { tracker.DisconnectedPeer(consume_peer()); },
            [&] {
                const NodeId peer{consume_peer()};
                for (const PkgInv& pkg : tracker.GetRequestable(peer, now)) {
                    if (fuzzed_data_provider.ConsumeBool()) {
                        const std::chrono::microseconds timeout{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(1, 60'000'000)};
                        tracker.Requested(peer, pkg, fuzzed_data_provider.ConsumeBool(), now + timeout);
                    } else {
                        tracker.Forget(pkg.GetId());
                    }
                }
            },
            [&] {
                // A reply to a child-alone request missing inputs, or a notfound with the parent gone.
                const NodeId peer{consume_peer()};
                const auto pkgs{tracker.ChildOnlyRequests(peer, consume_pkg().child)};
                for (const PkgInv& pkg : pkgs) {
                    if (fuzzed_data_provider.ConsumeBool()) tracker.ToFull(peer, pkg.GetId());
                }
            },
            [&] {
                const NodeId peer{consume_peer()};
                for (const PkgInv& pkg : tracker.GetFullToSend(peer)) assert(tracker.IsCandidate(peer, pkg.GetId()));
            },
            [&] { tracker.ReceivedResponse(consume_peer(), consume_pkg().GetId()); },
            [&] { tracker.Forget(consume_pkg().GetId()); },
            [&] { now += std::chrono::microseconds{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 120'000'000)}; },
            [&] { tracker.SanityCheck(); },
            [&] {
                size_t candidates{0};
                for (const PkgInv& pkg : PKGS) {
                    bool candidate{false};
                    for (NodeId peer{0}; peer < MAX_PEERS; ++peer) candidate |= tracker.IsCandidate(peer, pkg.GetId());
                    candidates += candidate;
                }
                assert(tracker.CountPackages() == candidates);
            });
    }
}
