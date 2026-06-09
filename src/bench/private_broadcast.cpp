// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <primitives/transaction.h>
#include <private_broadcast.h>
#include <util/time.h>

#include <cstdint>
#include <vector>

// Investigation bench: how does the per-event CPU cost of PrivateBroadcast
// scale with the number of outstanding transactions (N) and the number of
// recorded send attempts per transaction (S)?
//
// Hot operations are all O(N*S):
//   - PickTxForSend       : max_element over all txs, DerivePriority per tx
//   - GetStale            : scan all txs, DerivePriority per tx
//   - GetSendStatusByNode : scan all txs and all their send_statuses
//
// These benchmarks sweep the number of outstanding transactions (N) well past
// any realistic outstanding count to characterize the slope of the O(N*S)
// scans (it is super-linear once the unordered_map outgrows cache).

namespace {

CTransactionRef MakeDummyTx(uint32_t id)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = id; // distinct wtxid per id
    return MakeTransactionRef(mtx);
}

// Fill a PrivateBroadcast with num_txs transactions, then issue enough
// PickTxForSend calls that each tx accumulates roughly statuses_per_tx send
// statuses (PickTxForSend round-robins by picking the least-picked tx).
void Fill(PrivateBroadcast& pb, size_t num_txs, size_t statuses_per_tx)
{
    for (uint32_t i = 0; i < num_txs; ++i) {
        (void)pb.Add(MakeDummyTx(i));
    }
    const CService addr{};
    const size_t total_picks{num_txs * statuses_per_tx};
    for (size_t i = 0; i < total_picks; ++i) {
        pb.PickTxForSend(/*will_send_to_nodeid=*/static_cast<NodeId>(i), addr);
    }
}

// ---- N sweep: PickTxForSend with small fixed S ----
// PickTxForSend mutates (appends one status per call), but at large N the
// per-iteration growth of S is negligible relative to the O(N) max_element
// scan, which is what we are measuring.
void PickTxForSendN(benchmark::Bench& bench, size_t num_txs)
{
    SetMockTime(1);
    PrivateBroadcast pb;
    Fill(pb, num_txs, /*statuses_per_tx=*/1);
    const CService addr{};
    NodeId nodeid{0};
    bench.run([&] { pb.PickTxForSend(nodeid++, addr); });
}

// ---- N sweep: GetStale (read-only) with small fixed S ----
void GetStaleN(benchmark::Bench& bench, size_t num_txs)
{
    SetMockTime(1);
    PrivateBroadcast pb;
    Fill(pb, num_txs, /*statuses_per_tx=*/1);
    bench.run([&] { ankerl::nanobench::doNotOptimizeAway(pb.GetStale()); });
}

// ---- S sweep: GetStale at fixed N, varying statuses-per-tx ----
void GetStaleS(benchmark::Bench& bench, size_t statuses_per_tx)
{
    SetMockTime(1);
    PrivateBroadcast pb;
    Fill(pb, /*num_txs=*/1000, statuses_per_tx);
    bench.run([&] { ankerl::nanobench::doNotOptimizeAway(pb.GetStale()); });
}

} // namespace

static void PrivateBroadcastPick1k(benchmark::Bench& b) { PickTxForSendN(b, 1000); }
static void PrivateBroadcastPick10k(benchmark::Bench& b) { PickTxForSendN(b, 10000); }
static void PrivateBroadcastPick100k(benchmark::Bench& b) { PickTxForSendN(b, 100000); }

static void PrivateBroadcastStale1k(benchmark::Bench& b) { GetStaleN(b, 1000); }
static void PrivateBroadcastStale10k(benchmark::Bench& b) { GetStaleN(b, 10000); }
static void PrivateBroadcastStale100k(benchmark::Bench& b) { GetStaleN(b, 100000); }

static void PrivateBroadcastStaleS4(benchmark::Bench& b) { GetStaleS(b, 4); }
static void PrivateBroadcastStaleS50(benchmark::Bench& b) { GetStaleS(b, 50); }
static void PrivateBroadcastStaleS500(benchmark::Bench& b) { GetStaleS(b, 500); }

BENCHMARK(PrivateBroadcastPick1k);
BENCHMARK(PrivateBroadcastPick10k);
BENCHMARK(PrivateBroadcastPick100k);

BENCHMARK(PrivateBroadcastStale1k);
BENCHMARK(PrivateBroadcastStale10k);
BENCHMARK(PrivateBroadcastStale100k);

BENCHMARK(PrivateBroadcastStaleS4);
BENCHMARK(PrivateBroadcastStaleS50);
BENCHMARK(PrivateBroadcastStaleS500);
