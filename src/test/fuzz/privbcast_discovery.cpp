// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <netaddress.h>
#include <primitives/transaction.h>
#include <privbcast/discovery.h>
#include <privbcast/job.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <random.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <numeric>
#include <set>
#include <string>
#include <vector>

using namespace privbcast;

namespace {

void initialize_privbcast_discovery()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

CTransactionRef FallbackTx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    return MakeTransactionRef(mtx);
}

} // namespace

FUZZ_TARGET(privbcast_discovery, .init = initialize_privbcast_discovery)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    SetTimeDivisor(fdp.ConsumeIntegralInRange<uint32_t>(1, 1000));

    // --- Freeze: validation, dedup by tie order, caps ---
    DiscoveryPlan plan;
    const size_t n{fdp.ConsumeIntegralInRange<size_t>(0, 8)};
    for (size_t i = 0; i < n; ++i) plan.dns_seeds.push_back(strprintf("seed%d.test.", i));
    plan.port = fdp.ConsumeIntegral<uint16_t>();
    const size_t bundled_n{fdp.ConsumeIntegralInRange<size_t>(0, 12)};
    for (size_t i = 0; i < bundled_n; ++i) plan.bundled.push_back(ConsumeService(fdp));
    if (fdp.ConsumeBool() && !plan.bundled.empty()) plan.bundled.push_back(plan.bundled.front()); // duplicate

    SeedAnswers answers(n);
    size_t total_answers{0};
    for (size_t i = 0; i < n; ++i) {
        const size_t m{fdp.ConsumeIntegralInRange<size_t>(0, 6)};
        for (size_t j = 0; j < m; ++j) {
            // Mostly plausible answers, sometimes repeats of an earlier one across seeds.
            if (fdp.ConsumeBool() && total_answers > 0) {
                const size_t si{fdp.ConsumeIntegralInRange<size_t>(0, i)};
                if (!answers[si].empty()) {
                    answers[i].push_back(answers[si][fdp.ConsumeIntegralInRange<size_t>(0, answers[si].size() - 1)]);
                    ++total_answers;
                    continue;
                }
            }
            answers[i].push_back(ConsumeNetAddr(fdp));
            ++total_answers;
        }
    }
    FastRandomContext rng{/*fDeterministic=*/true};
    std::vector<size_t> tie_order(n);
    std::iota(tie_order.begin(), tie_order.end(), size_t{0});
    if (fdp.ConsumeBool()) std::shuffle(tie_order.begin(), tie_order.end(), rng);

    const DiscoveryResult d{Freeze(plan, answers, tie_order, rng)};
    assert(d.per_seed.size() == n && d.seeds.size() == n && d.tie_order == tie_order);
    std::set<CService> all_exit;
    uint32_t accepted_total{0};
    for (size_t i = 0; i < n; ++i) {
        assert(d.per_seed[i].size() <= disc::MAX_PER_SEED);
        assert(d.seeds[i].kept == d.per_seed[i].size());
        assert(d.seeds[i].kept <= d.seeds[i].accepted);
        assert(d.seeds[i].answers == answers[i].size());
        accepted_total += d.seeds[i].accepted;
        for (const Candidate& c : d.per_seed[i]) {
            assert(c.source == Source::DNS_SEED && c.provenance == plan.dns_seeds[i]);
            assert(c.addr.GetPort() == plan.port);
            assert(c.addr.IsValid() && c.addr.IsRoutable() && (c.addr.IsIPv4() || c.addr.IsIPv6()));
            assert(all_exit.insert(c.addr).second); // unique across seeds
            // Owned by the first seed in tie order that answered it: seed i answered it, and no
            // seed earlier in the tie order did.
            const CNetAddr bare{c.addr};
            assert(std::find(answers[i].begin(), answers[i].end(), bare) != answers[i].end());
            for (const size_t j : tie_order) {
                if (j == i) break;
                assert(std::find(answers[j].begin(), answers[j].end(), bare) == answers[j].end());
            }
        }
    }
    assert(accepted_total + d.duplicates + d.rejected == total_answers);
    assert(d.NumExitPath() == all_exit.size());
    assert(d.onion.size() <= disc::MAX_BUNDLED);
    std::set<CService> onions;
    for (const Candidate& c : d.onion) {
        assert(c.source == Source::BUNDLED && c.addr.IsTor());
        assert(onions.insert(c.addr).second);
    }

    // --- Assignment: primaries first, no reuse, onion reservation ---
    const Assignment a{AssignCandidates(d)};
    assert(a.size() == plan::SLOTS);
    std::set<std::string> used;
    bool any_exit_replacement{false};
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        assert(a[s].size() == plan::OPPORTUNITIES_PER_SLOT);
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
            if (!a[s][k]) continue;
            assert(used.insert(a[s][k]->addr.ToStringAddrPort()).second);
            if (ClassOfSlot(s) == SlotClass::EXIT_PATH) {
                assert(a[s][k]->source == Source::DNS_SEED);
                if (k > 0) any_exit_replacement = true;
            }
        }
    }
    if (any_exit_replacement) {
        // Every primary got its exit-path candidate before any exit-path replacement was handed out.
        for (uint32_t s = 0; s < plan::SLOTS; ++s) assert(a[s][0].has_value());
    }
    // Onion slots use onions while they last.
    size_t onion_used{0};
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        if (ClassOfSlot(s) != SlotClass::ONION) continue;
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
            if (a[s][k] && a[s][k]->source == Source::BUNDLED) ++onion_used;
        }
    }
    assert(onion_used == std::min<size_t>(d.onion.size(), plan::ONION_SLOTS * plan::OPPORTUNITIES_PER_SLOT));

    // --- Schedule arithmetic ---
    const auto t0{SteadyClock::time_point{std::chrono::seconds{fdp.ConsumeIntegral<uint32_t>()}}};
    const Schedule sched{Schedule::Draw(t0, rng)};
    assert(sched.DeliveryStart() == t0 + Scaled(disc::WINDOW));
    std::vector<std::chrono::seconds> late;
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        const auto p{sched.primary[s]};
        switch (StratumOfSlot(s)) {
        case Stratum::PROMPT: assert(p == std::chrono::seconds{0}); break;
        case Stratum::MID: assert(p >= plan::MID_MIN && p <= plan::MID_MAX); break;
        case Stratum::LATE:
            assert(p >= plan::LATE_MIN && p <= plan::LATE_MAX);
            late.push_back(p);
            break;
        }
        assert(sched.OpportunityStart(s, 0) == sched.DeliveryStart() + Scaled(p));
        for (uint32_t k = 1; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
            const auto b{sched.backup[s][k - 1]};
            assert(b >= plan::BACKUP_MIN && b <= plan::BACKUP_MAX);
            assert(sched.OpportunityStart(s, k) == sched.OpportunityStart(s, k - 1) + Scaled(b));
        }
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) assert(sched.AttemptDeadline(s, k) > sched.OpportunityStart(s, k));
        assert(sched.SlotEnd(s) <= sched.OpportunityStart(s, 0) + Scaled(plan::SLOT_MAX));
        assert(sched.SlotEnd(s) <= t0 + Scaled(plan::SCHEDULED_BOUND));
    }
    assert(late.size() == 2);
    std::sort(late.begin(), late.end());
    assert(late[1] - late[0] >= plan::PRIMARY_SEPARATION);

    // --- Report building over arbitrary records ---
    std::vector<SlotRecord> records(fdp.ConsumeIntegralInRange<size_t>(0, plan::SLOTS));
    const CTransactionRef tx{FallbackTx()};
    bool any_written{false};
    for (auto& rec : records) {
        rec.empty_opportunities = fdp.ConsumeIntegralInRange<uint32_t>(0, 3);
        rec.missed_opportunities = fdp.ConsumeIntegralInRange<uint32_t>(0, 3);
        rec.interrupted = fdp.ConsumeBool();
        const size_t attempts{fdp.ConsumeIntegralInRange<size_t>(0, 3)};
        for (size_t i = 0; i < attempts; ++i) {
            AttemptResult res;
            res.candidate = Candidate{ConsumeService(fdp), fdp.ConsumeBool() ? Source::BUNDLED : Source::DNS_SEED, "x"};
            res.outcome = static_cast<Outcome>(fdp.ConsumeIntegralInRange<int>(0, static_cast<int>(Outcome::POST_ANNOUNCEMENT_FAILURE)));
            res.reason = fdp.ConsumeRandomLengthString(8);
            res.scheduled_start = t0 + std::chrono::milliseconds{fdp.ConsumeIntegral<uint16_t>()};
            res.started = res.scheduled_start + std::chrono::milliseconds{fdp.ConsumeIntegral<uint8_t>()};
            res.ended = res.started + std::chrono::milliseconds{fdp.ConsumeIntegral<uint16_t>()};
            if (fdp.ConsumeBool()) res.connected = res.started;
            if (fdp.ConsumeBool()) res.evidence.inv_handed = res.started;
            if (res.evidence.inv_handed && fdp.ConsumeBool()) {
                res.evidence.inv_written = res.started;
                any_written = true;
            }
            if (fdp.ConsumeBool()) res.evidence.tx_written = res.started;
            if (fdp.ConsumeBool()) res.evidence.pong_received = res.started;
            res.bytes_sent = fdp.ConsumeIntegral<uint16_t>();
            res.bytes_recv = fdp.ConsumeIntegral<uint16_t>();
            rec.attempts.push_back(std::move(res));
        }
    }
    int exit_code{-1};
    const UniValue json{BuildReport("regtest", tx, sched, d, records, fdp.ConsumeIntegralInRange<uint32_t>(0, plan::SLOTS), fdp.ConsumeBool(),
                                    t0 + std::chrono::seconds{fdp.ConsumeIntegral<uint16_t>()}, exit_code)};
    assert(exit_code == (any_written ? 0 : 2));
    assert((json["summary"]["announcements_written"].getInt<int>() > 0) == any_written);
    assert(json["slots"].size() == records.size());
    (void)json.write();

    SetTimeDivisor(1);
}
