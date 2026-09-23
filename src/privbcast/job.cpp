// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/job.h>

#include <logging.h>
#include <netbase.h>
#include <privbcast/attempt.h>
#include <privbcast/discovery.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <random.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <mutex>
#include <set>
#include <thread>
#include <utility>


namespace privbcast {

std::pair<std::chrono::seconds, std::chrono::seconds> SeparateDraws(std::chrono::seconds a, std::chrono::seconds b, std::chrono::seconds gap, std::chrono::seconds hi)
{
    if (b < a) std::swap(a, b);
    if (b - a < gap) {
        if (a + gap <= hi) {
            b = a + gap;
        } else {
            a = b - gap;
        }
    }
    return {a, b};
}

Schedule Schedule::Draw(Clock::time_point t0, FastRandomContext& rng)
{
    const auto uniform = [&](std::chrono::seconds lo, std::chrono::seconds hi) {
        return lo + std::chrono::seconds{rng.randrange((hi - lo).count() + 1)};
    };
    Schedule s;
    s.t0 = t0;
    // Fixed draw order, so the schedule is a function of the seed alone: each slot's primary in
    // slot order, then the late pair's separation, then every slot's backups.
    std::vector<uint32_t> late_slots;
    for (uint32_t slot = 0; slot < plan::SLOTS; ++slot) {
        switch (StratumOfSlot(slot)) {
        case Stratum::PROMPT: s.primary[slot] = 0s; break;
        case Stratum::MID: s.primary[slot] = uniform(plan::MID_MIN, plan::MID_MAX); break;
        case Stratum::LATE:
            s.primary[slot] = uniform(plan::LATE_MIN, plan::LATE_MAX);
            late_slots.push_back(slot);
            break;
        }
    }
    const auto [late_a, late_b]{SeparateDraws(s.primary[late_slots.at(0)], s.primary[late_slots.at(1)], plan::PRIMARY_SEPARATION, plan::LATE_MAX)};
    s.primary[late_slots.at(0)] = late_a;
    s.primary[late_slots.at(1)] = late_b;
    for (uint32_t slot = 0; slot < plan::SLOTS; ++slot) {
        for (auto& b : s.backup[slot]) b = uniform(plan::BACKUP_MIN, plan::BACKUP_MAX);
    }
    return s;
}

Clock::time_point Schedule::OpportunityStart(uint32_t slot, uint32_t k) const
{
    auto start{DeliveryStart() + Scaled(primary.at(slot))};
    for (uint32_t i = 0; i < k; ++i) start += Scaled(backup.at(slot).at(i));
    return start;
}

Assignment AssignCandidates(const DiscoveryResult& discovery)
{
    const size_t n{discovery.per_seed.size()};
    std::vector<size_t> next_per_seed(n, 0);
    size_t rr{0};
    size_t next_onion{0};
    // Take the next exit-path candidate along the tie order, preferring a seed this slot has
    // not been given yet. `rr` advances past the chosen seed so consecutive draws spread.
    const auto take_exit_path = [&](std::set<size_t>& used_by_slot) -> std::optional<Candidate> {
        for (const bool avoid_used : {true, false}) {
            for (size_t tries = 0; tries < n; ++tries) {
                const size_t seed{discovery.tie_order[(rr + tries) % n]};
                if (avoid_used && used_by_slot.contains(seed)) continue;
                if (next_per_seed[seed] < discovery.per_seed[seed].size()) {
                    rr = (rr + tries + 1) % n;
                    used_by_slot.insert(seed);
                    return discovery.per_seed[seed][next_per_seed[seed]++];
                }
            }
        }
        return std::nullopt;
    };
    Assignment a(plan::SLOTS, std::vector<std::optional<Candidate>>(plan::OPPORTUNITIES_PER_SLOT));
    std::vector<std::set<size_t>> used(plan::SLOTS);
    // Primaries (opportunity 0) for every slot before any backup (opportunities 1..K-1), so no
    // slot's first attempt is starved by another slot's backups. Within a layer the exit-path
    // slots draw before the onion slots, whose exit-path fallback must not starve them of their
    // own backups.
    for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
        for (const SlotClass cls : {SlotClass::EXIT_PATH, SlotClass::ONION}) {
            for (uint32_t s = 0; s < plan::SLOTS; ++s) {
                if (ClassOfSlot(s) != cls) continue;
                if (cls == SlotClass::ONION && next_onion < discovery.onion.size()) {
                    a[s][k] = discovery.onion[next_onion++];
                } else {
                    a[s][k] = take_exit_path(used[s]);
                }
            }
        }
    }
    return a;
}

namespace {

/** Sleep until `when`, returning false if interrupted first. Interruption also unblocks this job's SOCKS exchanges. */
bool WaitUntilOrInterrupt(Clock::time_point when, const std::function<bool()>& interrupted, CThreadInterrupt& socks_interrupt)
{
    if (WaitUntil(when, interrupted)) return true;
    socks_interrupt();
    WakeWaiters();
    return false;
}

int64_t Ms(Clock::time_point t, Clock::time_point t0)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(t - t0).count();
}

UniValue OptMs(const std::optional<Clock::time_point>& t, Clock::time_point t0)
{
    if (!t) return UniValue{UniValue::VNULL};
    return UniValue{Ms(*t, t0)};
}

const char* StratumName(Stratum stratum)
{
    switch (stratum) {
    case Stratum::PROMPT: return "prompt";
    case Stratum::MID: return "mid";
    case Stratum::LATE: return "late";
    }
    return "?";
}

} // namespace

UniValue DiscoveryJson(const DiscoveryResult& discovery, bool addresses)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("duration_ms", static_cast<int64_t>(discovery.duration.count()));
    UniValue seeds{UniValue::VARR};
    for (size_t i = 0; i < discovery.seeds.size(); ++i) {
        const SeedStats& st{discovery.seeds[i]};
        UniValue o{UniValue::VOBJ};
        o.pushKV("name", st.name);
        o.pushKV("queries", st.queries);
        o.pushKV("skipped", st.skipped);
        o.pushKV("answers", st.answers);
        o.pushKV("accepted", st.accepted);
        o.pushKV("kept", st.kept);
        if (addresses && i < discovery.per_seed.size()) {
            UniValue cands{UniValue::VARR};
            for (const Candidate& c : discovery.per_seed[i]) cands.push_back(c.addr.ToStringAddrPort());
            o.pushKV("candidates", std::move(cands));
        }
        seeds.push_back(std::move(o));
    }
    out.pushKV("seeds", std::move(seeds));
    if (addresses) {
        UniValue onion{UniValue::VARR};
        for (const Candidate& c : discovery.onion) onion.push_back(c.addr.ToStringAddrPort());
        out.pushKV("onion", std::move(onion));
    }
    UniValue tie{UniValue::VARR};
    for (const size_t i : discovery.tie_order) tie.push_back(static_cast<uint64_t>(i));
    out.pushKV("tie_order", std::move(tie));
    out.pushKV("duplicates", discovery.duplicates);
    out.pushKV("rejected", discovery.rejected);
    out.pushKV("exit_path_candidates", static_cast<uint64_t>(discovery.NumExitPath()));
    out.pushKV("onion_candidates", static_cast<uint64_t>(discovery.onion.size()));
    return out;
}

UniValue BuildReport(const std::string& chain, const CTransactionRef& tx, const Schedule& schedule,
                     const DiscoveryResult& discovery, const std::vector<SlotRecord>& records,
                     uint32_t slots_completed, bool interrupted, Clock::time_point ended,
                     int& exit_code)
{
    const auto t0{schedule.t0};
    UniValue out{UniValue::VOBJ};
    out.pushKV("txid", tx->GetHash().ToString());
    out.pushKV("wtxid", tx->GetWitnessHash().ToString());
    out.pushKV("chain", chain);

    out.pushKV("discovery", DiscoveryJson(discovery, /*addresses=*/false));

    uint32_t connections{0}, handed{0}, written{0}, tx_written{0}, pongs{0};
    UniValue slots{UniValue::VARR};
    for (uint32_t s = 0; s < records.size(); ++s) {
        const SlotRecord& rec{records[s]};
        UniValue so{UniValue::VOBJ};
        so.pushKV("slot", s);
        so.pushKV("class", ClassOfSlot(s) == SlotClass::ONION ? "onion" : "exit_path");
        so.pushKV("stratum", StratumName(StratumOfSlot(s)));
        UniValue scheduled{UniValue::VARR};
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) scheduled.push_back(Ms(schedule.OpportunityStart(s, k), t0));
        so.pushKV("scheduled_ms", std::move(scheduled));
        so.pushKV("scheduled_end_ms", Ms(schedule.SlotEnd(s), t0));
        so.pushKV("empty_opportunities", rec.empty_opportunities);
        so.pushKV("missed_opportunities", rec.missed_opportunities);
        so.pushKV("interrupted", rec.interrupted);
        so.pushKV("error", rec.error ? UniValue{*rec.error} : UniValue{UniValue::VNULL});
        UniValue attempts{UniValue::VARR};
        for (uint32_t k = 0; k < rec.attempts.size(); ++k) {
            const AttemptResult& a{rec.attempts[k]};
            ++connections;
            const auto& ev{a.evidence};
            if (ev.inv_handed) ++handed;
            if (ev.inv_written) ++written;
            if (ev.tx_written) ++tx_written;
            if (ev.pong_received) ++pongs;
            UniValue ao{UniValue::VOBJ};
            ao.pushKV("endpoint", a.candidate.addr.ToStringAddrPort());
            ao.pushKV("source", a.candidate.source == Source::BUNDLED ? "bundled" : "dns_seed");
            ao.pushKV("provenance", a.candidate.provenance);
            ao.pushKV("outcome", std::string{OutcomeName(a.outcome)});
            ao.pushKV("reason", a.reason);
            ao.pushKV("scheduled_start_ms", Ms(a.scheduled_start, t0));
            ao.pushKV("started_ms", Ms(a.started, t0));
            ao.pushKV("connected_ms", OptMs(a.connected, t0));
            ao.pushKV("peer_version", ev.peer_version ? UniValue{*ev.peer_version} : UniValue{UniValue::VNULL});
            ao.pushKV("peer_user_agent", ev.peer_version ? UniValue{ev.peer_user_agent} : UniValue{UniValue::VNULL});
            ao.pushKV("inv_handed_ms", OptMs(ev.inv_handed, t0));
            ao.pushKV("inv_written_ms", OptMs(ev.inv_written, t0));
            ao.pushKV("getdata_ms", OptMs(ev.getdata_received, t0));
            ao.pushKV("tx_written_ms", OptMs(ev.tx_written, t0));
            ao.pushKV("ping_written_ms", OptMs(ev.ping_written, t0));
            ao.pushKV("pong_ms", OptMs(ev.pong_received, t0));
            ao.pushKV("ended_ms", Ms(a.ended, t0));
            ao.pushKV("extra_requests", ev.extra_requests);
            ao.pushKV("bytes_sent", static_cast<uint64_t>(a.bytes_sent));
            ao.pushKV("bytes_recv", static_cast<uint64_t>(a.bytes_recv));
            attempts.push_back(std::move(ao));
        }
        so.pushKV("attempts", std::move(attempts));
        slots.push_back(std::move(so));
    }
    out.pushKV("slots", std::move(slots));

    UniValue summary{UniValue::VOBJ};
    summary.pushKV("connections", connections);
    summary.pushKV("announcements_handed", handed);
    summary.pushKV("announcements_written", written);
    summary.pushKV("tx_written", tx_written);
    summary.pushKV("pongs", pongs);
    summary.pushKV("slots_completed", slots_completed);
    summary.pushKV("interrupted", interrupted);
    summary.pushKV("duration_ms", Ms(ended, t0));
    out.pushKV("summary", std::move(summary));

    exit_code = written > 0 ? 0 : 2;
    return out;
}

JobReport RunJob(const JobConfig& cfg)
{
    JobThreadScope job_thread; // this thread runs job code until it only waits for its workers
    // Delivery's SOCKS bounds are plan constants carried on every dial: a CONNECT always returns
    // within the handshake budget, so a slow proxy exchange cannot push the slot's next fixed
    // opportunity. The interrupt is this job's own; the process-wide SOCKS settings and interrupt
    // (ordinary connections' in bitcoind) are neither read nor written. Declared before anything
    // that captures it so it outlives every thread of the job.
    CThreadInterrupt socks_interrupt;
    // Progress for cfg.on_progress, updated from the slot threads and reported under the same
    // lock so reports arrive in order.
    std::mutex progress_mutex;
    JobProgress progress;
    const auto report_progress = [&](const std::function<void(JobProgress&)>& update) {
        std::lock_guard lock{progress_mutex};
        update(progress);
        if (cfg.on_progress) cfg.on_progress(progress);
    };
    const auto make_connector = [&](const Candidate& c, Clock::time_point socks_deadline) -> Connector {
        Socks5Params socks{ToSteady(socks_deadline)};
        socks.stage_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(Scaled(plan::SOCKS_RECV_TIMEOUT));
        socks.connect_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(Scaled(plan::CONNECT_TIMEOUT));
        socks.interrupt = &socks_interrupt;
        return cfg.connector ? cfg.connector(c, socks) : TorConnector(cfg.tor, c, std::move(socks));
    };
    FastRandomContext rng;
    const auto t0{Clock::now()};
    const Schedule schedule{Schedule::Draw(t0, rng)};
    LogDebug(BCLog::PRIVBROADCAST, "job txid=%s wtxid=%s slots=%u\n", cfg.tx->GetHash().ToString(), cfg.tx->GetWitnessHash().ToString(), plan::SLOTS);

    // A signal only sets a flag; a slot thread blocked inside a SOCKS exchange would not see it
    // until that exchange returned. The watcher turns the flag into this job's SOCKS interrupt.
    std::atomic<bool> watcher_stop{false};
    JobThreadScope::Reserve();
    std::thread watcher([&] {
        JobThreadScope job_thread{/*reserved=*/true};
        // Woken by the stop flag, an interrupt raised through WakeWaiters(), or the 50 ms poll.
        while (WaitUntil(Clock::time_point::max(), [&] { return watcher_stop.load() || cfg.interrupted(); }, 50ms), !watcher_stop.load()) {
            if (cfg.interrupted()) {
                socks_interrupt();
                WakeWaiters();
                return;
            }
        }
    });
    // Stopped once delivery is over, and on every exit path, so the thread is never left joinable.
    struct WatcherGuard {
        std::atomic<bool>& stop;
        std::thread& thread;
        void Stop()
        {
            stop.store(true);
            if (thread.joinable()) thread.join();
        }
        ~WatcherGuard() { Stop(); }
    } watcher_guard{watcher_stop, watcher};

    const DiscoveryResult discovery{cfg.discover ? cfg.discover() : Discover(cfg.tor, cfg.discovery, t0, rng, cfg.interrupted)};
    LogDebug(BCLog::PRIVBROADCAST, "discovery done: exit-path candidates=%u onion candidates=%u duplicates=%u rejected=%u\n",
            discovery.NumExitPath(), discovery.onion.size(), discovery.duplicates, discovery.rejected);
    report_progress([](JobProgress& p) { p.discovery_done = true; });
    const Assignment assignment{AssignCandidates(discovery)};

    std::vector<SlotRecord> records(plan::SLOTS);
    uint32_t slots_completed{0};
    bool interrupted{false};
    {
        // One thread per slot, each following only its own pre-drawn times. Nothing here consults
        // how many connections are live: a limiter that waited for another slot would let a
        // hostile peer holding its connection open delay this one. The threads are created during
        // the discovery window and each waits for its own start, so starting them never eats into
        // a prompt slot's grace.
        std::vector<std::thread> threads;
        struct JoinThreads {
            std::vector<std::thread>& threads;
            ~JoinThreads()
            {
                for (auto& t : threads) {
                    if (t.joinable()) t.join();
                }
            }
        } join_threads{threads};
        for (uint32_t s = 0; s < plan::SLOTS; ++s) {
            JobThreadScope::Reserve();
            threads.emplace_back([&, s] {
                JobThreadScope slot_thread{/*reserved=*/true};
                SlotRecord& rec{records[s]};
                try {
                    for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
                        const auto start{schedule.OpportunityStart(s, k)};
                        if (!WaitUntilOrInterrupt(start, cfg.interrupted, socks_interrupt)) {
                            rec.interrupted = true;
                            return;
                        }
                        const std::optional<Candidate> cand{assignment[s][k]};
                        if (!cand) {
                            ++rec.empty_opportunities;
                            LogDebug(BCLog::PRIVBROADCAST, "slot %u opportunity %u: no candidate\n", s, k);
                            report_progress([](JobProgress& p) { ++p.opportunities_ended; });
                            continue;
                        }
                        LogDebug(BCLog::PRIVBROADCAST, "slot %u opportunity %u: dial %s (%s)\n", s, k, cand->addr.ToStringAddrPort(), cand->provenance);
                        // The SOCKS exchange must be over HANDSHAKE_RESERVE before the handshake deadline,
                        // leaving the transport handshake and VERSION/VERACK their share of the budget.
                        const auto socks_deadline{start + Scaled(wire::HANDSHAKE_TIMEOUT) - Scaled(plan::HANDSHAKE_RESERVE)};
                        // The attempt dials only if the job is not cancelled and the opportunity's grace
                        // has not passed, checked last thing before the connect; otherwise nothing was dialled.
                        auto res{RunAttempt(make_connector(*cand, socks_deadline), *cand, cfg.tx, start,
                                            start + Scaled(plan::START_GRACE), schedule.AttemptDeadline(s, k), cfg.interrupted)};
                        if (!res) {
                            if (cfg.interrupted()) {
                                rec.interrupted = true;
                                return;
                            }
                            // A host stalled past the grace, or a previous attempt overran into this
                            // opportunity: skipped rather than dialled late.
                            ++rec.missed_opportunities;
                            LogDebug(BCLog::PRIVBROADCAST, "slot %u opportunity %u: missed\n", s, k);
                            report_progress([](JobProgress& p) { ++p.opportunities_ended; });
                            continue;
                        }
                        // The evidence is kept before anything that could still fail.
                        rec.attempts.push_back(std::move(*res));
                        const AttemptResult& done{rec.attempts.back()};
                        LogDebug(BCLog::PRIVBROADCAST, "slot %u opportunity %u: %s%s\n", s, k, OutcomeName(done.outcome),
                                done.reason.empty() ? "" : strprintf(" (%s)", done.reason));
                        report_progress([&](JobProgress& p) {
                            ++p.opportunities_ended;
                            ++p.connections;
                            if (done.evidence.inv_written) ++p.announcements_written;
                        });
                        if (done.evidence.inv_handed) return; // Nothing after an announcement is replaceable.
                        if (cfg.interrupted()) {
                            rec.interrupted = true;
                            return;
                        }
                    }
                } catch (const std::exception& e) {
                    // The slot ends here; no other slot's times or candidates change. Nothing in a
                    // handler may throw: the record is engaged first and the text copied best effort;
                    // the failure is logged by the main thread after the join.
                    rec.error.emplace();
                    try {
                        *rec.error = e.what();
                    } catch (...) {
                    }
                } catch (...) {
                    rec.error.emplace();
                }
            });
        }
        if (WaitUntilOrInterrupt(schedule.DeliveryStart(), cfg.interrupted, socks_interrupt)) {
            std::string primaries;
            for (uint32_t s = 0; s < plan::SLOTS; ++s) primaries += strprintf(" +%d", count_seconds(schedule.primary[s]));
            LogDebug(BCLog::PRIVBROADCAST, "delivery start: primaries%s s\n", primaries);
        }
        job_thread.Release(); // from here on this thread only waits for the workers
        for (auto& t : threads) t.join();
        for (uint32_t s = 0; s < plan::SLOTS; ++s) {
            if (records[s].interrupted) {
                LogDebug(BCLog::PRIVBROADCAST, "slot %u interrupted\n", s);
            } else if (records[s].error) {
                LogDebug(BCLog::PRIVBROADCAST, "slot %u failed%s\n", s, records[s].error->empty() ? "" : strprintf(": %s", *records[s].error));
            } else {
                ++slots_completed;
            }
        }
        interrupted = cfg.interrupted() || std::any_of(records.begin(), records.end(), [](const SlotRecord& rec) { return rec.interrupted; });
        LogDebug(BCLog::PRIVBROADCAST, "%s\n", interrupted ? "delivery interrupted" : "delivery done");
    }

    watcher_guard.Stop();
    int exit_code{2};
    UniValue json{BuildReport(cfg.chain, cfg.tx, schedule, discovery, records, slots_completed, interrupted, Clock::now(), exit_code)};
    const UniValue& summary{json["summary"]};
    LogDebug(BCLog::PRIVBROADCAST, "job done: connections=%s announcements_written=%s tx_written=%s pongs=%s\n",
            summary["connections"].getValStr(), summary["announcements_written"].getValStr(), summary["tx_written"].getValStr(),
            summary["pongs"].getValStr());
    return JobReport{std::move(json), exit_code};
}

} // namespace privbcast
