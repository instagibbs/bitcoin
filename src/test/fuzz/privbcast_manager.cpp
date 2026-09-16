// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/privbcast_manager.h>
#include <primitives/transaction.h>
#include <privbcast/job.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>
#include <univalue.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using node::PrivateBroadcastManager;
using Admission = PrivateBroadcastManager::Queue::Admission;
using Job = PrivateBroadcastManager::Job;
using JobInfo = PrivateBroadcastManager::JobInfo;
using JobState = PrivateBroadcastManager::JobState;
using Queue = PrivateBroadcastManager::Queue;
using namespace std::chrono_literals;

namespace {

/** Four transactions, each without and with a witness: two wtxids per txid. */
std::vector<CTransactionRef> MakePool()
{
    std::vector<CTransactionRef> pool;
    for (uint8_t k{0}; k < 4; ++k) {
        for (const bool witness : {false, true}) {
            CMutableTransaction mtx;
            mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{k}), 0});
            if (witness) mtx.vin[0].scriptWitness.stack.push_back({k});
            mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
            pool.push_back(MakeTransactionRef(std::move(mtx)));
        }
    }
    return pool;
}

/** One queue and the worker pool around it, as the manager runs them. */
struct Side {
    Queue queue;
    const size_t max_queued;
    const size_t max_finished;
    /** Every start, in order: when, and which transaction. */
    std::vector<std::pair<NodeClock::time_point, Wtxid>> starts;
    /** A start fell due while every worker was busy. */
    bool exhausted{false};
    /**
     * Networking was disabled while every worker was busy, so the queue was not aborted yet: that
     * waits for a job to end, which a recipient can delay. With networking back before then, the
     * queue survives, which it would not have with a worker free.
     */
    bool abort_delayed{false};
    /** The node clock stepped back since the last start. */
    bool stepped_back{false};

    Side(const uint256& seed, size_t max_q, size_t max_f) : queue{seed, max_q, max_f}, max_queued{max_q}, max_finished{max_f} {}

    /** What GetJobs() promises: retained finished jobs oldest first, then running, then queued, each within its limit. */
    void CheckLayout() const
    {
        assert(queue.Queued().size() <= max_queued && queue.Finished().size() <= max_finished);
        assert(queue.Running().size() <= PrivateBroadcastManager::MAX_CONCURRENT_JOBS);
        const auto jobs{queue.Jobs()};
        assert(jobs.size() == queue.Finished().size() + queue.Running().size() + queue.Queued().size());
        size_t k{0};
        for (const auto& j : queue.Finished()) {
            const JobInfo& info{jobs[k++]};
            // The transactions are dropped, the hashes kept.
            assert(info.wtxid == j->info.wtxid && (info.state == JobState::DONE || info.state == JobState::ABORTED));
            assert(!info.tx && !info.parent && info.ended);
        }
        for (const auto& j : queue.Running()) {
            const JobInfo& info{jobs[k++]};
            assert(info.wtxid == j->info.wtxid && info.state == JobState::RUNNING && info.tx && info.started && !info.ended);
        }
        for (const auto& j : queue.Queued()) {
            const JobInfo& info{jobs[k++]};
            assert(info.wtxid == j->info.wtxid && info.state == JobState::QUEUED && info.tx && !info.started);
        }
    }

    /**
     * The workers act at now: each job the gate lets through starts while a worker is free. With
     * networking disabled, the worker at the gate aborts the queue instead.
     */
    void Tick(NodeClock::time_point now, MockableSteadyClock::time_point steady, bool network_active)
    {
        while (!queue.Queued().empty()) {
            if (queue.Running().size() >= PrivateBroadcastManager::MAX_CONCURRENT_JOBS) {
                // Every worker is busy, so none consults the gate: a start that is due slips, and a gate
                // that a stepped-back clock left too far ahead is not brought back yet.
                if (now >= queue.NextStart() || queue.NextStart() > now + PrivateBroadcastManager::START_SPACING_MAX) exhausted = true;
                if (!network_active) abort_delayed = true;
                return;
            }
            if (!network_active) {
                // Every queued job is aborted, not held, and the running ones are marked cancelled.
                const auto queued{queue.Queued()};
                const auto running{queue.Running()};
                const auto aborted{queue.AbortAll("networking deactivated", now)};
                assert(queue.Queued().empty() && aborted.size() == queued.size() + running.size());
                for (const auto& job : queued) assert(job->info.state == JobState::ABORTED && job->info.error == "networking deactivated" && !job->info.tx);
                for (const auto& job : running) assert(job->abort.load() && job->info.error == "networking deactivated" && job->info.state == JobState::RUNNING);
                return;
            }
            if (!queue.GateOpen(now)) {
                // The gate is never further ahead than the longest spacing, even after the clock stepped back.
                assert(queue.NextStart() > now && queue.NextStart() <= now + PrivateBroadcastManager::START_SPACING_MAX);
                return;
            }
            // Starts are at least the shortest spacing apart, longer than discovery takes, unless the clock went back.
            if (!starts.empty() && !stepped_back) assert(now - starts.back().first >= PrivateBroadcastManager::START_SPACING_MIN);
            const std::shared_ptr<Job> next{queue.Queued().front()};
            const auto job{queue.Start(now, steady)};
            // In submission order, capped JOB_CAP later in real time.
            assert(job == next && job->info.state == JobState::RUNNING && job->info.started == now);
            assert(queue.Running().back() == job && job->cap_deadline == steady + privbcast::plan::JOB_CAP);
            // The next start is drawn from [START_SPACING_MIN, START_SPACING_MAX) after this one.
            assert(queue.NextStart() >= now + PrivateBroadcastManager::START_SPACING_MIN);
            assert(queue.NextStart() < now + PrivateBroadcastManager::START_SPACING_MAX);
            starts.emplace_back(now, job->info.wtxid);
            stepped_back = false;
        }
    }

    /** The runner has returned, with an outcome its recipients decided. */
    void Finish(const std::shared_ptr<Job>& job, NodeClock::time_point now, uint8_t outcome)
    {
        if ((outcome & 1) && !job->info.error) job->info.error = "threw";
        job->info.exit_code = outcome & 2 ? 0 : 2;
        if (outcome & 4) job->info.report = std::make_shared<const UniValue>(UniValue::VOBJ);
        const bool cancelled{job->abort.load() || job->capped.load()};
        const std::optional<std::string> error{job->info.error};
        queue.Finish(job, now);
        assert(std::ranges::find(queue.Running(), job) == queue.Running().end());
        assert(!queue.Finished().empty() && queue.Finished().back() == job);
        assert(job->info.state == (cancelled ? JobState::ABORTED : JobState::DONE) && job->info.ended == now);
        assert(!job->info.tx && !job->info.parent);
        // A job cancelled by networking being disabled, or stopped at the cap, says so, unless it had already failed.
        const std::optional<std::string> expected{error                     ? error :
                                                  job->network_off.load() ? std::optional<std::string>{"networking deactivated"} :
                                                  job->capped.load()      ? std::optional<std::string>{"stopped at the job cap"} :
                                                                            std::nullopt};
        assert(job->info.error == expected);
    }

    /**
     * The runner polls its interruption check and returns at once when told to stop: when the
     * manager stops, when the job was cancelled, when networking is disabled, or when it has run
     * JOB_CAP in real time.
     */
    void Poll(NodeClock::time_point now, MockableSteadyClock::time_point steady, bool network_active, FuzzedDataProvider& fdp)
    {
        const std::vector<std::shared_ptr<Job>> running{queue.Running()};
        for (const auto& job : running) {
            const bool aborted{job->abort.load()}, off{job->network_off.load()}, capped{job->capped.load()};
            // Stopping stops every job and marks none.
            assert(Queue::Interrupted(*job, /*stopping=*/true, network_active, steady));
            assert(job->abort.load() == aborted && job->network_off.load() == off && job->capped.load() == capped);
            const bool stop{Queue::Interrupted(*job, /*stopping=*/false, network_active, steady)};
            assert(stop == (aborted || capped || !network_active || steady >= job->cap_deadline));
            // Networking disabled cancels the job for good; only reaching the deadline sets the cap. Both stay set.
            assert(job->network_off.load() == (off || (!aborted && !network_active)));
            assert(job->abort.load() == (aborted || !network_active));
            assert(job->capped.load() == (capped || (!aborted && network_active && steady >= job->cap_deadline)));
            if (stop) Finish(job, now, fdp.ConsumeIntegral<uint8_t>());
        }
    }
};

} // namespace

FUZZ_TARGET(privbcast_manager)
{
    static const std::vector<CTransactionRef> POOL{MakePool()};
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const uint256 seed{ConsumeUInt256(fdp)};
    const size_t max_queued{fdp.ConsumeIntegralInRange<size_t>(1, 8)};
    const size_t max_finished{fdp.ConsumeIntegralInRange<size_t>(1, 8)};
    // Two queues drawing the same spacings see the same submissions, aborts and clocks. Their jobs
    // end at different times with different outcomes, and their mempools see different
    // transactions: that is all the recipients' doing, and none of it may move a later start,
    // except as the design allows (see resubmitted_apart).
    Side real{seed, max_queued, max_finished}, twin{seed, max_queued, max_finished};
    Side* const sides[]{&real, &twin};
    NodeClock::time_point now{std::chrono::seconds{fdp.ConsumeIntegralInRange<int64_t>(0, 4'000'000'000)}};
    MockableSteadyClock::time_point steady{};
    // Set once the node clock moves without the steady clock (setmocktime, a stepped system clock).
    bool wonky{false};
    // Networking, as setnetworkactive leaves it; read by both sides alike.
    bool network_active{true};
    // The design's one exception ("The queue" in doc/design/private-broadcast-tool.md): a transaction
    // whose job is still running is not queued again, and a recipient can keep its job running, so
    // the same transaction submitted again can be ignored on one side and queued on the other. From
    // then on the sides' starts may differ.
    bool resubmitted_apart{false};
    const auto pick_tx = [&] { return POOL[fdp.ConsumeIntegralInRange<size_t>(0, POOL.size() - 1)]; };

    LIMITED_WHILE(fdp.ConsumeBool(), 2000)
    {
        CallOneOf(
            fdp,
            [&] {
                // Submit(), with or without a parent; refused while networking is disabled.
                if (!network_active) return;
                const CTransactionRef tx{pick_tx()};
                CTransactionRef parent;
                if (fdp.ConsumeBool()) {
                    parent = pick_tx();
                    if (parent->GetHash() == tx->GetHash()) parent = nullptr; // a child does not spend itself
                }
                std::optional<Admission> first;
                for (Side* side : sides) {
                    Queue& q{side->queue};
                    // A job still queued, or running and not being aborted, for this wtxid and the same
                    // parent, or no parent on both, covers it. A finished or aborting one does not,
                    // whatever the node's mempool has seen.
                    const auto covers = [&](const std::shared_ptr<Job>& j) {
                        return j->info.wtxid == tx->GetWitnessHash() && !j->info.parent == !parent &&
                               (!parent || j->info.parent->GetWitnessHash() == parent->GetWitnessHash());
                    };
                    const bool covered{std::ranges::any_of(q.Queued(), covers) ||
                                       std::ranges::any_of(q.Running(), [&](const auto& j) { return !j->abort.load() && covers(j); })};
                    const size_t queued{q.Queued().size()}, running{q.Running().size()}, finished{q.Finished().size()};
                    const Admission admission{q.Submit(tx, parent, now)};
                    assert(admission == (covered ? Admission::COVERED : queued >= side->max_queued ? Admission::FULL : Admission::QUEUED));
                    assert(q.Queued().size() == queued + (admission == Admission::QUEUED));
                    assert(q.Running().size() == running && q.Finished().size() == finished);
                    if (first && *first != admission) {
                        // Until then both sides hold the same queue, so they can only disagree over a job that
                        // still runs on one side and has ended on the other: ignored there, queued or turned
                        // away by a full queue here. Only a queued one makes the queues differ.
                        if (!resubmitted_apart && !real.exhausted && !twin.exhausted && !real.abort_delayed && !twin.abort_delayed) {
                            assert((*first == Admission::COVERED) != (admission == Admission::COVERED));
                        }
                        if (*first == Admission::QUEUED || admission == Admission::QUEUED) resubmitted_apart = true;
                    }
                    first = admission;
                    if (admission == Admission::QUEUED) {
                        const JobInfo& info{q.Queued().back()->info};
                        assert(info.state == JobState::QUEUED && info.added == now && info.tx == tx && info.parent == parent);
                        assert(info.txid == tx->GetHash() && info.wtxid == tx->GetWitnessHash());
                        assert(info.parent_txid == (parent ? std::optional{parent->GetHash()} : std::nullopt));
                    }
                }
            },
            [&] {
                for (Side* side : sides) side->Tick(now, steady, network_active);
                // A job ends within its cap, and starts are further apart than the cap divided by the
                // number of workers, so with a sane clock a worker is always free when a start is due.
                assert(wonky || (!real.exhausted && !twin.exhausted));
                // Jobs start whether or not earlier jobs have ended: nothing a recipient does moves when
                // a later job starts, apart from the design's one exception.
                if (!real.exhausted && !twin.exhausted && !real.abort_delayed && !twin.abort_delayed && !resubmitted_apart) assert(real.starts == twin.starts);
            },
            [&] {
                // Time passes on both clocks, and runners notice cancellation and the cap.
                const std::chrono::milliseconds d{fdp.ConsumeIntegralInRange<int64_t>(0, 700'000)};
                now += d;
                steady += d;
                for (Side* side : sides) side->Poll(now, steady, network_active, fdp);
            },
            [&] {
                // The node clock steps alone.
                const std::chrono::seconds d{fdp.ConsumeIntegralInRange<int64_t>(-7200, 7200)};
                now += d;
                wonky = true;
                if (d < 0s) {
                    for (Side* side : sides) side->stepped_back = true;
                }
            },
            [&] {
                // A job returns early, on one side only.
                Side& side{fdp.ConsumeBool() ? real : twin};
                if (side.queue.Running().empty()) return;
                const auto job{side.queue.Running()[fdp.ConsumeIntegralInRange<size_t>(0, side.queue.Running().size() - 1)]};
                side.Finish(job, now, fdp.ConsumeIntegral<uint8_t>());
            },
            [&] {
                // The node's mempool accepts a transaction, on one side only.
                Side& side{fdp.ConsumeBool() ? real : twin};
                const Txid txid{fdp.ConsumeBool() ? pick_tx()->GetHash() : Txid::FromUint256(ConsumeUInt256(fdp))};
                const auto before{side.queue.Jobs()};
                const auto next_start{side.queue.NextStart()};
                side.queue.MarkSeen(txid, now);
                const auto after{side.queue.Jobs()};
                // Recorded for the report, the first time only; nothing else changes.
                assert(after.size() == before.size() && side.queue.NextStart() == next_start);
                for (size_t k{0}; k < after.size(); ++k) {
                    assert(after[k].wtxid == before[k].wtxid && after[k].state == before[k].state && after[k].tx == before[k].tx);
                    const bool first{!before[k].seen_in_mempool && before[k].txid == txid};
                    assert(after[k].seen_in_mempool == (first ? std::optional{now} : before[k].seen_in_mempool));
                }
            },
            [&] {
                // abortprivatebroadcast, by txid or wtxid.
                uint256 id{ConsumeUInt256(fdp)};
                if (fdp.ConsumeBool()) {
                    const CTransactionRef tx{pick_tx()};
                    id = fdp.ConsumeBool() ? tx->GetHash().ToUint256() : tx->GetWitnessHash().ToUint256();
                }
                for (Side* side : sides) {
                    Queue& q{side->queue};
                    const auto match = [&](const std::shared_ptr<Job>& j) { return j->info.txid.ToUint256() == id || j->info.wtxid.ToUint256() == id; };
                    std::vector<std::shared_ptr<Job>> queued, running;
                    std::ranges::copy_if(q.Queued(), std::back_inserter(queued), match);
                    std::ranges::copy_if(q.Running(), std::back_inserter(running), match);
                    const size_t queued_before{q.Queued().size()};
                    const auto found{q.Abort(id, now)};
                    // Every matching queued or running job, as found, transactions included: a queued one
                    // is removed and retained as aborted, a running one cancelled and left to end.
                    assert(found.size() == queued.size() + running.size());
                    for (size_t k{0}; k < queued.size(); ++k) {
                        assert(found[k].wtxid == queued[k]->info.wtxid && found[k].state == JobState::ABORTED && found[k].tx);
                        assert(queued[k]->info.state == JobState::ABORTED && queued[k]->info.ended == now && !queued[k]->info.tx);
                    }
                    for (size_t k{0}; k < running.size(); ++k) {
                        const JobInfo& info{found[queued.size() + k]};
                        assert(info.wtxid == running[k]->info.wtxid && info.state == JobState::RUNNING && info.tx);
                        assert(running[k]->abort.load() && std::ranges::find(q.Running(), running[k]) != q.Running().end());
                    }
                    assert(q.Queued().size() == queued_before - queued.size() && std::ranges::none_of(q.Queued(), match));
                    if (!queued.empty()) assert(q.Finished().back() == queued.back());
                }
            },
            [&] {
                // setnetworkactive: the worker at the gate and every running job read the flag themselves.
                network_active = fdp.ConsumeBool();
            },
            [&] {
                // getprivatebroadcastinfo.
                for (Side* side : sides) side->CheckLayout();
            });
    }
}
