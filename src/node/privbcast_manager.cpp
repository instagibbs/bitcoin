// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/privbcast_manager.h>

#include <kernel/mempool_entry.h>
#include <logging.h>
#include <privbcast/job.h>
#include <util/thread.h>
#include <util/threadnames.h>

#include <algorithm>
#include <cassert>
#include <exception>
#include <utility>

namespace node {

std::string_view PrivateBroadcastManager::StateName(JobState state)
{
    switch (state) {
    case JobState::QUEUED: return "queued";
    case JobState::RUNNING: return "running";
    case JobState::DONE: return "done";
    case JobState::ABORTED: return "aborted";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

bool PrivateBroadcastManager::UsableProxy(const std::optional<Proxy>& proxy)
{
    return proxy && proxy->IsValid();
}

PrivateBroadcastManager::Queue::Queue(const uint256& seed, size_t max_queued, size_t max_finished)
    : m_max_queued{max_queued}, m_max_finished{max_finished}, m_rng{seed} {}

auto PrivateBroadcastManager::Queue::Submit(CTransactionRef tx, CTransactionRef parent, NodeClock::time_point now) -> Admission
{
    const Wtxid wtxid{tx->GetWitnessHash()};
    // A job for the same transaction that is still queued, or running and not being aborted,
    // already covers it: with the same parent, or with any parent if none was given, as a job that
    // serves a parent announces the child too. A job without a parent does not cover a package.
    const auto same = [&](const std::shared_ptr<Job>& j) {
        return j->info.wtxid == wtxid &&
               (!parent || (j->info.parent && j->info.parent->GetWitnessHash() == parent->GetWitnessHash()));
    };
    if (std::ranges::any_of(m_queued, same) ||
        std::ranges::any_of(m_running, [&](const std::shared_ptr<Job>& j) { return !j->abort.load() && same(j); })) {
        return Admission::COVERED;
    }
    if (m_queued.size() >= m_max_queued) return Admission::FULL;
    auto job{std::make_shared<Job>()};
    job->info.txid = tx->GetHash();
    job->info.wtxid = wtxid;
    if (parent) job->info.parent_txid = parent->GetHash();
    job->info.tx = std::move(tx);
    job->info.parent = std::move(parent);
    job->info.added = now;
    m_queued.push_back(std::move(job));
    return Admission::QUEUED;
}

bool PrivateBroadcastManager::Queue::GateOpen(NodeClock::time_point now)
{
    // A clock that stepped back would otherwise hold the queue until it caught up.
    m_next_start = std::min(m_next_start, now + START_SPACING_MAX);
    return now >= m_next_start;
}

auto PrivateBroadcastManager::Queue::Start(NodeClock::time_point now, MockableSteadyClock::time_point steady_now) -> std::shared_ptr<Job>
{
    assert(!m_queued.empty());
    auto job{std::move(m_queued.front())};
    m_queued.pop_front();
    job->info.state = JobState::RUNNING;
    job->info.started = now;
    job->cap_deadline = steady_now + privbcast::plan::JOB_CAP;
    m_next_start = now + START_SPACING_MIN + m_rng.randrange<std::chrono::milliseconds>(START_SPACING_MAX - START_SPACING_MIN);
    m_running.push_back(job);
    return job;
}

void PrivateBroadcastManager::Queue::Finish(const std::shared_ptr<Job>& job, NodeClock::time_point now)
{
    m_running.erase(std::remove(m_running.begin(), m_running.end(), job), m_running.end());
    if (job->network_off.load() && !job->info.error) job->info.error = "networking deactivated";
    if (job->capped.load() && !job->info.error) job->info.error = "stopped at the job cap";
    job->info.state = job->abort.load() || job->capped.load() ? JobState::ABORTED : JobState::DONE;
    Retire(job, now);
}

void PrivateBroadcastManager::Queue::Retire(std::shared_ptr<Job> job, NodeClock::time_point now)
{
    job->info.ended = now;
    job->info.tx.reset();
    job->info.parent.reset();
    m_finished.push_back(std::move(job));
    while (m_finished.size() > m_max_finished) m_finished.pop_front();
}

auto PrivateBroadcastManager::Queue::Abort(const uint256& id, NodeClock::time_point now) -> std::vector<JobInfo>
{
    std::vector<JobInfo> found;
    const auto match = [&](const JobInfo& info) { return info.txid.ToUint256() == id || info.wtxid.ToUint256() == id; };
    for (auto it = m_queued.begin(); it != m_queued.end();) {
        if (!match((*it)->info)) {
            ++it;
            continue;
        }
        auto job{std::move(*it)};
        it = m_queued.erase(it);
        CTransactionRef tx{job->info.tx}, parent{job->info.parent};
        job->info.state = JobState::ABORTED;
        Retire(job, now);
        found.push_back(job->info);
        found.back().tx = std::move(tx);
        found.back().parent = std::move(parent);
    }
    for (const auto& job : m_running) {
        if (!match(job->info)) continue;
        job->abort.store(true);
        found.push_back(job->info);
    }
    return found;
}

auto PrivateBroadcastManager::Queue::AbortAll(const std::string& error, NodeClock::time_point now) -> std::vector<Wtxid>
{
    std::vector<Wtxid> aborted;
    while (!m_queued.empty()) {
        auto job{std::move(m_queued.front())};
        m_queued.pop_front();
        aborted.push_back(job->info.wtxid);
        job->info.state = JobState::ABORTED;
        job->info.error = error;
        Retire(std::move(job), now);
    }
    for (const auto& job : m_running) {
        job->abort.store(true);
        job->info.error = error;
        aborted.push_back(job->info.wtxid);
    }
    return aborted;
}

void PrivateBroadcastManager::Queue::MarkSeen(const Txid& txid, NodeClock::time_point now)
{
    const auto mark = [&](const std::shared_ptr<Job>& job) {
        if (job->info.txid == txid && !job->info.seen_in_mempool) job->info.seen_in_mempool = now;
    };
    for (const auto& j : m_queued) mark(j);
    for (const auto& j : m_running) mark(j);
    for (const auto& j : m_finished) mark(j);
}

auto PrivateBroadcastManager::Queue::Jobs() const -> std::vector<JobInfo>
{
    std::vector<JobInfo> out;
    out.reserve(m_finished.size() + m_running.size() + m_queued.size());
    for (const auto& j : m_finished) out.push_back(j->info);
    for (const auto& j : m_running) out.push_back(j->info);
    for (const auto& j : m_queued) out.push_back(j->info);
    return out;
}

bool PrivateBroadcastManager::Queue::Interrupted(Job& job, bool stopping, bool network_active, MockableSteadyClock::time_point now)
{
    if (stopping || job.abort.load()) return true;
    if (!network_active) {
        job.network_off.store(true);
        job.abort.store(true); // for good: networking coming back does not revive the job
        return true;
    }
    if (now < job.cap_deadline) return false;
    job.capped.store(true);
    return true;
}

PrivateBroadcastManager::PrivateBroadcastManager(Options opts)
    : m_opts{std::move(opts)}, m_queue{GetRandHash(), MAX_QUEUED_JOBS, MAX_FINISHED_JOBS}
{
    try {
        for (size_t i = 0; i < MAX_CONCURRENT_JOBS; ++i) {
            m_workers.emplace_back(&util::TraceThread, strprintf("privbcast.%u", i), [this] { WorkerLoop(); });
        }
    } catch (...) {
        Stop(); // the destructor does not run for a failed constructor; a joinable thread would terminate
        throw;
    }
}

PrivateBroadcastManager::~PrivateBroadcastManager()
{
    Stop();
}

bool PrivateBroadcastManager::Submit(CTransactionRef tx, CTransactionRef parent)
{
    const Wtxid wtxid{tx->GetWitnessHash()};
    Queue::Admission admission;
    {
        LOCK(m_mutex);
        // Admission is decided under the lock so nothing can be queued after Interrupt() has been observed by a worker.
        if (m_stopping.load() || !m_opts.network_active()) return false;
        admission = m_queue.Submit(std::move(tx), std::move(parent), NodeClock::now());
    }
    switch (admission) {
    case Queue::Admission::FULL:
        return false;
    case Queue::Admission::COVERED:
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s already queued or running, not queued again\n", wtxid.ToString());
        return true;
    case Queue::Admission::QUEUED:
        m_cv.notify_one();
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s queued\n", wtxid.ToString());
        return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::vector<PrivateBroadcastManager::JobInfo> PrivateBroadcastManager::GetJobs() const
{
    return WITH_LOCK(m_mutex, return m_queue.Jobs());
}

std::vector<PrivateBroadcastManager::JobInfo> PrivateBroadcastManager::Abort(const uint256& id)
{
    // Logging happens after the lock is released: the receipt callback takes this lock on the
    // validation thread and must never wait on the logger.
    const auto found{WITH_LOCK(m_mutex, return m_queue.Abort(id, NodeClock::now()))};
    for (const JobInfo& job : found) {
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s %s\n", job.wtxid.ToString(), job.state == JobState::RUNNING ? "abort requested" : "aborted while queued");
    }
    return found;
}

void PrivateBroadcastManager::Interrupt()
{
    // Set under the lock the workers wait with, so a worker cannot test the predicate, miss the
    // notification and sleep through Stop().
    WITH_LOCK(m_mutex, m_stopping.store(true));
    m_cv.notify_all();
}

void PrivateBroadcastManager::Stop()
{
    Interrupt();
    for (auto& w : m_workers) {
        if (w.joinable()) w.join();
    }
    m_workers.clear();
}

void PrivateBroadcastManager::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t)
{
    // Observation for the report only: nothing here touches a job's schedule, queue position or
    // lifetime. Kept short; the caller holds the validation queue.
    const auto now{NodeClock::now()};
    LOCK(m_mutex);
    m_queue.MarkSeen(tx.info.m_tx->GetHash(), now);
}

void PrivateBroadcastManager::WorkerLoop()
{
    while (true) {
        std::shared_ptr<Job> job;
        std::vector<Wtxid> aborted;
        bool full{false};
        {
            WAIT_LOCK(m_mutex, lock);
            while (true) {
                // One worker at a time waits for the gate; the others sleep until it has taken a job.
                m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_stopping.load() || (!m_queue.Queued().empty() && !m_gate_waiting); });
                if (m_stopping.load()) return;
                const auto now{NodeClock::now()};
                // Networking disabled aborts the queue rather than holding it; running jobs see it themselves.
                if (!m_opts.network_active()) {
                    aborted = m_queue.AbortAll("networking deactivated", now);
                    break;
                }
                if (m_queue.GateOpen(now)) {
                    job = m_queue.Start(NodeClock::now(), MockableSteadyClock::now());
                    full = m_queue.Running().size() >= MAX_CONCURRENT_JOBS;
                    if (!m_queue.Queued().empty()) m_cv.notify_one(); // another worker takes over the wait for the next start
                    break;
                }
                // The clock and networking are re-read at least every 100 ms, so the gate follows setmocktime.
                m_gate_waiting = true;
                m_cv.wait_for(lock, std::min<NodeClock::duration>(m_queue.NextStart() - now, 100ms));
                m_gate_waiting = false;
            }
        }
        for (const Wtxid& wtxid : aborted) LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s aborted: networking deactivated\n", wtxid.ToString());
        if (!job) continue;
        if (full) {
            // Only possible if a job outlived its cap or the clock misbehaved: the next start then waits for a worker.
            LogWarning("All %u private broadcast workers are busy; the next queued job will start when one finishes, not on schedule\n", MAX_CONCURRENT_JOBS);
        }
        Run(*job);
        WITH_LOCK(m_mutex, m_queue.Finish(job, NodeClock::now()));
    }
}

void PrivateBroadcastManager::Run(Job& job)
{
    Wtxid wtxid;
    CTransactionRef tx, parent;
    {
        LOCK(m_mutex);
        wtxid = job.info.wtxid;
        tx = job.info.tx;
        parent = job.info.parent;
    }
    std::optional<std::string> error;
    try {
        // Checked again here in case the proxy changed since admission. As for the node's other
        // connections, the configured proxy and the path to it are trusted: SOCKS5 carries the
        // destination and credentials in plaintext.
        const std::optional<Proxy> tor{m_opts.tor_proxy()};
        if (!UsableProxy(tor)) throw std::runtime_error("no Tor SOCKS5 proxy is configured");
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s starting\n", wtxid.ToString());
        privbcast::JobConfig cfg;
        cfg.tx = tx;
        cfg.parent = parent;
        cfg.tor = *tor;
        cfg.discovery = m_opts.discovery;
        cfg.chain = m_opts.chain;
        // Cancellation is latched: Stop(), Abort() and networking being disabled all set a flag that
        // is never cleared, and the real-time cap deadline, set when the job started, only ever
        // passes. Nothing observed later (networking coming back) can revive the job, and a job still
        // running JOB_CAP after it started, whatever the node clock did, is stopped, so its worker
        // always comes back.
        cfg.interrupted = [this, &job] { return Queue::Interrupted(job, m_stopping.load(), m_opts.network_active(), MockableSteadyClock::now()); };
        cfg.on_progress = [this, &job](const privbcast::JobProgress& progress) {
            LOCK(m_mutex);
            job.info.progress = progress;
        };
        privbcast::JobReport report{privbcast::RunJob(cfg)};
        auto json{std::make_shared<const UniValue>(std::move(report.json))};
        LOCK(m_mutex);
        job.info.report = std::move(json);
        job.info.exit_code = report.exit_code;
    } catch (const std::exception& e) {
        error = e.what();
        LOCK(m_mutex);
        if (!job.info.error) job.info.error = error;
    } catch (...) {
        // The worker runs under TraceThread, which rethrows: nothing may escape a job.
        error = "unknown exception";
        LOCK(m_mutex);
        if (!job.info.error) job.info.error = error;
    }
    if (job.capped.load()) {
        // Finish() records it as aborted with the cap as its error, like any other cancellation; the
        // default log names no transaction.
        LogWarning("A private broadcast job was still running %d minutes after it started and was stopped\n",
                   Ticks<std::chrono::minutes>(privbcast::plan::JOB_CAP));
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s stopped at the job cap\n", wtxid.ToString());
    } else if (error) {
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s not run: %s\n", wtxid.ToString(), *error);
    } else {
        LogDebug(BCLog::PRIVBROADCAST, "job wtxid=%s ended\n", wtxid.ToString());
    }
}

} // namespace node
