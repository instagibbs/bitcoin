// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/privbcast_manager.h>

#include <kernel/mempool_entry.h>
#include <logging.h>
#include <privbcast/input.h>
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
    return proxy && proxy->IsValid() && (proxy->m_is_unix_socket || privbcast::IsLoopback(proxy->proxy));
}

PrivateBroadcastManager::PrivateBroadcastManager(Options opts) : m_opts{std::move(opts)}
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

void PrivateBroadcastManager::SubscribeNetworkActive(btcsignals::signal<void(bool)>& network_active_changed)
{
    m_network_active_conn.emplace(network_active_changed.connect([this](bool active) { OnNetworkActiveChanged(active); }));
}

void PrivateBroadcastManager::FinishQueued(std::shared_ptr<Job> job, std::optional<std::string> error)
{
    job->info.state = JobState::ABORTED;
    job->info.ended = NodeClock::now();
    job->info.error = std::move(error);
    m_finished.push_back(std::move(job));
    while (m_finished.size() > MAX_FINISHED_JOBS) m_finished.pop_front();
}

void PrivateBroadcastManager::OnNetworkActiveChanged(bool active)
{
    if (active) return; // nothing is revived: cancellation is latched per job
    std::vector<uint64_t> aborted;
    {
        LOCK(m_mutex);
        while (!m_queued.empty()) {
            auto job{std::move(m_queued.front())};
            m_queued.pop_front();
            aborted.push_back(job->info.id);
            FinishQueued(std::move(job), "networking deactivated");
        }
        for (const auto& job : m_running) {
            job->abort.store(true);
            job->info.error = "networking deactivated";
            aborted.push_back(job->info.id);
        }
    }
    for (const uint64_t id : aborted) LogDebug(BCLog::PRIVBROADCAST, "job %u aborted: networking deactivated\n", id);
}

std::optional<uint64_t> PrivateBroadcastManager::Submit(CTransactionRef tx, CTransactionRef parent)
{
    auto job{std::make_shared<Job>()};
    uint64_t id;
    {
        LOCK(m_mutex);
        // Admission is decided under the lock so nothing can be queued after Interrupt() has been observed by a worker.
        if (m_stopping.load() || !m_opts.network_active() || m_queued.size() >= MAX_QUEUED_JOBS) return std::nullopt;
        id = m_next_id++;
        job->info.id = id;
        job->info.tx = std::move(tx);
        job->info.parent = std::move(parent);
        job->info.added = NodeClock::now();
        m_queued.push_back(std::move(job));
    }
    m_cv.notify_one();
    LogDebug(BCLog::PRIVBROADCAST, "job %u queued\n", id);
    return id;
}

std::vector<PrivateBroadcastManager::JobInfo> PrivateBroadcastManager::GetJobs() const
{
    std::vector<JobInfo> out;
    {
        LOCK(m_mutex);
        out.reserve(m_finished.size() + m_running.size() + m_queued.size());
        for (const auto& j : m_finished) out.push_back(j->info);
        for (const auto& j : m_running) out.push_back(j->info);
        for (const auto& j : m_queued) out.push_back(j->info);
    }
    std::stable_sort(out.begin(), out.end(), [](const JobInfo& a, const JobInfo& b) { return a.id < b.id; });
    return out;
}

std::optional<PrivateBroadcastManager::JobInfo> PrivateBroadcastManager::Abort(uint64_t id)
{
    // Logging happens after the lock is released: the receipt callback takes this lock on the
    // validation thread and must never wait on the logger.
    std::optional<JobInfo> found;
    const char* what{nullptr};
    {
        LOCK(m_mutex);
        for (auto it = m_queued.begin(); it != m_queued.end(); ++it) {
            if ((*it)->info.id != id) continue;
            auto job{*it};
            m_queued.erase(it);
            FinishQueued(job, std::nullopt);
            found = job->info;
            what = "aborted while queued";
            break;
        }
        if (!found) {
            for (const auto& job : m_running) {
                if (job->info.id != id) continue;
                job->abort.store(true);
                found = job->info;
                what = "abort requested";
                break;
            }
        }
    }
    if (found) LogDebug(BCLog::PRIVBROADCAST, "job %u %s\n", id, what);
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
    m_network_active_conn.reset();
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
    const Txid& txid{tx.info.m_tx->GetHash()};
    const auto now{NodeClock::now()};
    LOCK(m_mutex);
    const auto mark = [&](const std::shared_ptr<Job>& job) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        if (job->info.tx->GetHash() == txid && !job->info.seen_in_mempool) job->info.seen_in_mempool = now;
    };
    for (const auto& j : m_queued) mark(j);
    for (const auto& j : m_running) mark(j);
    for (const auto& j : m_finished) mark(j);
}

void PrivateBroadcastManager::WorkerLoop()
{
    while (true) {
        std::shared_ptr<Job> job;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_stopping.load() || !m_queued.empty(); });
            if (m_stopping.load()) return;
            job = std::move(m_queued.front());
            m_queued.pop_front();
            job->info.state = JobState::RUNNING;
            job->info.started = NodeClock::now();
            m_running.push_back(job);
        }
        Run(*job);
        {
            LOCK(m_mutex);
            m_running.erase(std::remove(m_running.begin(), m_running.end(), job), m_running.end());
            job->info.state = job->abort.load() ? JobState::ABORTED : JobState::DONE;
            job->info.ended = NodeClock::now();
            m_finished.push_back(std::move(job));
            while (m_finished.size() > MAX_FINISHED_JOBS) m_finished.pop_front();
        }
    }
}

void PrivateBroadcastManager::Run(Job& job)
{
    uint64_t id;
    CTransactionRef tx, parent;
    {
        LOCK(m_mutex);
        id = job.info.id;
        tx = job.info.tx;
        parent = job.info.parent;
    }
    std::optional<std::string> error;
    try {
        // The same trust boundary as the tool's -tor, checked again here in case the proxy changed
        // since admission: the SOCKS listener is on this host, so nothing on the path to it can read
        // destinations or credentials.
        const std::optional<Proxy> tor{m_opts.tor_proxy()};
        if (!UsableProxy(tor)) throw std::runtime_error("no local Tor SOCKS5 proxy is configured");
        LogDebug(BCLog::PRIVBROADCAST, "job %u starting\n", id);
        privbcast::JobConfig cfg;
        cfg.tx = tx;
        cfg.parent = parent;
        cfg.tor = *tor;
        cfg.discovery = m_opts.discovery;
        cfg.chain = m_opts.chain;
        // Cancellation is latched: Stop(), Abort() and networking being disabled all set a flag that
        // is never cleared, so nothing observed later (networking coming back) can revive the job.
        cfg.interrupted = [this, &job] { return m_stopping.load() || job.abort.load(); };
        privbcast::JobReport report{privbcast::RunJob(cfg)};
        auto json{std::make_shared<const UniValue>(std::move(report.json))};
        LOCK(m_mutex);
        job.info.report = std::move(json);
        job.info.exit_code = report.exit_code;
    } catch (const std::exception& e) {
        error = e.what();
        LOCK(m_mutex);
        if (!job.info.error) job.info.error = error;
    }
    if (error) {
        LogDebug(BCLog::PRIVBROADCAST, "job %u not run: %s\n", id, *error);
    } else {
        LogDebug(BCLog::PRIVBROADCAST, "job %u ended\n", id);
    }
}

} // namespace node
