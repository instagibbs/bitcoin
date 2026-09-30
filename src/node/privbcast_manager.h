// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_NODE_PRIVBCAST_MANAGER_H
#define BITCOIN_NODE_PRIVBCAST_MANAGER_H

#include <netbase.h>
#include <primitives/transaction.h>
#include <random.h>
#include <privbcast/discovery.h>
#include <privbcast/job.h>
#include <sync.h>
#include <uint256.h>
#include <univalue.h>
#include <util/time.h>
#include <validationinterface.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace node {

/** Default for -privatebroadcast. */
inline constexpr bool DEFAULT_PRIVATE_BROADCAST{false};

/**
 * Runs bitcoin-privbcast jobs inside the node. Each job is one bounded, fixed-schedule broadcast
 * of one transaction (optionally with its unconfirmed parent) over the node's Tor SOCKS5 proxy,
 * exactly as the standalone tool does: raw sockets, its own discovery from the release seeds, no
 * CConnman, PeerManager, addrman or banman involvement. The manager adds only a FIFO of pending
 * transactions, a start gate, retained reports, and one piece of observation for the report: when
 * the node's own mempool first saw the transaction, which never feeds back into a job.
 *
 * The gate starts the next queued job a random interval after the previous start, whether or not
 * earlier jobs have ended, so no recipient can choose when a job starts. Jobs therefore overlap,
 * and there is a worker for every job that can be running at once. A recipient can only keep its
 * job running longer, which decides whether the same transaction submitted again meanwhile is
 * ignored or queued as a new job that takes the next start (see Submit()).
 */
class PrivateBroadcastManager final : public CValidationInterface
{
public:
    /**
     * A queued job starts this long after the previous start, drawn uniformly, whatever has ended.
     * Longer than discovery, so no two jobs resolve seeds at once.
     */
    static constexpr std::chrono::seconds START_SPACING_MIN{35};
    static constexpr std::chrono::seconds START_SPACING_MAX{55};
    static_assert(START_SPACING_MIN > privbcast::disc::WINDOW && START_SPACING_MIN < START_SPACING_MAX);
    /**
     * Workers, one per job that can be running at once: a job's schedule ends within JOB_CAP of its
     * start, and starts are at least START_SPACING_MIN apart. A job still running JOB_CAP after it
     * started, in real time, is stopped. If every worker is busy anyway, the next start waits for
     * one and a warning is logged.
     */
    static constexpr size_t MAX_CONCURRENT_JOBS{(privbcast::plan::JOB_CAP + START_SPACING_MIN - std::chrono::seconds{1}) / START_SPACING_MIN};
    /** Jobs that may wait; a submission beyond this is rejected. */
    static constexpr size_t MAX_QUEUED_JOBS{10'000};
    /** Finished jobs whose reports are kept; the oldest is dropped first. */
    static constexpr size_t MAX_FINISHED_JOBS{100};
    /**
     * File descriptors to reserve at init: one job's discovery queries at a time (every seed times
     * the queries per seed, all open at once; 32 covers the release seed list with room to spare),
     * plus one connection per slot of every running job.
     */
    static constexpr size_t MAX_SOCKETS{32 + MAX_CONCURRENT_JOBS * privbcast::plan::SLOTS};

    enum class JobState : uint8_t { QUEUED, RUNNING, DONE, ABORTED };
    static std::string_view StateName(JobState state);

    struct JobInfo {
        Txid txid;
        Wtxid wtxid;
        std::optional<Txid> parent_txid; //!< set if a package was submitted
        /** The transactions themselves, dropped when the job finishes; the hashes above stay. */
        CTransactionRef tx;
        CTransactionRef parent; //!< null unless a package was submitted
        JobState state{JobState::QUEUED};
        NodeClock::time_point added;
        std::optional<NodeClock::time_point> started;
        std::optional<NodeClock::time_point> ended;
        /** When this node's own mempool first accepted the transaction, if it has; recorded for the report only. */
        std::optional<NodeClock::time_point> seen_in_mempool;
        /** How far a running job has got; meaningful while RUNNING, the report says the rest. */
        privbcast::JobProgress progress;
        /** The tool's JSON report, once the job has run. Shared so snapshots do not copy it. */
        std::shared_ptr<const UniValue> report;
        /** The tool's exit status: 0 at least one announcement written, 2 none. */
        int exit_code{2};
        /** Set if the job could not run at all (no usable Tor proxy), threw, or was cut short by networking being disabled. */
        std::optional<std::string> error;
    };

    /** A job and its cancellation flags, shared by the queue and the worker running it. */
    struct Job {
        JobInfo info; //!< guarded by the manager's m_mutex
        std::atomic<bool> abort{false}; //!< cancelled by Abort() or by networking being disabled
        std::atomic<bool> network_off{false}; //!< saw networking disabled while it ran
        std::atomic<bool> capped{false}; //!< still running JOB_CAP after it started, in real time
        MockableSteadyClock::time_point cap_deadline{}; //!< set when the job starts, read by the worker running it
    };

    /**
     * The manager's bookkeeping without its threads: the FIFO, the start gate, deduplication, aborts,
     * the real-time cap and the retained reports. It reads no clock, blocks on nothing and starts no
     * thread; the caller passes the time and decides when a worker takes a job, so the whole policy
     * can be driven deterministically. Not thread-safe: the manager calls it under m_mutex.
     */
    class Queue
    {
    public:
        enum class Admission : uint8_t { QUEUED, COVERED, FULL };

        Queue(const uint256& seed, size_t max_queued, size_t max_finished);

        /** Queue a job unless one already covers it (see PrivateBroadcastManager::Submit) or the queue is full. */
        Admission Submit(CTransactionRef tx, CTransactionRef parent, NodeClock::time_point now);
        /**
         * Whether the gate lets a queued job start at now. A gate more than START_SPACING_MAX ahead of
         * now, as after the clock stepped back, is first brought back to now + START_SPACING_MAX.
         */
        bool GateOpen(NodeClock::time_point now);
        NodeClock::time_point NextStart() const { return m_next_start; }
        /** Start the oldest queued job, which must exist, and draw when the next one may start. */
        std::shared_ptr<Job> Start(NodeClock::time_point now, MockableSteadyClock::time_point steady_now);
        /** Retire a job that has run: aborted if it was cancelled or capped, done otherwise. */
        void Finish(const std::shared_ptr<Job>& job, NodeClock::time_point now);
        /** See PrivateBroadcastManager::Abort. */
        std::vector<JobInfo> Abort(const uint256& id, NodeClock::time_point now);
        /** Abort every queued job and cancel every running one, recording error; returns their wtxids. */
        std::vector<Wtxid> AbortAll(const std::string& error, NodeClock::time_point now);
        /** Record when the node's mempool first accepted txid, for the report; nothing else changes. */
        void MarkSeen(const Txid& txid, NodeClock::time_point now);
        /** See PrivateBroadcastManager::GetJobs. */
        std::vector<JobInfo> Jobs() const;

        const std::deque<std::shared_ptr<Job>>& Queued() const { return m_queued; }
        const std::vector<std::shared_ptr<Job>>& Running() const { return m_running; }
        const std::deque<std::shared_ptr<Job>>& Finished() const { return m_finished; }

        /**
         * A running job's interruption check: true once the manager is stopping, the job was
         * cancelled, networking is disabled, which cancels it for good, or it has run JOB_CAP in
         * real time, which latches capped.
         */
        static bool Interrupted(Job& job, bool stopping, bool network_active, MockableSteadyClock::time_point now);

    private:
        /** Record a job's end, drop its transactions and keep its report, dropping the oldest beyond the limit. */
        void Retire(std::shared_ptr<Job> job, NodeClock::time_point now);

        const size_t m_max_queued;
        const size_t m_max_finished;
        std::deque<std::shared_ptr<Job>> m_queued;
        std::vector<std::shared_ptr<Job>> m_running;
        std::deque<std::shared_ptr<Job>> m_finished;
        /** When the next queued job may start; the first starts at once. */
        NodeClock::time_point m_next_start{};
        FastRandomContext m_rng;
    };

    struct Options {
        /** The Tor SOCKS5 proxy to use, read when each job starts; nullopt if none is configured. */
        std::function<std::optional<Proxy>()> tor_proxy;
        /**
         * Whether networking is active, read at admission, by the worker waiting to start a job and by
         * running jobs: networking disabled aborts queued jobs and cancels running ones, and
         * re-enabling it revives none.
         */
        std::function<bool()> network_active;
        privbcast::DiscoveryPlan discovery;
        std::string chain;
    };

    /** The proxy a job may use: any valid configured SOCKS5 proxy, trusted like the node's other proxy settings. */
    static bool UsableProxy(const std::optional<Proxy>& proxy);

    /** Starts the workers; if a thread cannot be created, the ones already running are joined and the exception rethrown. */
    explicit PrivateBroadcastManager(Options opts);
    ~PrivateBroadcastManager();

    /**
     * Queue a job. Returns false if the queue is full, the manager is stopping, or networking is
     * inactive. A transaction whose job is still queued, or running and not being aborted, is not
     * queued again, and true is returned: the job must have the same parent, or any parent if none
     * is given now. Otherwise the transaction is queued again, even while an aborted job for it
     * winds down.
     */
    bool Submit(CTransactionRef tx, CTransactionRef parent = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Snapshot of the retained finished jobs, oldest first, then the running and queued ones in order. */
    std::vector<JobInfo> GetJobs() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Abort every queued or running job whose transaction has this txid or wtxid. A queued job is
     * removed; a running one is cancelled and ends shortly with a report of what it did. Returns
     * the jobs as they were found, transactions included; empty if none matched.
     */
    std::vector<JobInfo> Abort(const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Refuse new jobs and cancel running ones; returns at once. */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Interrupt() and join the workers. Idempotent. A job inside the TCP connect to the proxy
     * finishes that connect first, so this may wait up to the proxy connect timeout.
     */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void WorkerLoop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Run(Job& job) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    const Options m_opts;
    mutable Mutex m_mutex;
    std::condition_variable_any m_cv;
    Queue m_queue GUARDED_BY(m_mutex);
    /** Set while a worker waits for the gate, so the others sleep. */
    bool m_gate_waiting GUARDED_BY(m_mutex){false};
    std::atomic<bool> m_stopping{false};
    std::vector<std::thread> m_workers;
};

} // namespace node

#endif // BITCOIN_NODE_PRIVBCAST_MANAGER_H
