// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_NODE_PRIVBCAST_MANAGER_H
#define BITCOIN_NODE_PRIVBCAST_MANAGER_H

#include <netbase.h>
#include <primitives/transaction.h>
#include <privbcast/discovery.h>
#include <privbcast/job.h>
#include <sync.h>
#include <univalue.h>
#include <util/btcsignals.h>
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
 * transactions, a small pool of workers, retained reports, and one piece of observation for the
 * report: when the node's own mempool first saw the transaction, which never feeds back into a
 * job.
 *
 * Known residual: a job ends when its last announced connection ends, and its worker then takes
 * the next queued job. A recipient that holds or drops a connection can therefore shift when the
 * next queued job starts by up to that connection's lifetime. That is a conditional link between
 * two transactions from one node, not a node identifier, and is accepted for simplicity.
 */
class PrivateBroadcastManager final : public CValidationInterface
{
public:
    /** Jobs running at once; the rest wait in submission order. */
    static constexpr size_t MAX_CONCURRENT_JOBS{2};
    /** Jobs that may wait; a submission beyond this is rejected. */
    static constexpr size_t MAX_QUEUED_JOBS{100};
    /** Finished jobs whose reports are kept; the oldest is dropped first. */
    static constexpr size_t MAX_FINISHED_JOBS{100};
    /**
     * File descriptors to reserve at init: each running job holds at most its discovery queries
     * (every seed times the queries per seed, all open at once) or its slot connections, plus the
     * proxy control sockets; 32 covers the release seed list with room to spare.
     */
    static constexpr size_t MAX_SOCKETS{MAX_CONCURRENT_JOBS * 32};

    enum class JobState : uint8_t { QUEUED, RUNNING, DONE, ABORTED };
    static std::string_view StateName(JobState state);

    struct JobInfo {
        uint64_t id{0};
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

    struct Options {
        /** The Tor SOCKS5 proxy to use, read when each job starts; nullopt if none is configured. */
        std::function<std::optional<Proxy>()> tor_proxy;
        /** Whether networking is active, checked at admission; see SubscribeNetworkActive for cancellation. */
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
     * Latch cancellation onto networking being disabled: when the signal fires with false, every
     * queued job is aborted and every running one cancelled, and re-enabling does not revive them.
     */
    void SubscribeNetworkActive(btcsignals::signal<void(bool)>& network_active_changed);
    void OnNetworkActiveChanged(bool active) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Queue a job. Returns its id, or nullopt if the queue is full, the manager is stopping, or
     * networking is inactive. The same transaction may be queued more than once; each is a job.
     */
    std::optional<uint64_t> Submit(CTransactionRef tx, CTransactionRef parent = nullptr) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Snapshot of every queued, running and retained finished job, oldest first. */
    std::vector<JobInfo> GetJobs() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Abort a job. A queued job is removed; a running one is cancelled and ends shortly with a
     * report of what it did. Returns the job as it was found, or nullopt if unknown or finished.
     */
    std::optional<JobInfo> Abort(uint64_t id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Refuse new jobs and cancel running ones; returns at once. */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Interrupt() and join the workers. Idempotent. A job inside the TCP connect to the proxy
     * finishes that connect first, so this may wait up to the proxy connect timeout.
     */
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Job {
        JobInfo info; //!< guarded by the manager's m_mutex
        std::atomic<bool> abort{false};
    };

    void WorkerLoop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Run(Job& job) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Move a queued job to the finished list as aborted. */
    void FinishQueued(std::shared_ptr<Job> job, std::optional<std::string> error) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const Options m_opts;
    std::optional<btcsignals::scoped_connection> m_network_active_conn;
    mutable Mutex m_mutex;
    std::condition_variable_any m_cv;
    std::deque<std::shared_ptr<Job>> m_queued GUARDED_BY(m_mutex);
    std::vector<std::shared_ptr<Job>> m_running GUARDED_BY(m_mutex);
    std::deque<std::shared_ptr<Job>> m_finished GUARDED_BY(m_mutex);
    uint64_t m_next_id GUARDED_BY(m_mutex){1};
    std::atomic<bool> m_stopping{false};
    std::vector<std::thread> m_workers;
};

} // namespace node

#endif // BITCOIN_NODE_PRIVBCAST_MANAGER_H
