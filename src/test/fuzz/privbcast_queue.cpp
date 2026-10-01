// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/privbcast.h>
#include <primitives/transaction.h>
#include <privbcast/job.h>
#include <privbcast/params.h>
#include <privbcast/report.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/privbcast_queue.h>
#include <test/util/random.h>
#include <test/util/time.h>
#include <uint256.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using node::PrivbcastQueue;
using Policy = PrivbcastQueue::StartPolicy;
using SubmitResult = PrivbcastQueue::SubmitResult;
using namespace std::chrono_literals;
using std::chrono::milliseconds;

namespace {

/** Six transactions, each with two witnesses: two wtxids per txid, so that a witness variant gets a
 *  job of its own (N5). */
const std::vector<CTransactionRef>& Pool()
{
    static const std::vector<CTransactionRef> pool{[] {
        std::vector<CTransactionRef> txs;
        for (uint32_t n{0}; n < 6; ++n) {
            for (const uint8_t witness : {1, 2}) {
                CMutableTransaction tx;
                tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), n});
                tx.vin[0].scriptWitness.stack.push_back({witness});
                tx.vout.emplace_back(10'000, CScript{} << OP_TRUE);
                txs.push_back(MakeTransactionRef(std::move(tx)));
            }
        }
        return txs;
    }()};
    return pool;
}

/**
 * Stands in for privbcast::Job on the queue's job threads. A run passes on the end of its discovery
 * and ends only when the target says, so that the target decides how far every job gets and when
 * it ends, whatever the threads do.
 */
class Runner
{
public:
    /** How a run ends: as a job that wrote this many INVs in full and, if error is set, failed with
     *  it, or as one whose run throws error. */
    struct Ending {
        int announcements{0};
        std::optional<std::string> error{};
        bool thrown{false};
    };

    privbcast::Report Run(const privbcast::JobInputs& inputs, const PrivbcastQueue::ProgressCallback& progress) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        Entry& run{m_runs.emplace_back()};
        m_cv.notify_all();
        while (!run.ending && !m_closed) {
            if (run.discover && !run.discovered) {
                {
                    REVERSE_LOCK(lock, m_mutex);
                    progress(privbcast::Progress{.discovery_done = true});
                }
                run.discovered = true;
                m_cv.notify_all();
                continue;
            }
            m_cv.wait(lock);
        }
        const Ending ending{run.ending.value_or(Ending{})};
        if (ending.thrown) throw std::runtime_error{ending.error.value_or("")};
        privbcast::Report report;
        report.txid = inputs.tx->GetHash();
        report.wtxid = inputs.tx->GetWitnessHash();
        report.chain = inputs.chain;
        report.summary.announcements_written = ending.announcements;
        report.summary.interrupted = inputs.cancel->load();
        report.summary.error = ending.error;
        return report;
    }

    /** Wait until n runs have begun. */
    void WaitForRuns(size_t n) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        assert(m_cv.wait_for(lock, 60s, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_runs.size() >= n; }));
    }
    /** Have run i pass on the end of its discovery, and wait until it has. */
    void Discover(size_t i) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_runs.at(i).discover = true;
        m_cv.notify_all();
        assert(m_cv.wait_for(lock, 60s, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_runs.at(i).discovered; }));
    }
    void End(size_t i, Ending ending) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_runs.at(i).ending = std::move(ending);
        m_cv.notify_all();
    }
    /** Have every run, begun or not, end at once. */
    void Close() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        m_closed = true;
        m_cv.notify_all();
    }

private:
    struct Entry {
        bool discover{false};
        bool discovered{false};
        std::optional<Ending> ending;
    };

    Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Entry> m_runs GUARDED_BY(m_mutex);
    bool m_closed GUARDED_BY(m_mutex){false};
};

/** Starts the queue's job threads, or fails to when told, and counts the threads that are done. */
class Threads
{
public:
    std::thread Launch(std::function<void()> run)
    {
        if (std::exchange(m_fail_next, false)) throw std::system_error{std::make_error_code(std::errc::resource_unavailable_try_again)};
        return std::thread{[this, run = std::move(run)] {
            run();
            LOCK(m_mutex);
            ++m_done;
            m_cv.notify_all();
        }};
    }
    /** The next launch fails. Only the target's thread uses it: the queue launches under Poll(). */
    void FailNext() { m_fail_next = true; }
    bool FailsNext() const { return m_fail_next; }
    /** Wait until n threads are done. */
    void WaitForDone(size_t n) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        assert(m_cv.wait_for(lock, 60s, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_done >= n; }));
    }

private:
    bool m_fail_next{false};
    Mutex m_mutex;
    std::condition_variable m_cv;
    size_t m_done GUARDED_BY(m_mutex){0};
};

/** One queue as the start rule sees it, driven by StartPolicy as Poll() drives it, with a model of
 *  what the rule must decide. */
struct Side {
    struct Job {
        int id{0};
        NodeClock::time_point started{};
        MockableSteadyClock::time_point steady_started{};
        bool cancelled{false};
        bool discovery_done{false};
    };

    /** Jobs that run at once, at most. */
    size_t max_concurrent{PrivbcastQueue::MAX_CONCURRENT_JOBS};
    std::optional<NodeClock::time_point> last_poll;
    /** The end of the window, as the model has it: a drawn spacing after the last start, or after
     *  the last step back of the clock since (N3). */
    std::optional<NodeClock::time_point> window_end;
    /** The last start, or the last step back since: the next start is at least START_SPACING_MIN
     *  after it. */
    std::optional<NodeClock::time_point> spaced_from;
    std::deque<int> queued;
    std::vector<Job> running;
    /** Every start: when, and which job. */
    std::vector<std::pair<NodeClock::time_point, int>> starts;

    /** A pass of the scheduler. When sane, with the node clock never stepped back and as many
     *  jobs allowed at once as the node allows, a start that the window allows waits for no running
     *  job. */
    void Pass(NodeClock::time_point now, MockableSteadyClock::time_point steady_now, milliseconds spacing, bool network, bool proxy, bool sane)
    {
        std::vector<Policy::RunningJob> jobs;
        for (const Job& job : running) jobs.push_back({.steady_started = job.steady_started, .cancelled = job.cancelled, .discovery_done = job.discovery_done});
        const Policy::Snapshot snapshot{
            .last_poll = last_poll,
            .next_start = window_end,
            .running = std::move(jobs),
            .queued = !queued.empty(),
            .max_concurrent = max_concurrent,
            .network_active = network,
            .proxy = proxy,
        };
        const Policy::Decision decision{Policy::Decide(snapshot, now, steady_now, spacing)};

        // N3: once a job has started, a pass that reads the clock earlier than the one before opens
        // the window again, from now, with the pass's draw.
        const bool stepped_back{window_end && last_poll && now < *last_poll};
        assert(decision.stepped_back == stepped_back);
        if (stepped_back) {
            window_end = now + spacing;
            spaced_from = now;
        }
        last_poll = now;
        // N6: networking off cancels every running job and drops every queued one; nothing starts.
        assert(decision.cancel_all == !network);
        if (!network) {
            assert(!decision.start && !decision.drop_queued && decision.capped.empty());
            assert(decision.next_start == window_end);
            for (Job& job : running) job.cancelled = true;
            queued.clear();
            return;
        }
        // D2: a job is stopped once it has run JOB_CAP on the steady clock, unless it is being
        // cancelled already.
        for (size_t i{0}; i < running.size(); ++i) {
            const bool cap{!running[i].cancelled && steady_now - running[i].steady_started >= privbcast::JOB_CAP};
            assert(std::ranges::count(decision.capped, i) == (cap ? 1 : 0));
            if (cap) running[i].cancelled = true;
        }
        assert(std::ranges::all_of(decision.capped, [&](size_t i) { return i < running.size(); }));
        // N3, N4: the job at the front starts once the window has closed, unless the most jobs run
        // or a running job's discovery has not ended: N4 comes first. Without a proxy, the jobs
        // that are due cannot run.
        const bool window_closed{!window_end || now >= *window_end};
        const bool due{!queued.empty() && window_closed && running.size() < max_concurrent &&
                       std::ranges::all_of(running, &Job::discovery_done)};
        assert(decision.start == (due && proxy));
        assert(decision.drop_queued == (due && !proxy));
        // Start times depend on no earlier job's end and on no recipient (N3): with sane clocks, a
        // discovery ends within the window and a job within its scheduled bound, and the spacing
        // keeps the most jobs from running at once.
        if (sane && !queued.empty() && window_closed) assert(decision.start || decision.drop_queued);
        if (decision.start) {
            // In submission order, at least START_SPACING_MIN after the last start or step back.
            if (spaced_from) assert(now >= *spaced_from + privbcast::START_SPACING_MIN);
            window_end = now + spacing;
            spaced_from = now;
            running.push_back({.id = queued.front(), .started = now, .steady_started = steady_now});
            starts.emplace_back(now, queued.front());
            queued.pop_front();
        }
        if (decision.drop_queued) queued.clear();
        // The window is the pass's draw, from the start or the step back, or else as it was.
        assert(decision.next_start == window_end);
        assert(running.size() <= max_concurrent);
    }

    /** The jobs' own clock, the node clock, reads now: a discovery ends by the end of its window
     *  (C3), a job by its scheduled bound (D2). */
    void Advance(NodeClock::time_point now)
    {
        for (Job& job : running) {
            if (now >= job.started + privbcast::DISCOVERY_WINDOW) job.discovery_done = true;
        }
        std::erase_if(running, [&](const Job& job) { return now >= job.started + privbcast::SCHEDULED_BOUND; });
    }

    /** abortprivatebroadcast: a queued job is dropped, a running one cancelled. */
    void Abort(int id)
    {
        std::erase(queued, id);
        for (Job& job : running) {
            if (job.id == id) job.cancelled = true;
        }
    }
};

} // namespace

/**
 * The start rule (N3, N4, N6, D2) through StartPolicy alone: two queues, as the rule sees them, get
 * the same submissions, aborts, clocks, networking and draws. Their recipients and seeds differ, so
 * their jobs' discoveries and the jobs themselves end at different times. Each pass's decision is
 * checked against a model of the rule, and, while the node clock has not stepped back and the node
 * allows MAX_CONCURRENT_JOBS at once, both queues start the same jobs at the same times.
 */
FUZZ_TARGET(privbcast_start_policy)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    std::array<Side, 2> sides;
    // A lower limit lets the limit bind.
    const size_t max_concurrent{provider.ConsumeBool() ? PrivbcastQueue::MAX_CONCURRENT_JOBS : provider.ConsumeIntegralInRange<size_t>(1, PrivbcastQueue::MAX_CONCURRENT_JOBS)};
    for (Side& side : sides) side.max_concurrent = max_concurrent;
    NodeClock::time_point now{std::chrono::seconds{provider.ConsumeIntegralInRange<int64_t>(0, 4'000'000'000)}};
    MockableSteadyClock::time_point steady_now{milliseconds{provider.ConsumeIntegralInRange<int64_t>(0, 4'000'000'000)}};
    bool network{true};
    bool proxy{true};
    // The node clock has stepped back: windows open again from the step, and a discovery whose
    // window it stretches can hold a start (N3, N4).
    bool stepped_back{false};
    int next_id{0};

    LIMITED_WHILE(provider.ConsumeBool(), 3'000)
    {
        CallOneOf(
            provider,
            [&] {
                // A submission.
                for (Side& side : sides) side.queued.push_back(next_id);
                ++next_id;
            },
            [&] {
                if (next_id == 0) return;
                const int id{provider.ConsumeIntegralInRange<int>(0, next_id - 1)};
                for (Side& side : sides) side.Abort(id);
            },
            [&] {
                // Time passes on both clocks. A cancelled job stops at its next step.
                const milliseconds elapsed{provider.ConsumeIntegralInRange<int64_t>(0, 700'000)};
                now += elapsed;
                steady_now += elapsed;
                for (Side& side : sides) {
                    std::erase_if(side.running, [](const Side::Job& job) { return job.cancelled; });
                    side.Advance(now);
                }
            },
            [&] {
                // The node clock steps alone: setmocktime, or the system clock set.
                const milliseconds step{provider.ConsumeIntegralInRange<int64_t>(-7'200'000, 7'200'000)};
                now += step;
                if (step < 0ms) stepped_back = true;
                for (Side& side : sides) side.Advance(now);
            },
            [&] {
                // The steady clock runs on alone.
                steady_now += milliseconds{provider.ConsumeIntegralInRange<int64_t>(0, 700'000)};
                for (Side& side : sides) std::erase_if(side.running, [](const Side::Job& job) { return job.cancelled; });
            },
            [&] { network = provider.ConsumeBool(); },
            [&] { proxy = provider.ConsumeBool(); },
            [&] {
                // On one queue only, the seeds have answered: a running job's discovery ends.
                Side& side{sides[provider.ConsumeBool()]};
                if (side.running.empty()) return;
                side.running[provider.ConsumeIntegralInRange<size_t>(0, side.running.size() - 1)].discovery_done = true;
            },
            [&] {
                // On one queue only, the recipients are done with a running job.
                Side& side{sides[provider.ConsumeBool()]};
                if (side.running.empty()) return;
                side.running.erase(side.running.begin() + provider.ConsumeIntegralInRange<size_t>(0, side.running.size() - 1));
            },
            [&] {
                // A pass of each scheduler, with the same draw.
                const milliseconds spacing{provider.ConsumeIntegralInRange<int64_t>(milliseconds{privbcast::START_SPACING_MIN}.count(),
                                                                                    milliseconds{privbcast::START_SPACING_MAX}.count() - 1)};
                const bool sane{!stepped_back && max_concurrent == PrivbcastQueue::MAX_CONCURRENT_JOBS};
                for (Side& side : sides) side.Pass(now, steady_now, spacing, network, proxy, sane);
                if (sane) assert(sides[0].starts == sides[1].starts);
            });
    }
}

/**
 * The node's queue through its interface, with the job threads run by a Runner, against a model of
 * what the queue holds: submissions (N5, N6, D3), aborts, passes of the scheduler, both clocks,
 * networking, the onion proxy, the mempool (N7), discoveries and jobs that end when the target says,
 * threads that cannot start, and shutdown. The draws of the spacing are the queue's own, so the
 * model checks starts against the bounds of the window rather than its exact end.
 */
FUZZ_TARGET(privbcast_queue)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const std::vector<CTransactionRef>& pool{Pool()};
    // Far enough from 0, which would end the mock, for every step back.
    NodeSeconds now{std::chrono::seconds{provider.ConsumeIntegralInRange<int64_t>(100'000'000, 4'000'000'000)}};
    FakeNodeClock clock{now};
    FakeSteadyClock steady;
    milliseconds steady_now{0};
    bool network{true};
    bool proxy{true};
    std::set<Txid> mempool;
    const Proxy tor{LookupNumeric("127.0.0.1", 9050), /*tor_stream_isolation=*/true};
    // A lower limit lets the limit bind.
    const size_t max_concurrent{provider.ConsumeBool() ? PrivbcastQueue::MAX_CONCURRENT_JOBS : provider.ConsumeIntegralInRange<size_t>(1, PrivbcastQueue::MAX_CONCURRENT_JOBS)};
    Runner runner;
    Threads threads;
    PrivbcastQueue queue{
        node::PrivbcastSeeds{.dns_seeds = {"a.seed."}, .fixed_seeds = {}, .default_port = 18444, .chain = "regtest"},
        [&] { return network; },
        [&]() -> std::optional<Proxy> {
            if (!proxy) return std::nullopt;
            return tor;
        },
        [&](const Txid& txid) { return mempool.contains(txid); },
        [&](const privbcast::JobInputs& inputs, PrivbcastQueue::ProgressCallback progress) { return runner.Run(inputs, progress); },
        max_concurrent};
    node::PrivbcastQueueTest::SetLauncher(queue, [&](std::function<void()> run) { return threads.Launch(std::move(run)); });

    // The model.
    struct Job {
        size_t tx{0};
        std::string state{"queued"};
        int64_t time_added{0};
        std::optional<int64_t> time_started{};
        std::optional<int64_t> time_ended{};
        std::optional<int64_t> seen_in_mempool{};
        std::optional<std::string> error{};
        bool cancel{false};
        bool discovery_done{false};
        std::optional<bool> announced{};
        bool report{false};
        /** The run, once running. */
        size_t run{0};
        milliseconds steady_started{0};
    };
    std::deque<Job> queued, running, finished;
    bool interrupted{false};
    size_t runs{0};
    size_t threads_done{0};
    // The node clock as the last pass read it, and the last start, or the last step back of the
    // clock since: the window ends a drawn spacing after it (N3).
    std::optional<NodeSeconds> last_poll;
    std::optional<NodeSeconds> window_from;

    const auto ToUnix{[](NodeSeconds time) { return TicksSinceEpoch<std::chrono::seconds>(time); }};
    const auto finish{[&](Job job, std::string state) {
        job.state = std::move(state);
        job.time_ended = ToUnix(now);
        finished.push_back(std::move(job));
        if (finished.size() > privbcast::MAX_FINISHED_JOBS) finished.pop_front();
    }};
    const auto drop_queued{[&](const std::string& error) {
        while (!queued.empty()) {
            Job job{std::move(queued.front())};
            queued.pop_front();
            job.error = error;
            finish(std::move(job), "aborted");
        }
    }};
    const auto cancel_all{[&](const std::string& error) {
        for (Job& job : running) {
            if (job.cancel) continue;
            job.error = error;
            job.cancel = true;
        }
        drop_queued(error);
    }};

    // A submission (N5, N6, D3, N7).
    const auto submit{[&](size_t tx) {
        // N5: a queued job, or a running one not being aborted, with the same wtxid covers the
        // submission.
        const auto covers{[&](const Job& job) { return pool[job.tx]->GetWitnessHash() == pool[tx]->GetWitnessHash(); }};
        SubmitResult expected{SubmitResult::Queued};
        if (interrupted) {
            expected = SubmitResult::ShuttingDown;
        } else if (!network) {
            expected = SubmitResult::NetworkOff;
        } else if (std::ranges::any_of(queued, covers) || std::ranges::any_of(running, [&](const Job& job) { return !job.cancel && covers(job); })) {
            expected = SubmitResult::Covered;
        } else if (queued.size() >= privbcast::MAX_QUEUED_JOBS) {
            expected = SubmitResult::QueueFull;
        }
        assert(queue.Submit(pool[tx]) == expected);
        if (expected != SubmitResult::Queued) return;
        Job& job{queued.emplace_back()};
        job.tx = tx;
        job.time_added = ToUnix(now);
        // N7: seen from its submission if the mempool holds its txid.
        if (mempool.contains(pool[tx]->GetHash())) job.seen_in_mempool = job.time_added;
    }};
    // abortprivatebroadcast: the running jobs it matches are cancelled, the queued ones dropped.
    const auto abort_job{[&](const uint256& id) {
        const auto matches{[&](const Job& job) { return pool[job.tx]->GetHash().ToUint256() == id || pool[job.tx]->GetWitnessHash().ToUint256() == id; }};
        std::vector<PrivbcastQueue::Removed> expected;
        for (Job& job : running) {
            if (!matches(job)) continue;
            job.cancel = true;
            expected.push_back({pool[job.tx]->GetHash(), pool[job.tx]->GetWitnessHash(), EncodeHexTx(*pool[job.tx]), "running"});
        }
        for (auto it{queued.begin()}; it != queued.end();) {
            if (!matches(*it)) {
                ++it;
                continue;
            }
            expected.push_back({pool[it->tx]->GetHash(), pool[it->tx]->GetWitnessHash(), EncodeHexTx(*pool[it->tx]), "aborted"});
            Job job{std::move(*it)};
            it = queued.erase(it);
            finish(std::move(job), "aborted");
        }
        // In any order.
        const auto key{[](const PrivbcastQueue::Removed& entry) { return std::tuple{entry.wtxid, entry.state, entry.txid, entry.hex}; }};
        std::vector<PrivbcastQueue::Removed> removed{queue.Abort(id)};
        std::ranges::sort(removed, {}, key);
        std::ranges::sort(expected, {}, key);
        assert(std::ranges::equal(removed, expected, {}, key, key));
    }};

    LIMITED_WHILE(provider.ConsumeBool(), 1'000)
    {
        CallOneOf(
            provider,
            [&] {
                // sendrawtransaction.
                submit(provider.ConsumeIntegralInRange<size_t>(0, pool.size() - 1));
            },
            [&] {
                // abortprivatebroadcast, by txid or wtxid.
                uint256 id{ConsumeUInt256(provider)};
                if (provider.ConsumeBool()) {
                    const CTransactionRef& tx{pool[provider.ConsumeIntegralInRange<size_t>(0, pool.size() - 1)]};
                    id = provider.ConsumeBool() ? tx->GetHash().ToUint256() : tx->GetWitnessHash().ToUint256();
                }
                abort_job(id);
            },
            [&] {
                // Many submissions, each aborted at once, to fill the finished jobs (D3).
                for (int n{provider.ConsumeIntegralInRange<int>(0, 60)}; n > 0; --n) {
                    const size_t tx{static_cast<size_t>(n) % pool.size()};
                    submit(tx);
                    abort_job(pool[tx]->GetWitnessHash().ToUint256());
                }
            },
            [&] {
                // A pass of the scheduler.
                const size_t queued_before{queued.size()};
                const bool fails{threads.FailsNext()};
                node::PrivbcastQueueTest::Poll(queue);
                if (interrupted) return;
                // N3: once a job has started, a pass that reads the clock earlier than the one before
                // opens the window again, from now.
                if (window_from && last_poll && now < *last_poll) window_from = now;
                last_poll = now;
                if (!network) {
                    // N6: every running job is cancelled, every queued one dropped.
                    cancel_all("networking disabled");
                    return;
                }
                // D2: on the steady clock.
                for (Job& job : running) {
                    if (job.cancel || steady_now - job.steady_started < privbcast::JOB_CAP) continue;
                    job.error = "cap";
                    job.cancel = true;
                }
                // N3, N4: the job at the front may start once START_SPACING_MIN has passed, and must
                // once START_SPACING_MAX has, unless the most jobs run or a discovery has not ended.
                const bool can{!queued.empty() && running.size() < max_concurrent &&
                               std::ranges::all_of(running, &Job::discovery_done)};
                const bool may{can && (!window_from || now >= *window_from + privbcast::START_SPACING_MIN)};
                const bool must{can && (!window_from || now >= *window_from + privbcast::START_SPACING_MAX)};
                size_t queued_after{0};
                for (const PrivbcastQueue::JobInfo& info : queue.Info()) queued_after += info.state == "queued";
                if (proxy) {
                    const bool started{queued_after + 1 == queued_before};
                    assert(started || queued_after == queued_before);
                    assert(may || !started);
                    assert(started || !must);
                    if (!started) return;
                    Job job{std::move(queued.front())};
                    queued.pop_front();
                    job.time_started = ToUnix(now);
                    window_from = now;
                    if (fails) {
                        // Its thread cannot start: it ends at once, its start and window standing.
                        job.error = "cannot start a thread";
                        finish(std::move(job), "aborted");
                        return;
                    }
                    job.state = "running";
                    job.run = runs++;
                    job.steady_started = steady_now;
                    running.push_back(std::move(job));
                    runner.WaitForRuns(runs);
                } else {
                    // The jobs that are due cannot run: every queued one is dropped.
                    const bool dropped{queued_before > 0 && queued_after == 0};
                    assert(dropped || queued_after == queued_before);
                    assert(may || !dropped);
                    assert(dropped || !must);
                    if (dropped) drop_queued("no Tor proxy");
                }
            },
            [&] {
                // Time passes on both clocks.
                const std::chrono::seconds elapsed{provider.ConsumeIntegralInRange<int64_t>(0, 700)};
                now += elapsed;
                clock.set(now);
                steady += elapsed;
                steady_now += elapsed;
            },
            [&] {
                // The node clock steps alone, forward or back.
                now += std::chrono::seconds{provider.ConsumeIntegralInRange<int64_t>(-7'200, 7'200)};
                clock.set(now);
            },
            [&] {
                // The steady clock runs on alone.
                const milliseconds elapsed{provider.ConsumeIntegralInRange<int64_t>(0, 700'000)};
                steady += elapsed;
                steady_now += elapsed;
            },
            [&] { network = provider.ConsumeBool(); },
            [&] { proxy = provider.ConsumeBool(); },
            [&] {
                // A transaction arrives in the mempool, and the queue may be told (N7): the first
                // arrival is recorded, and nothing else changes.
                const CTransactionRef& tx{pool[provider.ConsumeIntegralInRange<size_t>(0, pool.size() - 1)]};
                mempool.insert(tx->GetHash());
                if (!provider.ConsumeBool()) return;
                node::PrivbcastQueueTest::TransactionAddedToMempool(queue, tx);
                for (auto* jobs : {&queued, &running, &finished}) {
                    for (Job& job : *jobs) {
                        if (pool[job.tx]->GetHash() == tx->GetHash() && !job.seen_in_mempool) job.seen_in_mempool = ToUnix(now);
                    }
                }
            },
            [&] {
                // A running job's discovery ends.
                if (running.empty()) return;
                Job& job{running[provider.ConsumeIntegralInRange<size_t>(0, running.size() - 1)]};
                if (job.discovery_done) return;
                runner.Discover(job.run);
                job.discovery_done = true;
            },
            [&] {
                // A running job ends: it ran, maybe announcing, or it failed, with a report or by
                // throwing.
                if (running.empty()) return;
                const auto it{running.begin() + provider.ConsumeIntegralInRange<size_t>(0, running.size() - 1)};
                Runner::Ending ending;
                ending.announcements = provider.ConsumeIntegralInRange<int>(0, 2);
                if (provider.ConsumeBool()) {
                    ending.error = provider.ConsumeBool() ? "failed" : "loop";
                    ending.thrown = provider.ConsumeBool();
                }
                runner.End(it->run, ending);
                threads.WaitForDone(++threads_done);
                Job job{std::move(*it)};
                running.erase(it);
                if (ending.error) job.error = ending.error;
                if (!ending.thrown) {
                    job.announced = ending.announcements > 0;
                    job.report = true;
                }
                // A job that failed, or was cancelled before it ended, was aborted, whatever it did.
                const bool aborted{job.cancel || ending.error};
                finish(std::move(job), aborted ? "aborted" : "done");
            },
            [&] { threads.FailNext(); },
            [&] {
                // Shutdown (N6).
                queue.Interrupt();
                if (!interrupted) cancel_all("shutting down");
                interrupted = true;
            });

        // The queue holds what the model holds: the retained finished jobs, oldest first, then the
        // running ones, then the queued ones, each within its bound (D3, N3).
        assert(queued.size() <= privbcast::MAX_QUEUED_JOBS);
        assert(running.size() <= max_concurrent);
        assert(finished.size() <= privbcast::MAX_FINISHED_JOBS);
        const std::vector<PrivbcastQueue::JobInfo> infos{queue.Info()};
        assert(infos.size() == finished.size() + running.size() + queued.size());
        size_t i{0};
        for (const auto* jobs : {&finished, &running, &queued}) {
            for (const Job& job : *jobs) {
                const PrivbcastQueue::JobInfo& info{infos[i++]};
                // The ids stay once the transactions are gone (N9).
                assert(info.txid == pool[job.tx]->GetHash() && info.wtxid == pool[job.tx]->GetWitnessHash());
                assert(info.state == job.state);
                assert(info.time_added == job.time_added);
                assert(info.time_started == job.time_started);
                assert(info.time_ended == job.time_ended);
                assert(info.seen_in_mempool == job.seen_in_mempool);
                assert(info.error == job.error);
                assert(info.progress.has_value() == (job.state == "running"));
                if (info.progress) assert(info.progress->discovery_done == job.discovery_done);
                assert(info.announced == job.announced);
                assert((info.report != nullptr) == job.report);
            }
        }
        // N9: a transaction is held only while a job that carries it is queued or running.
        for (size_t tx{0}; tx < pool.size(); ++tx) {
            const auto carries{[&](const Job& job) { return job.tx == tx; }};
            const bool held{std::ranges::any_of(queued, carries) || std::ranges::any_of(running, carries)};
            assert(held == (pool[tx].use_count() > 1));
        }
    }
    runner.Close();
    queue.Stop();
    for (const CTransactionRef& tx : pool) assert(tx.use_count() == 1);
}
