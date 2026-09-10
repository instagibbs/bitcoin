// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/discovery.h>
#include <privbcast/timing.h>

#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <util/time.h>

#include <algorithm>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <numeric>
#include <set>
#include <thread>

/** Defined in netbase.cpp; how long each SOCKS5 stage waits for the proxy. The tool bounds it per phase. */
extern std::chrono::milliseconds g_socks5_recv_timeout;

namespace privbcast {

size_t DiscoveryResult::NumExitPath() const
{
    size_t n{0};
    for (const auto& v : per_seed) n += v.size();
    return n;
}

static bool IsUsableExitPathAnswer(const CNetAddr& addr)
{
    return addr.IsValid() && addr.IsRoutable() && (addr.IsIPv4() || addr.IsIPv6());
}

DiscoveryResult Freeze(const DiscoveryPlan& plan, const SeedAnswers& answers, const std::vector<size_t>& tie_order, FastRandomContext& rng)
{
    const size_t n{plan.dns_seeds.size()};
    assert(answers.size() == n && tie_order.size() == n);

    DiscoveryResult result;
    result.tie_order = tie_order;
    result.per_seed.resize(n);
    result.seeds.resize(n);
    for (size_t i = 0; i < n; ++i) {
        result.seeds[i].name = plan.dns_seeds[i];
        result.seeds[i].answers = answers[i].size();
    }

    // The onion draw comes first: the bundled list is fixed at job start, so drawing it before any
    // answer-dependent shuffle keeps the onion choice independent of what the seeds returned.
    std::set<CService> onion_seen;
    for (const CService& s : plan.bundled) {
        if (!s.IsTor() || !s.IsValid()) continue;
        if (!onion_seen.insert(s).second) continue;
        result.onion.push_back(Candidate{s, Source::BUNDLED, "bundled"});
    }
    std::shuffle(result.onion.begin(), result.onion.end(), rng);
    if (result.onion.size() > disc::MAX_BUNDLED) result.onion.resize(disc::MAX_BUNDLED);

    // Assign each endpoint to the first seed in tie order that returned it.
    std::set<CService> seen;
    for (const size_t i : tie_order) {
        for (const CNetAddr& addr : answers[i]) {
            if (!IsUsableExitPathAnswer(addr)) {
                ++result.rejected;
                continue;
            }
            const CService endpoint{addr, plan.port};
            if (!seen.insert(endpoint).second) {
                ++result.duplicates;
                continue;
            }
            ++result.seeds[i].accepted;
            result.per_seed[i].push_back(Candidate{endpoint, Source::DNS_SEED, plan.dns_seeds[i]});
        }
    }
    for (size_t i = 0; i < n; ++i) {
        auto& kept{result.per_seed[i]};
        std::shuffle(kept.begin(), kept.end(), rng);
        if (kept.size() > disc::MAX_PER_SEED) kept.resize(disc::MAX_PER_SEED);
        result.seeds[i].kept = kept.size();
    }

    return result;
}

namespace {

/** Shared between the query workers and Discover(); outlives both through shared ownership. */
struct DiscoveryState {
    std::mutex mutex;
    std::condition_variable cv;
    SeedAnswers answers;
    std::vector<uint32_t> queries;
    std::vector<uint32_t> skipped; //!< queries never started: the host had stalled past the start grace
    bool closed{false};            //!< the window has ended: late answers are discarded
    size_t running{0};
};

} // namespace

DiscoveryResult Discover(const Proxy& tor, const DiscoveryPlan& plan, SteadyClock::time_point t0, FastRandomContext& rng, const std::function<bool()>& interrupted)
{
    const size_t n{plan.dns_seeds.size()};
    std::vector<size_t> tie_order(n);
    std::iota(tie_order.begin(), tie_order.end(), size_t{0});
    std::shuffle(tie_order.begin(), tie_order.end(), rng);

    // SOCKS stage timeouts are plan constants: with the connect timeout a RESOLVE always ends by
    // its absolute deadline, so a slow exit or resolver cannot delay the freeze or delivery.
    nConnectTimeout = std::chrono::duration_cast<std::chrono::milliseconds>(Scaled(disc::CONNECT_TIMEOUT)).count();
    g_socks5_recv_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(Scaled(disc::SOCKS_RECV_TIMEOUT));

    auto st{std::make_shared<DiscoveryState>()};
    st->answers.resize(n);
    st->queries.resize(n, 0);
    st->skipped.resize(n, 0);
    st->running = n * disc::QUERIES_PER_SEED;
    const auto window_end{t0 + Scaled(disc::WINDOW)};

    // One worker per query, all launched now: each is a fresh Tor stream, none waits for
    // another, and every one carries the same absolute deadline from job start.
    std::vector<std::thread> workers;
    struct JoinThreads {
        std::vector<std::thread>& threads;
        ~JoinThreads()
        {
            for (auto& t : threads) {
                if (t.joinable()) t.join();
            }
        }
    } join_workers{workers};
    for (size_t i = 0; i < n; ++i) {
        for (uint32_t q = 0; q < disc::QUERIES_PER_SEED; ++q) {
            workers.emplace_back([st, i, q, tor, name = plan.dns_seeds[i], t0, window_end, interrupted] {
                bool run{false};
                {
                    std::lock_guard lock{st->mutex};
                    if (!st->closed && !interrupted() && SteadyClock::now() <= std::min(t0 + Scaled(disc::QUERY_GRACE), window_end)) {
                        ++st->queries[i];
                        run = true;
                    } else if (!st->closed) {
                        ++st->skipped[i]; // the host stalled past the grace: not run late
                    }
                }
                if (run) {
                    try {
                        const auto addr{ResolveThroughProxy(tor, name, t0 + Scaled(disc::QUERY_DEADLINE))};
                        std::lock_guard lock{st->mutex};
                        if (!st->closed && SteadyClock::now() < window_end) { // late answers are discarded
                            if (addr) {
                                LogDebug(BCLog::PRIVBROADCAST, "discovery: %s answered %s\n", name, addr->ToStringAddr());
                                st->answers[i].push_back(*addr);
                            } else {
                                LogDebug(BCLog::PRIVBROADCAST, "discovery: %s query %u failed\n", name, q);
                            }
                        }
                    } catch (...) {
                        // A query that failed without an answer; the accounting below still runs.
                    }
                }
                std::lock_guard lock{st->mutex};
                --st->running;
                st->cv.notify_all();
            });
        }
    }

    // Wait for the workers or the window, whichever ends first. Delivery starts at the window's
    // end regardless, so a slow seed or exit cannot move it.
    SeedAnswers answers;
    std::vector<uint32_t> queries, skipped;
    {
        std::unique_lock lock{st->mutex};
        while (st->running > 0 && SteadyClock::now() < window_end && !interrupted()) {
            st->cv.wait_until(lock, std::min(window_end, SteadyClock::now() + 100ms));
        }
        st->closed = true;
        answers = st->answers;
        queries = st->queries;
        skipped = st->skipped;
        // A worker still inside a RESOLVE is cut short: its answer would be discarded anyway,
        // and no discovery socket may outlive this call.
        if (st->running > 0 || interrupted()) g_socks5_interrupt();
    }
    for (auto& w : workers) w.join();
    // The SOCKS interrupt is a latch. Discovery is over, so unless the job itself is being
    // cancelled, clear it for delivery.
    if (!interrupted()) {
        g_socks5_interrupt.reset();
        if (interrupted()) g_socks5_interrupt(); // cancelled between the check and the reset
    }

    DiscoveryResult result{Freeze(plan, answers, tie_order, rng)};
    for (size_t i = 0; i < n; ++i) {
        result.seeds[i].queries = queries[i];
        result.seeds[i].skipped = skipped[i];
    }
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - t0);
    return result;
}

} // namespace privbcast
