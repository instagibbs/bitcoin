// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVBCAST_TIMING_H
#define BITCOIN_PRIVBCAST_TIMING_H

#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>

namespace privbcast {

/**
 * The clock behind every schedule time in the library: the node clock, so setmocktime drives a
 * job on regtest as it drives the node's other timers. It is a wall clock on purpose: the plan
 * bounds a job in the time observers see, so a host that sleeps through part of a job finds its
 * remaining opportunities missed rather than stretched over an unbounded span.
 */
using Clock = NodeClock;

/**
 * Regtest-only divisor applied to every plan duration so the tool's functional test runs quickly.
 * It is 1 on every other chain, where the durations are the compile-time constants.
 */
uint32_t TimeDivisor();
void SetTimeDivisor(uint32_t divisor);

/** A schedule time as netbase expects it: the same remaining budget, on the steady clock. */
inline SteadyClock::time_point ToSteady(Clock::time_point t)
{
    return SteadyClock::now() + std::chrono::duration_cast<SteadyClock::duration>(std::max(t - Clock::now(), Clock::duration{0}));
}

/** A plan duration scaled by the time divisor. */
inline Clock::duration Scaled(std::chrono::seconds d)
{
    return std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds{d.count() * 1000 / TimeDivisor()});
}

/**
 * Block until `when` has passed, or until `stop()` returns true, which is re-checked at least
 * every `poll`. Returns false if stopped first. `stop` must be a plain flag read: it runs under
 * the waiters' lock. The clock is re-read at every poll, so a wait follows setmocktime. Under
 * the test driver (see mocktime) the wait is driven by the clock alone: it wakes when the clock
 * is advanced and never returns early because the host was slow, so nothing timed through this
 * call depends on wall-clock speed. A `when` of Clock::time_point::max() waits for `stop` alone.
 */
bool WaitUntil(Clock::time_point when, const std::function<bool()>& stop, std::chrono::milliseconds poll = std::chrono::milliseconds{100});

/** Wake every WaitUntil() so it re-checks its stop condition, for example after raising an interrupt. */
void WakeWaiters();

/**
 * Test driver for the mocked clock, for code that waits through WaitUntil(). Threads that run job
 * code are registered (RunJob registers its own); a registered thread is parked while it is
 * inside WaitUntil(). A test advances the clock only once every registered thread is parked, and
 * by exactly the wait that is due next, so a job runs the same way at any host speed. The mock
 * has whole-second resolution, as every plan duration is whole seconds.
 */
namespace mocktime {
/** Mock the clock and start driving it. */
void Start();
/** Stop driving and unmock the clock. */
void Stop();
bool Active();
/** Advance the mocked clock by `by` and wake every waiter. */
void Advance(std::chrono::seconds by);
/**
 * Wait until every registered thread is parked and has re-checked its wait since the last
 * Advance() or WakeWaiters(), or until `stop()` returns true. Returns false only if `timeout`
 * of real time elapsed first.
 */
bool Settle(std::chrono::milliseconds timeout, const std::function<bool()>& stop);
/** The time until the earliest pending WaitUntil() deadline, rounded up, or nullopt when none is pending. */
std::optional<std::chrono::seconds> NextWait();
} // namespace mocktime

/** Registers the current thread as one running job code, for mocktime. RunJob uses it for its threads. */
class JobThreadScope
{
public:
    /** Register the current thread, or adopt a registration made by Reserve() before it was created. */
    explicit JobThreadScope(bool reserved = false);
    ~JobThreadScope();
    JobThreadScope(const JobThreadScope&) = delete;
    JobThreadScope& operator=(const JobThreadScope&) = delete;
    /** Count a thread before it exists, so a test never sees the job as fully parked while it starts. */
    static void Reserve();
    /** End the registration early; RunJob's own thread does so before it joins its workers. */
    void Release();

private:
    bool m_active{true};
};

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_TIMING_H
