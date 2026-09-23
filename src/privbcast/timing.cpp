// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privbcast/timing.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <set>

using namespace std::chrono_literals;

namespace privbcast {

static std::atomic<uint32_t> g_time_divisor{1};

uint32_t TimeDivisor()
{
    return g_time_divisor.load();
}

void SetTimeDivisor(uint32_t divisor)
{
    assert(divisor >= 1);
    g_time_divisor.store(divisor);
}

namespace {

struct Waiters {
    std::mutex mutex;
    std::condition_variable cv;        //!< waiters sleep here; notified by every wake
    std::condition_variable settle_cv; //!< Settle() sleeps here; notified when a thread parks, leaves or registers
    uint64_t generation{0};            //!< bumped by every wake, so a waiter knows it has re-checked since
    bool mocked{false};
    int registered{0};                 //!< job threads alive
    int parked{0};                     //!< registered threads parked in WaitUntil() since the last wake
    std::multiset<Clock::time_point> deadlines;

    /** Wake every waiter: each must re-check its condition before it counts as parked again. */
    void Wake()
    {
        ++generation;
        parked = 0;
        cv.notify_all();
    }
};

Waiters& W()
{
    static Waiters w;
    return w;
}

thread_local bool t_registered{false};

} // namespace

bool WaitUntil(Clock::time_point when, const std::function<bool()>& stop, std::chrono::milliseconds poll)
{
    Waiters& w{W()};
    std::unique_lock lock{w.mutex};
    const bool registered{t_registered};
    const auto deadline{w.deadlines.insert(when)};
    bool result;
    while (true) {
        if (stop()) {
            result = false;
            break;
        }
        if (Clock::now() >= when) {
            result = true;
            break;
        }
        if (w.mocked) {
            const uint64_t seen{w.generation};
            if (registered) {
                ++w.parked;
                w.settle_cv.notify_all();
            }
            // Woken by a wake; the bound covers a clock advanced by other means.
            w.cv.wait_for(lock, 1ms, [&] { return w.generation != seen; });
            // A wake resets the parked count; only a spurious return leaves this thread's share to undo.
            if (registered && w.generation == seen) --w.parked;
        } else {
            const auto remaining{when == Clock::time_point::max() ? Clock::duration{poll} : when - Clock::now()};
            w.cv.wait_for(lock, std::min<Clock::duration>(poll, std::max<Clock::duration>(remaining, 0ms)));
        }
    }
    w.deadlines.erase(deadline);
    return result;
}

void WakeWaiters()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    w.Wake();
}

namespace mocktime {

void Start()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    SetMockTime(std::chrono::seconds{1'700'000'000});
    w.mocked = true;
    w.Wake();
}

void Stop()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    w.mocked = false;
    SetMockTime(0s);
    w.Wake();
}

bool Active()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    return w.mocked;
}

void Advance(std::chrono::seconds by)
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    assert(w.mocked);
    SetMockTime(GetMockTime() + by);
    w.Wake();
}

bool Settle(std::chrono::milliseconds timeout, const std::function<bool()>& stop)
{
    Waiters& w{W()};
    std::unique_lock lock{w.mutex};
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (true) {
        if (stop() || (w.registered > 0 && w.parked == w.registered)) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        w.settle_cv.wait_for(lock, 1ms); // `stop` may flip without a notification
    }
}

std::optional<std::chrono::seconds> NextWait()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    // Ordered, so the first deadline is the earliest; the unbounded sentinel sorts last.
    if (w.deadlines.empty() || *w.deadlines.begin() == Clock::time_point::max()) return std::nullopt;
    return std::chrono::ceil<std::chrono::seconds>(*w.deadlines.begin() - Clock::now());
}

} // namespace mocktime

JobThreadScope::JobThreadScope(bool reserved)
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    assert(!t_registered);
    if (!reserved) ++w.registered;
    t_registered = true;
    w.settle_cv.notify_all();
}

JobThreadScope::~JobThreadScope()
{
    Release();
}

void JobThreadScope::Reserve()
{
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    ++w.registered;
}

void JobThreadScope::Release()
{
    if (!m_active) return;
    m_active = false;
    Waiters& w{W()};
    std::lock_guard lock{w.mutex};
    --w.registered;
    t_registered = false;
    w.settle_cv.notify_all();
}

} // namespace privbcast
