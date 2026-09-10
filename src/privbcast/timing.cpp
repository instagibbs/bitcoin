// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/timing.h>

#include <atomic>
#include <cassert>

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

} // namespace privbcast
