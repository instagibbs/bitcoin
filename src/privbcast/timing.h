// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_TIMING_H
#define BITCOIN_PRIVBCAST_TIMING_H

#include <util/time.h>

#include <chrono>
#include <cstdint>

namespace privbcast {

/**
 * Regtest-only divisor applied to every plan duration so functional tests run quickly.
 * It is 1 on every other chain, where the durations are the compile-time constants.
 */
uint32_t TimeDivisor();
void SetTimeDivisor(uint32_t divisor);

/** A plan duration scaled by the time divisor. */
inline SteadyClock::duration Scaled(std::chrono::seconds d)
{
    return std::chrono::duration_cast<SteadyClock::duration>(std::chrono::milliseconds{d.count() * 1000 / TimeDivisor()});
}

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_TIMING_H
