// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVBCAST_PLAN_H
#define BITCOIN_PRIVBCAST_PLAN_H

#include <netaddress.h>
#include <privbcast/params.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

class FastRandomContext;

namespace privbcast {

/** A slot's times, as offsets from job start on the plan clock. */
struct SlotSchedule {
    int index{0};
    SlotClass cls{SlotClass::ExitPath};
    Stratum stratum{Stratum::Prompt};
    /** The opportunities' scheduled starts: the first attempt, then each backup. */
    std::array<std::chrono::milliseconds, OPPORTUNITIES_PER_SLOT> scheduled{};
    /** The last opportunity's scheduled start plus ATTEMPT_MAX. The slot ends by then (D2). */
    std::chrono::milliseconds scheduled_end{0};

    bool operator==(const SlotSchedule&) const = default;
};

/** What a job draws at its start, before any network activity (C1). */
struct Plan {
    Timing timing;
    std::array<SlotSchedule, SLOTS> slots;
    /** Each DNS seed once, in the order exit-path candidates are credited and handed out (R5b). */
    std::vector<std::string> seed_order;
    /** At most ONIONS_KEPT onion services of the fixed-seed list, in the order the onion slots
     *  take them (R1, R3). */
    std::vector<CService> onions;
    /** Seeds the draw of each DNS seed's kept answers from its accepted ones (R5b). */
    uint64_t answer_seed{0};

    bool operator==(const Plan&) const = default;
};

/**
 * Draw a job's plan from rng alone, before any network activity (C1, R3): the schedule under
 * timing, the order of dns_seeds, the onion candidates and the answer seed. Only the onion
 * services of fixed_seeds are candidates (R2). A name or an onion listed twice counts once.
 */
Plan DrawPlan(FastRandomContext& rng, const Timing& timing,
              std::span<const std::string> dns_seeds, std::span<const CService> fixed_seeds);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_PLAN_H
