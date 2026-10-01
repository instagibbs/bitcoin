// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <netbase.h>
#include <privbcast/params.h>
#include <privbcast/plan.h>
#include <protocol.h>
#include <random.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace privbcast;

namespace {

const std::vector<std::string> DNS_SEEDS{
    "seed.a.example", "seed.b.example", "seed.c.example", "seed.d.example", "seed.e.example",
    "seed.f.example", "seed.g.example", "seed.h.example", "seed.i.example"};

/** The slot layout of the Parameters table. */
constexpr std::array<std::pair<SlotClass, Stratum>, SLOTS> LAYOUT{{
    {SlotClass::ExitPath, Stratum::Prompt},
    {SlotClass::ExitPath, Stratum::Prompt},
    {SlotClass::Onion, Stratum::Prompt},
    {SlotClass::Onion, Stratum::Mid},
    {SlotClass::ExitPath, Stratum::Late},
    {SlotClass::ExitPath, Stratum::Late},
}};

CService Endpoint(const std::string& addr)
{
    const std::optional<CService> endpoint{Lookup(addr, /*portDefault=*/8333, /*fAllowLookup=*/false)};
    BOOST_REQUIRE(endpoint);
    return *endpoint;
}

/** A different onion service for every n. */
CService Onion(uint8_t n)
{
    std::array<uint8_t, 32> pubkey{};
    pubkey[0] = n;
    return Endpoint(OnionToString(pubkey));
}

/** Twenty onion services among IPv4, IPv6 and I2P entries, as a release's list mixes them. */
std::vector<CService> FixedSeeds()
{
    std::vector<CService> seeds;
    for (uint8_t n{0}; n < 20; ++n) {
        seeds.push_back(Endpoint(strprintf("1.2.3.%d", n)));
        seeds.push_back(Onion(n));
        seeds.push_back(Endpoint(strprintf("2600::%d", n + 1)));
    }
    seeds.push_back(Endpoint("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"));
    return seeds;
}

/** The lowest and highest values seen. */
struct Extremes {
    std::chrono::milliseconds min{std::chrono::milliseconds::max()};
    std::chrono::milliseconds max{std::chrono::milliseconds::min()};
    void Add(std::chrono::milliseconds value)
    {
        min = std::min(min, value);
        max = std::max(max, value);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(privbcast_plan_tests)

BOOST_AUTO_TEST_CASE(parameters)
{
    // The Parameters section of doc/design/private-broadcast-tool.md.
    BOOST_CHECK_EQUAL(QUERIES_PER_SEED, 4);
    BOOST_CHECK_EQUAL(ANSWERS_KEPT_PER_SEED, 3);
    BOOST_CHECK_EQUAL(ONIONS_KEPT, 8U);
    BOOST_CHECK(DISCOVERY_WINDOW == 18s);
    BOOST_CHECK_EQUAL(SLOTS, 6U);
    for (size_t i{0}; i < SLOTS; ++i) {
        BOOST_CHECK(SLOT_LAYOUT[i].cls == LAYOUT[i].first);
        BOOST_CHECK(SLOT_LAYOUT[i].stratum == LAYOUT[i].second);
    }
    BOOST_CHECK(MID_SLOT_RANGE.min == 35s);
    BOOST_CHECK(MID_SLOT_RANGE.max == 180s);
    BOOST_CHECK(LATE_SLOT_RANGE.min == 185s);
    BOOST_CHECK(LATE_SLOT_RANGE.max == 240s);
    BOOST_CHECK(LATE_SLOT_SEPARATION == 5s);
    BOOST_CHECK_EQUAL(OPPORTUNITIES_PER_SLOT, 4U);
    BOOST_CHECK(BACKUP_RANGE.min == 50s);
    BOOST_CHECK(BACKUP_RANGE.max == 60s);
    BOOST_CHECK(START_GRACE == 5s);
    BOOST_CHECK(HANDSHAKE_BUDGET == 45s);
    BOOST_CHECK(REQUEST_WINDOW == 75s);
    BOOST_CHECK(PONG_WAIT == 10s);
    BOOST_CHECK_EQUAL(MAX_RECV_BYTES, 128U * 1024);
    BOOST_CHECK_EQUAL(PROFILE_VERSION, 70017);
    BOOST_CHECK_EQUAL(PROFILE_SERVICES, NODE_WITNESS);
    BOOST_CHECK(PROFILE_USER_AGENT == "/pynode:0.0.1/");
    BOOST_CHECK_EQUAL(MIN_PEER_PROTOCOL_VERSION, 70016);
    BOOST_CHECK(JOB_CAP == 10min);
    BOOST_CHECK(START_SPACING_MIN == 35s);
    BOOST_CHECK(START_SPACING_MAX == 55s);
    BOOST_CHECK_EQUAL(MAX_QUEUED_JOBS, 10'000U);
    BOOST_CHECK_EQUAL(MAX_FINISHED_JOBS, 100U);
    BOOST_CHECK_EQUAL(MAX_STDIN_BYTES, 8'004'096U);
    BOOST_CHECK_EQUAL(MAX_TIME_DIVISOR, 1000);

    // Derived: 24 connections per job.
    BOOST_CHECK_EQUAL(SLOTS * OPPORTUNITIES_PER_SLOT, 24U);
}

BOOST_AUTO_TEST_CASE(schedule)
{
    const std::vector<CService> fixed_seeds{FixedSeeds()};
    for (const int divisor : {1, 10, MAX_TIME_DIVISOR}) {
        const Timing timing{divisor};
        const std::chrono::milliseconds delivery_start{timing.Scale(DISCOVERY_WINDOW)};
        Extremes mid, late, separation, backup;
        FastRandomContext rng{uint256{1}};
        for (int draw{0}; draw < 2000; ++draw) {
            const Plan plan{DrawPlan(rng, timing, DNS_SEEDS, fixed_seeds)};
            BOOST_CHECK(plan.timing == timing);
            std::vector<std::chrono::milliseconds> late_firsts;
            for (size_t i{0}; i < SLOTS; ++i) {
                const SlotSchedule& slot{plan.slots[i]};
                BOOST_CHECK_EQUAL(slot.index, static_cast<int>(i));
                BOOST_CHECK(slot.cls == LAYOUT[i].first);
                BOOST_CHECK(slot.stratum == LAYOUT[i].second);

                const std::chrono::milliseconds first{slot.scheduled[0] - delivery_start};
                switch (slot.stratum) {
                case Stratum::Prompt:
                    BOOST_CHECK(first == 0ms);
                    break;
                case Stratum::Mid:
                    BOOST_CHECK(timing.Scale(MID_SLOT_RANGE.min) <= first && first <= timing.Scale(MID_SLOT_RANGE.max));
                    mid.Add(first);
                    break;
                case Stratum::Late:
                    BOOST_CHECK(timing.Scale(LATE_SLOT_RANGE.min) <= first && first <= timing.Scale(LATE_SLOT_RANGE.max));
                    late.Add(first);
                    late_firsts.push_back(first);
                    break;
                }
                for (size_t k{1}; k < OPPORTUNITIES_PER_SLOT; ++k) {
                    const std::chrono::milliseconds interval{slot.scheduled[k] - slot.scheduled[k - 1]};
                    BOOST_CHECK(timing.Scale(BACKUP_RANGE.min) <= interval && interval <= timing.Scale(BACKUP_RANGE.max));
                    backup.Add(interval);
                }
                BOOST_CHECK(slot.scheduled_end == slot.scheduled.back() + timing.Scale(ATTEMPT_MAX));
                // D2's bounds hold under any divisor.
                BOOST_CHECK(slot.scheduled_end - slot.scheduled[0] <= timing.Scale(SLOT_MAX));
                BOOST_CHECK(slot.scheduled_end <= timing.Scale(SCHEDULED_BOUND));
                if (divisor == 10) {
                    // Everything divided by ten.
                    if (slot.stratum == Stratum::Prompt) BOOST_CHECK(slot.scheduled[0] == 1800ms);
                    BOOST_CHECK(slot.scheduled_end - slot.scheduled.back() == 13000ms);
                    BOOST_CHECK(slot.scheduled_end <= 56800ms);
                }
            }
            BOOST_REQUIRE_EQUAL(late_firsts.size(), 2U);
            BOOST_CHECK(std::chrono::abs(late_firsts[0] - late_firsts[1]) >= timing.Scale(LATE_SLOT_SEPARATION));
            separation.Add(std::chrono::abs(late_firsts[0] - late_firsts[1]));
        }
        if (divisor == 10) {
            BOOST_CHECK(3500ms <= mid.min && mid.max <= 18000ms);
            BOOST_CHECK(18500ms <= late.min && late.max <= 24000ms);
            BOOST_CHECK(500ms <= separation.min);
            BOOST_CHECK(5000ms <= backup.min && backup.max <= 6000ms);
        }
        if (divisor == MAX_TIME_DIVISOR) {
            // With few values in each range, both ends come up: the ranges are closed.
            BOOST_CHECK(mid.min == 35ms && mid.max == 180ms);
            BOOST_CHECK(late.min == 185ms && late.max == 240ms);
            BOOST_CHECK(separation.min == 5ms);
            BOOST_CHECK(backup.min == 50ms && backup.max == 60ms);
        }
    }
}

BOOST_AUTO_TEST_CASE(seeds_and_onions)
{
    const std::vector<CService> fixed_seeds{FixedSeeds()};
    std::set<CService> onions_in;
    for (const CService& seed : fixed_seeds) {
        if (seed.IsTor()) onions_in.insert(seed);
    }
    BOOST_REQUIRE_EQUAL(onions_in.size(), 20U);

    FastRandomContext rng{uint256{2}};
    std::set<CService> onions_drawn;
    std::set<std::string> first_seeds;
    for (int draw{0}; draw < 200; ++draw) {
        const Plan plan{DrawPlan(rng, Timing{}, DNS_SEEDS, fixed_seeds)};
        BOOST_CHECK(std::is_permutation(plan.seed_order.begin(), plan.seed_order.end(), DNS_SEEDS.begin(), DNS_SEEDS.end()));
        // ONIONS_KEPT of the onion services, none twice, and never an IPv4, IPv6 or I2P entry (R2).
        BOOST_CHECK_EQUAL(plan.onions.size(), ONIONS_KEPT);
        BOOST_CHECK_EQUAL(std::set<CService>(plan.onions.begin(), plan.onions.end()).size(), plan.onions.size());
        for (const CService& onion : plan.onions) {
            BOOST_CHECK(onion.IsTor());
            BOOST_CHECK(onions_in.contains(onion));
        }
        onions_drawn.insert(plan.onions.begin(), plan.onions.end());
        first_seeds.insert(plan.seed_order.front());
    }
    // Over many jobs every onion is drawn and every seed comes first.
    BOOST_CHECK(onions_drawn == onions_in);
    BOOST_CHECK_EQUAL(first_seeds.size(), DNS_SEEDS.size());

    // With fewer onions than ONIONS_KEPT all are drawn. An entry listed twice counts once.
    const std::vector<std::string> names{"seed.a.example", "seed.b.example", "seed.a.example"};
    const std::vector<CService> few{Endpoint("1.2.3.4"), Onion(1), Endpoint("2600::1"), Onion(2), Onion(1), Onion(3)};
    const Plan plan{DrawPlan(rng, Timing{}, names, few)};
    const std::vector<std::string> distinct_names{"seed.a.example", "seed.b.example"};
    BOOST_CHECK(std::is_permutation(plan.seed_order.begin(), plan.seed_order.end(), distinct_names.begin(), distinct_names.end()));
    const std::vector<CService> distinct_onions{Onion(1), Onion(2), Onion(3)};
    BOOST_CHECK(std::is_permutation(plan.onions.begin(), plan.onions.end(), distinct_onions.begin(), distinct_onions.end()));

    // No onion in the list, or no list at all.
    const std::vector<CService> no_onions{Endpoint("1.2.3.4"), Endpoint("2600::1")};
    BOOST_CHECK(DrawPlan(rng, Timing{}, DNS_SEEDS, no_onions).onions.empty());
    const Plan empty{DrawPlan(rng, Timing{}, {}, {})};
    BOOST_CHECK(empty.seed_order.empty());
    BOOST_CHECK(empty.onions.empty());
}

BOOST_AUTO_TEST_SUITE_END()
