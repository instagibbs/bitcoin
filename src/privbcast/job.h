// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_JOB_H
#define BITCOIN_PRIVBCAST_JOB_H

#include <netbase.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/discovery.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <random.h>
#include <univalue.h>
#include <util/time.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace privbcast {

enum class SlotClass : uint8_t { ONION, EXIT_PATH };
/** When a slot's primary opens: at delivery start, or at a time drawn in the middle or late window. */
enum class Stratum : uint8_t { PROMPT, MID, LATE };
struct SlotSpec {
    Stratum stratum;
    SlotClass cls;
};
/** The delivery slots, the same for every job: three prompt (exit, exit, onion), one middle onion, two late exit-path. */
inline constexpr std::array<SlotSpec, 6> SLOT_SPECS{{{Stratum::PROMPT, SlotClass::EXIT_PATH},
                                                      {Stratum::PROMPT, SlotClass::EXIT_PATH},
                                                      {Stratum::PROMPT, SlotClass::ONION},
                                                      {Stratum::MID, SlotClass::ONION},
                                                      {Stratum::LATE, SlotClass::EXIT_PATH},
                                                      {Stratum::LATE, SlotClass::EXIT_PATH}}};
inline constexpr SlotClass ClassOfSlot(uint32_t slot) { return SLOT_SPECS[slot].cls; }
inline constexpr Stratum StratumOfSlot(uint32_t slot) { return SLOT_SPECS[slot].stratum; }
constexpr uint32_t CountSlots(Stratum stratum)
{
    uint32_t n{0};
    for (const SlotSpec& spec : SLOT_SPECS) {
        if (spec.stratum == stratum) ++n;
    }
    return n;
}
constexpr uint32_t CountSlots(SlotClass cls)
{
    uint32_t n{0};
    for (const SlotSpec& spec : SLOT_SPECS) {
        if (spec.cls == cls) ++n;
    }
    return n;
}

/** Delivery plan constants. Visible to recipients in aggregate, so identical for every user. */
namespace plan {
inline constexpr uint32_t SLOTS{SLOT_SPECS.size()};
inline constexpr uint32_t ONION_SLOTS{CountSlots(SlotClass::ONION)};
/** Connection opportunities per slot: a primary and three backups. */
inline constexpr uint32_t OPPORTUNITIES_PER_SLOT{4};
/** The middle slot's primary is drawn uniformly in this window after delivery start. */
inline constexpr auto MID_MIN{35s};
inline constexpr auto MID_MAX{180s};
/** The two late slots' primaries are drawn uniformly in this window after delivery start. */
inline constexpr auto LATE_MIN{185s};
inline constexpr auto LATE_MAX{240s};
/** Minimum scheduled separation between the two late primaries. */
inline constexpr auto PRIMARY_SEPARATION{5s};
/**
 * A backup opens this long after the previous opportunity's SCHEDULED start, drawn uniformly at
 * job start. The floor equals the handshake budget plus the start grace, so a pre-announcement
 * outcome is always known before the backup's time.
 */
inline constexpr auto BACKUP_MIN{50s};
inline constexpr auto BACKUP_MAX{60s};
/** A slot ends no later than this after its primary's scheduled start. */
inline constexpr auto SLOT_MAX{(OPPORTUNITIES_PER_SLOT - 1) * BACKUP_MAX + wire::ATTEMPT_MAX};
/** Latest scheduled end of any opportunity, from job start. */
inline constexpr auto SCHEDULED_BOUND{disc::WINDOW + LATE_MAX + SLOT_MAX};
/** Hard cap on the whole job, discovery included. */
inline constexpr auto JOB_CAP{10min};
/**
 * An opportunity (or discovery query) not started within this grace of its scheduled time is
 * skipped rather than dialled late, so when a connection starts never depends on how long
 * the previous one took. Only scheduler jitter is meant to fit inside it.
 */
inline constexpr auto START_GRACE{5s};
/** TCP connect timeout to the proxy, and the cap on each local SOCKS5 stage (method, auth) during delivery. */
inline constexpr auto CONNECT_TIMEOUT{disc::CONNECT_TIMEOUT};
inline constexpr auto SOCKS_RECV_TIMEOUT{15s};
/**
 * Reserved at the end of the handshake budget for the BIP324 handshake and VERSION/VERACK
 * (about two round trips over Tor): the SOCKS exchange must be over this long before the
 * handshake deadline.
 */
inline constexpr auto HANDSHAKE_RESERVE{10s};
static_assert(CountSlots(Stratum::PROMPT) >= 1 && CountSlots(Stratum::MID) == 1 && CountSlots(Stratum::LATE) == 2);
static_assert(OPPORTUNITIES_PER_SLOT >= 1);
static_assert(MID_MIN > 0s && MID_MIN <= MID_MAX && LATE_MIN > MID_MAX && LATE_MIN <= LATE_MAX);
static_assert(PRIMARY_SEPARATION > 0s && LATE_MAX - LATE_MIN >= PRIMARY_SEPARATION);
static_assert(BACKUP_MIN == wire::HANDSHAKE_TIMEOUT + START_GRACE);
static_assert(BACKUP_MIN <= BACKUP_MAX);
static_assert(SCHEDULED_BOUND <= JOB_CAP);
// A connect through the proxy returns before the slot's next opportunity: the TCP connect is
// bounded by CONNECT_TIMEOUT and the whole SOCKS exchange by an absolute deadline
// HANDSHAKE_RESERVE before the handshake deadline, so even an attempt started at the end of its
// grace has connected in time and is back before the next scheduled start.
static_assert(START_GRACE + CONNECT_TIMEOUT < wire::HANDSHAKE_TIMEOUT - HANDSHAKE_RESERVE);
static_assert(SOCKS_RECV_TIMEOUT < wire::HANDSHAKE_TIMEOUT - HANDSHAKE_RESERVE);
} // namespace plan

/**
 * Keep two draws from a window ending at `hi` at least `gap` apart: sorted, then the later one
 * moved forward, or the earlier one moved back when moving forward would leave the window.
 */
std::pair<std::chrono::seconds, std::chrono::seconds> SeparateDraws(std::chrono::seconds a, std::chrono::seconds b, std::chrono::seconds gap, std::chrono::seconds hi);

/** All timing of a job, fixed at its start. Nothing observed later moves any of it. */
struct Schedule {
    Clock::time_point t0;
    /** Each slot's primary offset from delivery start, unscaled: zero for the prompt slots, drawn for the rest. */
    std::array<std::chrono::seconds, plan::SLOTS> primary{};
    /** Each slot's backup intervals, unscaled: opportunity k opens backup[k-1] after opportunity k-1's scheduled start. */
    std::array<std::array<std::chrono::seconds, plan::OPPORTUNITIES_PER_SLOT - 1>, plan::SLOTS> backup{};

    static Schedule Draw(Clock::time_point t0, FastRandomContext& rng);
    Clock::time_point DeliveryStart() const { return t0 + Scaled(disc::WINDOW); }
    Clock::time_point OpportunityStart(uint32_t slot, uint32_t k) const;
    /** End of an attempt started at opportunity k of a slot, anchored to the scheduled start. */
    Clock::time_point AttemptDeadline(uint32_t slot, uint32_t k) const { return OpportunityStart(slot, k) + Scaled(wire::ATTEMPT_MAX); }
    Clock::time_point SlotEnd(uint32_t slot) const { return AttemptDeadline(slot, plan::OPPORTUNITIES_PER_SLOT - 1); }
};

/** Preassigned candidates indexed [slot][opportunity]; nullopt means unfillable. */
using Assignment = std::vector<std::vector<std::optional<Candidate>>>;

/**
 * Assign frozen candidates to opportunities. Primaries (opportunity 0) of every slot are
 * assigned before any backup, so no slot's first attempt is starved by another slot's backups.
 * Exit-path opportunities take seeds round-robin along the tie order, and a slot avoids a seed
 * it has already been given while another seed still has candidates. Onion opportunities take
 * the onion list and fall back to the exit-path pool only after the exit-path slots of the same
 * opportunity have drawn; exit-path opportunities never take onion candidates. A candidate is
 * used by exactly one opportunity.
 */
Assignment AssignCandidates(const DiscoveryResult& discovery);

/** What one slot did. */
struct SlotRecord {
    std::vector<AttemptResult> attempts;
    uint32_t empty_opportunities{0};  //!< no candidate was assigned
    uint32_t missed_opportunities{0}; //!< reached more than START_GRACE after the scheduled time (a stalled host or an overrunning previous attempt)
    bool interrupted{false};
    std::optional<std::string> error; //!< set if the slot's thread failed, with the exception text (possibly empty); no other slot is affected
};

/** How far a running job has got, reported after discovery and after every opportunity that ends. */
struct JobProgress {
    bool discovery_done{false};
    uint32_t opportunities_ended{0};   //!< dialled and over, missed, or without a candidate
    uint32_t connections{0};           //!< attempts made: the report's `connections`
    uint32_t announcements_written{0}; //!< attempts whose INV was fully written: the report's `announcements_written`
};

struct JobConfig {
    CTransactionRef tx;
    Proxy tor;
    DiscoveryPlan discovery;
    std::string chain;
    /** Cancellation flag, polled from every thread; must not throw. Production reads an atomic. */
    std::function<bool()> interrupted;
    /** Optional: called with the job's progress after discovery and after each opportunity ends, from the job's threads; must not throw. */
    std::function<void(const JobProgress&)> on_progress;
    /**
     * Test seam: how attempts open their connections. Defaults to TorConnector with the given
     * bounds (exchange deadline, stage and connect timeouts, and this job's own interrupt).
     */
    std::function<Connector(const Candidate&, const Socks5Params& socks)> connector;
    /** Test seam: the frozen candidates to deliver to. Defaults to resolving through the proxy. */
    std::function<DiscoveryResult()> discover;
};

/** The discovery section of the report; with `addresses`, also every kept candidate (the `discover` command). */
UniValue DiscoveryJson(const DiscoveryResult& discovery, bool addresses);

struct JobReport {
    UniValue json;
    /** 0: bounded effort completed with at least one INV fully written; 2: none written. */
    int exit_code{2};
};

/**
 * Build the JSON report from what happened. Pure. `slots_completed` counts slots whose opportunities
 * all ran, were skipped, or were suppressed by an announcement; an interrupted or failed slot is not
 * completed, and a job can be interrupted with every slot completed if the cancel arrived after the
 * last announcement.
 */
UniValue BuildReport(const std::string& chain, const CTransactionRef& tx, const Schedule& schedule,
                     const DiscoveryResult& discovery, const std::vector<SlotRecord>& records,
                     uint32_t slots_completed, bool interrupted, Clock::time_point ended,
                     int& exit_code);

JobReport RunJob(const JobConfig& cfg);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_JOB_H
