// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_DISCOVERY_H
#define BITCOIN_PRIVBCAST_DISCOVERY_H

#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <util/time.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace privbcast {

using namespace std::chrono_literals;

/** Discovery constants. Wire-visible to seeds and exits, so identical for every user. */
namespace disc {
/** RESOLVE queries per seed, each on a fresh Tor stream. */
inline constexpr uint32_t QUERIES_PER_SEED{4};
/** Candidates kept per seed after deduplication. */
inline constexpr uint32_t MAX_PER_SEED{3};
/** Onion candidates kept from the bundled list. */
inline constexpr uint32_t MAX_BUNDLED{8};
/**
 * All of a seed's queries start together at job start, each on its own Tor stream. Delivery
 * begins at the window's end regardless of answers; a RESOLVE still running then is cut off.
 */
inline constexpr auto WINDOW{18s};
/**
 * Absolute deadline, from job start, for every RESOLVE exchange. On one Tor client over 40 bursts a
 * whole burst completed within 8 s nine times in ten and 15 s kept the same candidates as 25 s;
 * QUERIES_PER_SEED against MAX_PER_SEED absorbs a single slow circuit, not a stall of the whole
 * burst, and other Tor environments may lose candidates here.
 */
inline constexpr auto QUERY_DEADLINE{15s};
/** A query not started within this grace of job start (a stalled host) is skipped, not run late. */
inline constexpr auto QUERY_GRACE{5s};
/** TCP connect timeout to the proxy, and the cap on each local SOCKS5 stage (method, auth) during discovery. */
inline constexpr auto CONNECT_TIMEOUT{5s};
inline constexpr auto SOCKS_RECV_TIMEOUT{8s};
// A RESOLVE fits the window: even a query started at the end of its grace has connected by
// QUERY_GRACE + CONNECT_TIMEOUT and its exchange ends by QUERY_DEADLINE, before delivery starts.
static_assert(QUERY_GRACE + CONNECT_TIMEOUT < QUERY_DEADLINE);
static_assert(QUERY_DEADLINE < WINDOW);
} // namespace disc

/**
 * Isolation credentials for one proxy stream, drawn fresh from the OS: no process- or job-wide
 * prefix, so nothing at the SOCKS interface groups the node's streams with a job's.
 */
ProxyCredentials FreshIsolationCredentials();

/** Where a candidate recipient came from. */
enum class Source : uint8_t {
    DNS_SEED, //!< A release DNS seed name, resolved through Tor; reached through an exit
    BUNDLED,  //!< The release fixed-seed list; onion, no exit
};

struct Candidate {
    CService addr;
    Source source;
    /** Seed name for DNS_SEED, "bundled" for BUNDLED. */
    std::string provenance;
};

/** Everything discovery is allowed to know. Common release material, fixed before any query. */
struct DiscoveryPlan {
    /** Release seed names, base form, in release order. */
    std::vector<std::string> dns_seeds;
    /** Release fixed seeds; only onion entries are used. */
    std::vector<CService> bundled;
    /** P2P port attached to resolved addresses. */
    uint16_t port{0};
};

struct SeedStats {
    std::string name;
    uint32_t queries{0};  //!< RESOLVE queries sent
    uint32_t skipped{0};  //!< Queries not sent because their fixed slot had already passed
    uint32_t answers{0};  //!< Successful numeric replies
    uint32_t accepted{0}; //!< Valid public endpoints not already assigned to an earlier seed in tie order
    uint32_t kept{0};     //!< Candidates kept after the per-seed cap
};

struct DiscoveryResult {
    /** Kept exit-path candidates per seed, indexed like DiscoveryPlan::dns_seeds. Not flattened. */
    std::vector<std::vector<Candidate>> per_seed;
    /** Kept onion candidates. */
    std::vector<Candidate> onion;
    std::vector<SeedStats> seeds;
    /** Permutation of seed indices drawn before any query; decides duplicate assignment and slot order. */
    std::vector<size_t> tie_order;
    uint32_t duplicates{0}; //!< Answers dropped because the endpoint was already assigned
    uint32_t rejected{0};   //!< Answers that were not valid public IPv4/IPv6
    std::chrono::milliseconds duration{0};

    size_t NumExitPath() const;
};

/** Raw RESOLVE answers per seed, indexed like DiscoveryPlan::dns_seeds. */
using SeedAnswers = std::vector<std::vector<CNetAddr>>;

/**
 * Freeze candidates from raw answers: validate, deduplicate by tie order, apply the caps,
 * shuffle. A pure function of its inputs and the rng.
 */
DiscoveryResult Freeze(const DiscoveryPlan& plan, const SeedAnswers& answers, const std::vector<size_t>& tie_order, FastRandomContext& rng);

/**
 * Resolve the plan's seed names through the Tor proxy on the fixed query schedule anchored
 * at `t0`, then freeze. Returns when every query has completed or when the discovery window
 * ends, whichever comes first; answers arriving after that are discarded, so a slow seed or
 * exit cannot delay delivery. `interrupted` is polled from several threads and must be safe
 * to call concurrently.
 */
DiscoveryResult Discover(const Proxy& tor, const DiscoveryPlan& plan, SteadyClock::time_point t0, FastRandomContext& rng, const std::function<bool()>& interrupted);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_DISCOVERY_H
