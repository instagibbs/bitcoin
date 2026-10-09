// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIVBCAST_ASSIGN_H
#define BITCOIN_PRIVBCAST_ASSIGN_H

#include <netaddress.h>
#include <privbcast/params.h>
#include <privbcast/plan.h>

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace privbcast {

/** One DNS seed's answers, as discovery collected them. */
struct SeedAnswers {
    std::string name;
    /** RESOLVE queries started and not started, answers received in the window, and those of them
     *  that were not public routable IPv4 or IPv6 addresses (R2). */
    int queries{0}, skipped{0}, answers{0}, rejected{0};
    /** The other answers, with the chain's default port, repeats kept. */
    std::vector<CService> usable;
};

/** What discovery found (C3). */
struct DiscoveryResult {
    std::vector<SeedAnswers> seeds;
    /** When discovery ended, from job start. */
    std::chrono::milliseconds duration{0};
};

enum class Source { DnsSeed, Bundled };

/** The recipient of an opportunity. */
struct Candidate {
    CService endpoint;
    Source source{Source::DnsSeed};
    /** The DNS seed's name, or "bundled" for an onion of the fixed-seed list. */
    std::string provenance;

    bool operator==(const Candidate&) const = default;
};

/** One DNS seed's entry in the report. */
struct SeedSummary {
    std::string name;
    /** As discovery counted them. */
    int queries{0}, skipped{0}, answers{0};
    /** Distinct usable endpoints credited to this seed, and those of them that became candidates. */
    int accepted{0}, kept{0};
    /** The kept endpoints, in the order they are handed out. */
    std::vector<CService> candidates;

    bool operator==(const SeedSummary&) const = default;
};

/** The counts the report shows of discovery and the assignment. */
struct DiscoverySummary {
    /** One per DNS seed, in the plan's order, with the endpoints each kept. */
    std::vector<SeedSummary> seeds;
    /** Usable answers whose endpoint was already accepted, and answers that were not usable. */
    int duplicates{0}, rejected{0};
    /** The sum of kept, and the number of the plan's onions. */
    int exit_path_candidates{0}, onion_candidates{0};

    bool operator==(const DiscoverySummary&) const = default;
};

/** Every opportunity's candidate, and the counts the report shows. */
struct Assignment : DiscoverySummary {
    /** By slot index, then opportunity. Empty where there is no candidate. */
    std::array<std::array<std::optional<Candidate>, OPPORTUNITIES_PER_SLOT>, SLOTS> opportunities;

    bool operator==(const Assignment&) const = default;
};

/**
 * Fix every opportunity's candidate when discovery ends, as a function of the plan and the
 * discovery result alone (C2). The result lists the seeds in plan.seed_order, as discovery does.
 *
 * Each endpoint is credited to the first seed in plan.seed_order that returned it (R4). Each seed
 * keeps ANSWERS_KEPT_PER_SEED of its credited endpoints, drawn at random: sorted, then shuffled by
 * a generator seeded from plan.answer_seed and the seed's position in plan.seed_order (R5b). The
 * opportunities are filled layer by layer, every slot's first opportunity before any slot's first
 * backup and so on (R5a). In each layer the exit-path slots draw first, round robin over the seeds
 * in plan.seed_order, from a seed the slot has not drawn from or, once none of those has a
 * candidate left, from one it has; an opportunity stays empty only when no candidate is left (R5b).
 * Then the onion slots take the plan's onions in turn and, once none is left, draw as the
 * exit-path slots do (R5c).
 */
Assignment Assign(const Plan& plan, const DiscoveryResult& result);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_ASSIGN_H
