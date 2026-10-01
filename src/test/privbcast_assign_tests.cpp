// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <netbase.h>
#include <privbcast/assign.h>
#include <privbcast/params.h>
#include <privbcast/plan.h>
#include <random.h>
#include <tinyformat.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace privbcast;

namespace {

CService Endpoint(const std::string& addr)
{
    const std::optional<CService> endpoint{Lookup(addr, /*portDefault=*/8333, /*fAllowLookup=*/false)};
    BOOST_REQUIRE(endpoint);
    return *endpoint;
}

/** A public IPv4 endpoint with the default port, different for every (seed, n). */
CService Answer(int seed, int n)
{
    return Endpoint(strprintf("1.%d.%d.1", seed + 1, n + 1));
}

/** A different onion service for every n. */
CService Onion(int n)
{
    std::array<uint8_t, 32> pubkey{};
    pubkey[0] = static_cast<uint8_t>(n);
    return Endpoint(OnionToString(pubkey));
}

std::vector<CService> Onions(int count)
{
    std::vector<CService> onions;
    for (int n{0}; n < count; ++n) onions.push_back(Onion(n));
    return onions;
}

std::string Name(int seed) { return strprintf("seed%d.example", seed); }

/** A seed that answered every query with these usable endpoints. */
SeedAnswers Seed(const std::string& name, std::vector<CService> usable)
{
    SeedAnswers seed;
    seed.name = name;
    seed.queries = QUERIES_PER_SEED;
    seed.answers = static_cast<int>(usable.size());
    seed.usable = std::move(usable);
    return seed;
}

/** Seeds 0 to count - 1, each with `answers` endpoints of its own. */
DiscoveryResult Seeds(int count, int answers)
{
    DiscoveryResult result;
    for (int seed{0}; seed < count; ++seed) {
        std::vector<CService> usable;
        for (int n{0}; n < answers; ++n) usable.push_back(Answer(seed, n));
        result.seeds.push_back(Seed(Name(seed), usable));
    }
    return result;
}

/** A plan with a real schedule, these seeds in this order and these onions. */
Plan MakePlan(std::vector<std::string> seed_order, std::vector<CService> onions = {})
{
    FastRandomContext rng{uint256{1}};
    Plan plan{DrawPlan(rng, Timing{}, {}, {})};
    plan.seed_order = std::move(seed_order);
    plan.onions = std::move(onions);
    return plan;
}

std::vector<std::string> Names(int count)
{
    std::vector<std::string> names;
    for (int seed{0}; seed < count; ++seed) names.push_back(Name(seed));
    return names;
}

/** The opportunities, a slot at a time: D for a DNS seed's candidate, O for an onion, . for none. */
std::string Layout(const Assignment& assignment)
{
    std::string layout;
    for (size_t slot{0}; slot < SLOTS; ++slot) {
        if (slot > 0) layout += ' ';
        for (const std::optional<Candidate>& candidate : assignment.opportunities[slot]) {
            layout += !candidate ? '.' : candidate->source == Source::Bundled ? 'O' : 'D';
        }
    }
    return layout;
}

/** The seed of each of a slot's DNS seed candidates. */
std::vector<std::string> Provenances(const Assignment& assignment, size_t slot)
{
    std::vector<std::string> provenances;
    for (const std::optional<Candidate>& candidate : assignment.opportunities[slot]) {
        if (candidate && candidate->source == Source::DnsSeed) provenances.push_back(candidate->provenance);
    }
    return provenances;
}

bool Contains(const std::vector<CService>& endpoints, const CService& endpoint)
{
    return std::ranges::find(endpoints, endpoint) != endpoints.end();
}

} // namespace

BOOST_AUTO_TEST_SUITE(privbcast_assign_tests)

BOOST_AUTO_TEST_CASE(kept_at_random)
{
    // R5b: a seed keeps three of four answers, at random: each is left out under some answer_seed.
    const DiscoveryResult four{Seeds(1, 4)};
    Plan plan{MakePlan(Names(1))};
    std::set<CService> left_out;
    for (uint64_t answer_seed{0}; answer_seed < 100; ++answer_seed) {
        plan.answer_seed = answer_seed;
        const Assignment assignment{Assign(plan, four)};
        BOOST_CHECK_EQUAL(assignment.seeds[0].accepted, 4);
        BOOST_REQUIRE_EQUAL(assignment.seeds[0].kept, 3);
        for (const CService& answer : four.seeds[0].usable) {
            if (!Contains(assignment.seeds[0].candidates, answer)) left_out.insert(answer);
        }
    }
    BOOST_CHECK_EQUAL(left_out.size(), 4U);
}

BOOST_AUTO_TEST_CASE(spread_over_seeds)
{
    // R5b: a slot draws from a seed again only once no seed it has not drawn from has a candidate,
    // rather than leave an opportunity empty. Seeds keep 3, 3, 2 and 2: in the third layer slot 0,
    // which has drawn from the only two seeds left, takes the second's, and slot 1 the first's.
    DiscoveryResult result{Seeds(4, 3)};
    for (const int seed : {2, 3}) {
        result.seeds[seed].usable.resize(2);
        result.seeds[seed].answers = 2;
    }
    const Plan plan{MakePlan(Names(4), Onions(8))};
    const Assignment assignment{Assign(plan, result)};
    BOOST_CHECK_EQUAL(Layout(assignment), "DDD. DDD. OOOO OOOO DD.. DD..");
    BOOST_CHECK(Provenances(assignment, 0) == (std::vector{Name(0), Name(1), Name(1)}));
    BOOST_CHECK(Provenances(assignment, 1) == (std::vector{Name(1), Name(2), Name(0)}));
    BOOST_CHECK(Provenances(assignment, 4) == (std::vector{Name(2), Name(3)}));
    BOOST_CHECK(Provenances(assignment, 5) == (std::vector{Name(3), Name(0)}));
}

BOOST_AUTO_TEST_SUITE_END()
