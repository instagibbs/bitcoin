// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privbcast/assign.h>

#include <hash.h>
#include <netaddress.h>
#include <privbcast/params.h>
#include <privbcast/plan.h>
#include <random.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace privbcast {

Assignment Assign(const Plan& plan, const DiscoveryResult& result)
{
    // Discovery lists the seeds in the plan's order.
    Assume(std::ranges::equal(result.seeds, plan.seed_order, {}, &SeedAnswers::name));
    const size_t num_seeds{result.seeds.size()};
    Assignment assignment;
    assignment.seeds.resize(num_seeds);

    std::set<CService> accepted;
    for (size_t pos{0}; pos < num_seeds; ++pos) {
        const SeedAnswers& answers{result.seeds[pos]};
        SeedSummary& seed{assignment.seeds[pos]};
        seed.name = answers.name;
        seed.queries = answers.queries;
        seed.skipped = answers.skipped;
        seed.answers = answers.answers;
        assignment.rejected += answers.rejected;

        std::vector<CService> credited;
        for (const CService& endpoint : answers.usable) {
            if (accepted.insert(endpoint).second) {
                credited.push_back(endpoint);
            } else {
                ++assignment.duplicates;
            }
        }
        // Sorted, so that the order the answers arrived in plays no part in the draw (R5b).
        std::sort(credited.begin(), credited.end());
        // A generator per seed, so that how many answers the other seeds had plays no part in this
        // seed's draw.
        FastRandomContext rng{(HashWriter{} << plan.answer_seed << uint64_t{pos}).GetSHA256()};
        std::shuffle(credited.begin(), credited.end(), rng);
        seed.accepted = static_cast<int>(credited.size());
        seed.kept = std::min(seed.accepted, ANSWERS_KEPT_PER_SEED);
        seed.candidates.assign(credited.begin(), credited.begin() + seed.kept);
        assignment.exit_path_candidates += seed.kept;
    }
    assignment.onion_candidates = static_cast<int>(plan.onions.size());

    // The hand-out state, by position in the plan's order of the seeds.
    std::vector<size_t> handed_out(num_seeds, 0);
    std::array<std::vector<bool>, SLOTS> drawn_from;
    drawn_from.fill(std::vector<bool>(num_seeds, false));
    size_t next_seed{0};
    const auto draw_exit_path{[&](size_t slot) -> std::optional<Candidate> {
        // First a seed this slot has not drawn from, then any with a candidate left (R5b).
        for (const bool again : {false, true}) {
            for (size_t step{0}; step < num_seeds; ++step) {
                const size_t pos{(next_seed + step) % num_seeds};
                const SeedSummary& seed{assignment.seeds[pos]};
                if (handed_out[pos] == seed.candidates.size()) continue;
                if (drawn_from[slot][pos] && !again) continue;
                drawn_from[slot][pos] = true;
                next_seed = (pos + 1) % num_seeds;
                return Candidate{seed.candidates[handed_out[pos]++], Source::DnsSeed, seed.name};
            }
        }
        return std::nullopt;
    }};

    size_t next_onion{0};
    for (size_t layer{0}; layer < OPPORTUNITIES_PER_SLOT; ++layer) {
        for (const SlotClass cls : {SlotClass::ExitPath, SlotClass::Onion}) {
            for (size_t slot{0}; slot < SLOTS; ++slot) {
                if (plan.slots[slot].cls != cls) continue;
                std::optional<Candidate>& opportunity{assignment.opportunities[slot][layer]};
                if (cls == SlotClass::Onion && next_onion < plan.onions.size()) {
                    opportunity = Candidate{plan.onions[next_onion++], Source::Bundled, "bundled"};
                } else {
                    opportunity = draw_exit_path(slot);
                }
            }
        }
    }
    return assignment;
}

} // namespace privbcast
