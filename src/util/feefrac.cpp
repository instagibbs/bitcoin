// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/feefrac.h>
#include <algorithm>
#include <array>
#include <vector>

void BuildDiagramFromUnsortedChunks(std::vector<FeeFrac>& chunks, std::vector<FeeFrac>& diagram)
{
    diagram.clear();
    diagram.reserve(chunks.size() + 1);
    // Finish by sorting the chunks we calculated, and then accumulating them.
    std::sort(chunks.begin(), chunks.end(), [](const FeeFrac& a, const FeeFrac& b) { return a > b; });

    // And now build the diagram for these chunks.
    diagram.emplace_back(0, 0);
    for (auto& chunk : chunks) {
        FeeFrac& last = diagram.back();
        diagram.emplace_back(last.fee+chunk.fee, last.size+chunk.size);
    }
}

std::partial_ordering CompareFeerateDiagram(Span<const FeeFrac> dia0, Span<const FeeFrac> dia1)
{
    /** Array to allow indexed access to input diagrams. */
    const std::array<Span<const FeeFrac>, 2> dias = {dia0, dia1};
    /** How many elements we have processed in each input. */
    size_t next_index[2] = {1, 1};
    /** Whether the corresponding input is strictly better than the other at least in one place. */
    bool better_somewhere[2] = {false, false};
    /** Get the first unprocessed point in diagram number dia. */
    const auto next_point = [&](int dia) { return dias[dia][next_index[dia]]; };
    /** Get the last processed point in diagram number dia. */
    const auto prev_point = [&](int dia) { return dias[dia][next_index[dia] - 1]; };

    // Diagrams should be non-empty, and first elements zero in size and fee
    Assert(!dia0.empty() && !dia1.empty());
    Assert(prev_point(0).IsEmpty());
    Assert(prev_point(1).IsEmpty());

    // Compare the overlapping area of the diagrams.
    while (next_index[0] < dias[0].size() && next_index[1] < dias[1].size()) {
        // Determine which diagram has the first unprocessed point.
        const int unproc_side = next_point(0).size > next_point(1).size;

        // let `P` be the next point on diagram unproc_side, and `A` and `B` the previous and next points
        // on the other diagram. We want to know if P lies above or below the line AB. To determine this, we
        // compute the direction coefficients of line AB and of line AP, and compare them. These
        // direction coefficients are fee per size, and can thus be expressed as FeeFracs.
        const FeeFrac& point_p = next_point(unproc_side);
        const FeeFrac& point_a = prev_point(!unproc_side);
        const FeeFrac& point_b = next_point(!unproc_side);
        const auto coef_ab = point_b - point_a;
        const auto coef_ap = point_p - point_a;
        Assume(coef_ap.size > 0);
        Assume(coef_ab.size >= coef_ap.size);
        // Perform the comparison. If P lies above AB, unproc_side is better in P. If P lies below
        // AB, then !unproc_side is better in P.
        const auto cmp = FeeRateCompare(coef_ap, coef_ab);
        if (std::is_gt(cmp)) better_somewhere[unproc_side] = true;
        if (std::is_lt(cmp)) better_somewhere[!unproc_side] = true;

        // Mark P as processed. If B and P have the same size, B can also be marked as processed as
        // we've already performed a comparison at this size.
        ++next_index[unproc_side];
        if (point_b.size == point_p.size) ++next_index[!unproc_side];
    }

    // Tail check at 0 feerate: Compare the remaining area. Use similar logic as in the loop above,
    // except we use a horizontal line instead of AB, as no point B exists anymore.
    const int long_side = next_index[1] != dias[1].size();
    Assume(next_index[!long_side] == dias[!long_side].size());
    // The point A now remains fixed: the last point of the shorter diagram.
    const FeeFrac& point_a = prev_point(!long_side);
    while (next_index[long_side] < dias[long_side].size()) {
        // Compare AP (where P is the next unprocessed point on the longer diagram) with a horizontal line
        // extending infinitely from A. This is equivalent to checking the sign of the fee of P-A.
        const FeeFrac& point_p = next_point(long_side);
        const auto coef_ap = point_p - point_a;
        const auto cmp = coef_ap.fee <=> 0;
        if (std::is_gt(cmp)) better_somewhere[long_side] = true;
        if (std::is_lt(cmp)) better_somewhere[!long_side] = true;
        // Mark P as processed.
        ++next_index[long_side];
    }

    // If both diagrams are better somewhere, they are incomparable.
    if (better_somewhere[0] && better_somewhere[1]) return std::partial_ordering::unordered;
    // Otherwise compare the better_somewhere values.
    return better_somewhere[0] <=> better_somewhere[1];
}
