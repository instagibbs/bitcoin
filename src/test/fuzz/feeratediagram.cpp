// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>

#include <vector>

#include <util/feefrac.h>
#include <policy/rbf.h>

#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <assert.h>

namespace {

int CompareFeeFracWithDiagram(const FeeFrac& ff, Span<const FeeFrac> diagram)
{
    assert(diagram.size() > 0);
    unsigned not_above = 0;
    unsigned not_below = diagram.size() - 1;
    if (ff.size < diagram[not_above].size) return 0;
    if (ff.size > diagram[not_below].size) return 0;
    while (not_below > not_above + 1) {
        unsigned mid = (not_below + not_above) / 2;
        if (diagram[mid].size <= ff.size) not_above = mid;
        if (diagram[mid].size >= ff.size) not_below = mid;
    }
    if (not_below == not_above) {
        if (ff.fee > diagram[not_below].fee) return 1;
        if (ff.fee < diagram[not_below].fee) return -1;
        return 0;
    }
    int64_t left = ff.fee*diagram[not_below].size + diagram[not_above].fee*ff.size + diagram[not_below].fee*diagram[not_above].size;
    int64_t right = ff.size*diagram[not_below].fee + diagram[not_above].size*ff.fee + diagram[not_below].size*diagram[not_above].fee;
    if (left > right) return 1;
    if (left < right) return -1;
    return 0;
}

std::optional<int> CompareDiagrams(Span<const FeeFrac> dia1, Span<const FeeFrac> dia2)
{
    bool all_ge = true;
    bool all_le = true;
    for (const auto p1 : dia1) {
        int cmp = CompareFeeFracWithDiagram(p1, dia2);
        if (cmp < 0) all_ge = false;
        if (cmp > 0) all_le = false;
    }
    for (const auto p2 : dia2) {
        int cmp = CompareFeeFracWithDiagram(p2, dia1);
        if (cmp < 0) all_le = false;
        if (cmp > 0) all_ge = false;
    }
    if (all_ge && all_le) return 0;
    if (all_ge && !all_le) return 1;
    if (!all_ge && all_le) return -1;
    return std::nullopt;
}

void PopulateDiagram(FuzzedDataProvider& fuzzed_data_provider, std::vector<FeeFrac>& diagram)
{
    diagram.clear();
    diagram.emplace_back(FeeFrac{0, 0});

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 50)
    {
        const auto& last_point = diagram.back();
        diagram.emplace_back(FeeFrac{last_point.fee + fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(INT32_MIN>>1, INT32_MAX>>1), last_point.size+fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(1, 1000000)});
    }
    return;
}

void PopulateChunks(FuzzedDataProvider& fuzzed_data_provider, std::vector<FeeFrac>& chunks)
{
    chunks.clear();

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 50)
    {
        chunks.emplace_back(FeeFrac{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(INT32_MIN>>1, INT32_MAX>>1), fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(1, 1000000)});
    }
    return;
}

} // namespace

FUZZ_TARGET(rbf_compare_feerate_diagram)
{
    // Generate two random feerate diagrams, and verify that the comparison results match.
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::vector<FeeFrac> diagram1, diagram2;

    PopulateDiagram(fuzzed_data_provider, diagram1);
    PopulateDiagram(fuzzed_data_provider, diagram2);

    // Note: CompareFeerateDiagram will pad the diagrams to be the same size. I
    // believe this is needed, both for correctness of the algorithm, and also
    // so that the re-implementation above will produce correct results.
    if (CompareFeerateDiagram(diagram1, diagram2)) {
        assert(CompareFeerateDiagram(diagram2, diagram1) == false);
        assert(CompareDiagrams(diagram1, diagram2) == -1);
    }
    if (CompareFeerateDiagram(diagram2, diagram1)) {
        assert(CompareDiagrams(diagram2, diagram1) == -1);
    }
    return;
}

FUZZ_TARGET(build_and_compare_feerate_diagram)
{
    // Generate a random set of chunks
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::vector<FeeFrac> chunks1, chunks2;
    std::vector<FeeFrac> diagram1, diagram2;
    FeeFrac empty{0, 0};

    PopulateChunks(fuzzed_data_provider, chunks1);
    PopulateChunks(fuzzed_data_provider, chunks2);

    BuildDiagramFromUnsortedChunks(chunks1, diagram1);
    BuildDiagramFromUnsortedChunks(chunks2, diagram2);

    assert(diagram1.front() == empty);
    assert(diagram2.front() == empty);

    // Note: CompareFeerateDiagram will pad the diagrams to be the same size. I
    // believe this is needed, both for correctness of the algorithm, and also
    // so that the re-implementation above will produce correct results.
    if (CompareFeerateDiagram(diagram1, diagram2)) {
        assert(CompareFeerateDiagram(diagram2, diagram1) == false);
        assert(CompareDiagrams(diagram1, diagram2) == -1);
    }
    if (CompareFeerateDiagram(diagram2, diagram1)) {
        assert(CompareDiagrams(diagram2, diagram1) == -1);
    }
    return;
}
