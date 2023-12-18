// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/feefrac.h>

void BuildDiagramFromUnsortedChunks(std::vector<FeeFrac>& chunks, std::vector<FeeFrac>& diagram)
{
    diagram.clear();
    // Finish by sorting the chunks we calculated, and then accumulating them.
    std::sort(chunks.begin(), chunks.end(), [](const FeeFrac& a, const FeeFrac& b) { return a > b; });

    // And now build the diagram for these chunks.
    diagram.emplace_back(FeeFrac{0, 0});
    for (auto& chunk : chunks) {
        FeeFrac& last = diagram.back();
        diagram.emplace_back(FeeFrac{last.fee+chunk.fee, last.size+chunk.size});
    }
    return;
}

