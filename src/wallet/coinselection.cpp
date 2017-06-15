// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/coinselection.h"

// Descending order comparator
struct {
    bool operator()(CInputCoin a, CInputCoin b) const
    {
        return a.txout.nValue > b.txout.nValue;
    }
} descending;

bool SelectCoinsBnB(std::vector<CInputCoin>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::vector<CInputCoin>& out_set, FastRandomContext* rand)
{
    if (utxo_pool.size() <=0) {
        return false;
    }

    CAmount selected_value = 0;
    int depth = 0;
    int tries = 100000;
    std::vector<std::pair<bool, bool>> selection; // First bool: select the utxo at this index; Second bool: traversing second branch of this utxo
    selection.assign(utxo_pool.size(), std::pair<bool, bool>(false, false));
    bool done = false;
    bool backtrack = false;
    
    // Sort the utxo_pool
    std::sort(utxo_pool.begin(), utxo_pool.end(), descending);
    
    // Calculate remaining
    CAmount remaining = 0;
    for (CInputCoin utxo : utxo_pool) {
        remaining += utxo.txout.nValue;
    }
    
    // Depth first search to find 
    while (!done)
    {
        if (selected_value > target_value + cost_of_change) { // Selected value is out of range, go back and try other branch
            backtrack = true;
        } else if (selected_value >= target_value) { // Selected value is within range
            done = true;
        } else if (tries <= 0) { // Too many tries, exit
            done = true;
        } else if (depth >= (int)utxo_pool.size()) { // Reached a leaf node, no solution here
            backtrack = true;
        } else if (selected_value + remaining < target_value) { // Cannot possibly reach target with amount remaining
            if (depth == 0) { // At the first utxo, no possible selections, so exit
                return false;
            } else {
                backtrack = true;
            }
        } else { // Continue down this branch
            // Remove this utxo from the remaining utxo amount
            remaining -= utxo_pool.at(depth).txout.nValue;
            // Randomly choose to explore either inclusion or exclusion branch
            if (rand == nullptr || rand->randbool()) {
                // Inclusion branch first
                selection[depth].first = true;
                selected_value += utxo_pool.at(depth).txout.nValue;
                ++depth;
            } else {
                // Exclusion branch first
                selection[depth].first = false;
                ++depth;
            }
        }

        // Step back to the previous utxo and try the other branch
        if (backtrack) {
            backtrack = false; // Reset
            --depth;

            // Walk backwards to find the first utxo which has not has its second branch traversed
            while (selection[depth].second) {
                // Reset this utxo's selection
                if (selection[depth].first) {
                    selected_value -= utxo_pool.at(depth).txout.nValue;
                }
                selection[depth].first = false;
                selection[depth].second = false;
                remaining += utxo_pool.at(depth).txout.nValue;

                // Step back one
                --depth;

                if (depth < 0) { // We have walked back to the first utxo and no branch is untraversed. No solution, exit.
                    return false;
                }
            }
            
            if (!done) {
                // Now traverse the second branch of the utxo we have arrived at.
                selection[depth].second = true;

                if(selection[depth].first) { // If it was included, do exclusion now
                    selection[depth].first = false;
                    selected_value -= utxo_pool.at(depth).txout.nValue;
                    ++depth;
                }
                else { // It was excluded first, do inclusion now
                    selection[depth].first = true;
                    selected_value += utxo_pool.at(depth).txout.nValue;
                    ++ depth;
                }
            }
        }
        --tries;
    }

    // Set output set
    out_set.clear();
    for (unsigned int i = 0; i < selection.size(); ++i) {
        if (selection.at(i).first) {
            out_set.push_back(utxo_pool.at(i));
        }
   }

    return true;
}

