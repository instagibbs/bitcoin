// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_H
#define BITCOIN_COINSELECTION_H

#include "amount.h"
#include "primitives/transaction.h"
#include "random.h"

/**
 * A coin selector object
 */
class CoinSelector
{
public:
    static bool BranchAndBoundSearch(std::vector<std::pair<CAmount, COutPoint>>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::vector<std::pair<CAmount, COutPoint>>& out_set, FastRandomContext& rand);
    
};

#endif // BITCOIN_COINSELECTION_H
