// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_H
#define BITCOIN_COINSELECTION_H

#include "amount.h"
#include "primitives/transaction.h"
#include "random.h"
#include "wallet/wallet.h"

// rand can be nullptr, but only for testing. exclude_first should only ever be true in tests.
bool SelectCoinsBnB(std::vector<CInputCoin>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::set<CInputCoin>& out_set, CAmount& value_ret, std::vector<CAmount>& fee_vec, CAmount& fee_ret);

// Original coin selection algorithm as a fallback
bool KnapsackSolver(std::vector<CInputCoin>& utxo_pool, const CAmount& nTargetValue, std::set<CInputCoin>& out_set, CAmount& value_ret);

#endif // BITCOIN_COINSELECTION_H
