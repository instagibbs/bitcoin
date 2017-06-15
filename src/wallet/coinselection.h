// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_H
#define BITCOIN_COINSELECTION_H

#include "amount.h"
#include "primitives/transaction.h"
#include "random.h"
#include "wallet.h"

// rand can be nullptr, but only for testing. exclude_first should only ever be true in tests.
bool SelectCoinsBnB(std::vector<CInputCoin>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::vector<CInputCoin>& out_set, FastRandomContext* rand);

#endif // BITCOIN_COINSELECTION_H
