// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "wallet/coinselection.h"
#include "amount.h"
#include "primitives/transaction.h"
#include "random.h"
#include "test/test_bitcoin.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(coin_selection_tests, WalletTestingSetup)

static const CWallet testWallet;
static void add_coin(const CAmount& nValue, int nInput, std::vector<CInputCoin>& set)
{
    CMutableTransaction tx;
    tx.vout.resize(nInput+1);
    tx.vout[nInput].nValue = nValue;
    std::unique_ptr<CWalletTx> wtx(new CWalletTx(&testWallet, MakeTransactionRef(std::move(tx))));
    set.emplace_back(CInputCoin(wtx.get(), nInput));
}
static bool equal_sets(std::vector<CInputCoin> a, std::vector<CInputCoin> b)
{
    // Sets different if different size
    if (a.size() != b.size()) {
        return false;
    }

    // Check each element
    for (unsigned int i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }

    return true;
}

BOOST_AUTO_TEST_CASE(bnb_search_test)
{
    // Setup 
    std::vector<CInputCoin> utxo_pool;
    std::vector<CInputCoin> selection;
    std::vector<CInputCoin> actual_selection;
    
    /////////////////////////
    // Known Outcome tests //
    /////////////////////////
    BOOST_TEST_MESSAGE("Testing known outcomes");

    // Empty utxo pool
    BOOST_CHECK(!SelectCoinsBnB(utxo_pool, 1 * CENT, 0.5 * CENT, selection, nullptr));
    selection.clear();
    
    // Add 1, 2, and 3, utxos
    add_coin(1 * CENT, 1, utxo_pool);    
    add_coin(2 * CENT, 2, utxo_pool);
    add_coin(3 * CENT, 3, utxo_pool);
    add_coin(4 * CENT, 4, utxo_pool);
    
    // Select 1 Cent
    add_coin(1 * CENT, 1, actual_selection);
    BOOST_CHECK(SelectCoinsBnB(utxo_pool, 1 * CENT, 0.5 * CENT, selection, nullptr));
    BOOST_CHECK(equal_sets(selection, actual_selection));
    actual_selection.clear();
    selection.clear();
    
    // Select 2 Cent
    add_coin(2 * CENT, 2, actual_selection);
    BOOST_CHECK(SelectCoinsBnB(utxo_pool, 2 * CENT, 0.5 * CENT, selection, nullptr));
    BOOST_CHECK(equal_sets(selection, actual_selection));
    actual_selection.clear();
    selection.clear();
    
    // Select 5 Cent
    add_coin(4 * CENT, 4, actual_selection);
    add_coin(1 * CENT, 1, actual_selection);
    BOOST_CHECK(SelectCoinsBnB(utxo_pool, 5 * CENT, 0.5 * CENT, selection, nullptr));
    BOOST_CHECK(equal_sets(selection, actual_selection));
    actual_selection.clear();
    selection.clear();
    
    // Select 11 Cent, not possible
    BOOST_CHECK(!SelectCoinsBnB(utxo_pool, 11 * CENT, 0.5 * CENT, selection, nullptr));
    actual_selection.clear();
    selection.clear();
    
    // Select 10 Cent
    add_coin(5 * CENT, 5, utxo_pool);
    add_coin(5 * CENT, 5, actual_selection);
    add_coin(4 * CENT, 4, actual_selection);
    add_coin(1 * CENT, 1, actual_selection);
    BOOST_CHECK(SelectCoinsBnB(utxo_pool, 10 * CENT, 0.5 * CENT, selection, nullptr));
    BOOST_CHECK(equal_sets(selection, actual_selection));
    actual_selection.clear();
    selection.clear();

    // Select 0.25 Cent, not possible
    BOOST_CHECK(!SelectCoinsBnB(utxo_pool, 0.25 * CENT, 0.5 * CENT, selection, nullptr));
    actual_selection.clear();
    selection.clear();

    ////////////////////
    // Behavior tests //
    ////////////////////
    BOOST_TEST_MESSAGE("Testing behavior");

    FastRandomContext rand;

    // Populate utxo pool with 50 inputs from 1 to 50
    utxo_pool.clear();
    for (int i = 1; i <= 50; ++i) {
        add_coin(i * CENT, i, utxo_pool);
    }

    // Select 100 Cent
    // One possible exact solution, should appear at least once.
    add_coin(50 * CENT, 50, actual_selection);
    add_coin(49 * CENT, 49, actual_selection);
    add_coin(3 * CENT, 3, actual_selection);
    bool found_sample_sol = false;
    // Run 100 times, make sure above solution appears and that solutions are valid
    for (int i = 0; i < 100; ++i) {
        BOOST_CHECK(SelectCoinsBnB(utxo_pool, 100 * CENT, 2 * CENT, selection, &rand));
        if (equal_sets(selection, actual_selection)) {
            found_sample_sol = true;
        }
        // Check the solution is within the bounds set
        CAmount selection_value = 0;
        for (auto utxo : selection) {
            selection_value += utxo.txout.nValue;
        }
        BOOST_CHECK(selection_value >= 100 * CENT);
        BOOST_CHECK(selection_value <= 102 * CENT);
    }
    BOOST_CHECK(found_sample_sol);
    
    // Select 1 Cent with pool of only greater than 5 Cent
    utxo_pool.clear();
    for (int i = 5; i <= 20; ++i) {
        add_coin(i * CENT, i, utxo_pool);
    }
    // Run 100 times, to make sure it is never finding a solution
    for (int i = 0; i < 100; ++i) {
        BOOST_CHECK(!SelectCoinsBnB(utxo_pool, 1 * CENT, 2 * CENT, selection, &rand));
    } 
}

BOOST_AUTO_TEST_SUITE_END()
