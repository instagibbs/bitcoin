// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <node/anticycle.h>
#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <memory>

#include <boost/test/unit_test.hpp>

using node::AntiCycle;

BOOST_FIXTURE_TEST_SUITE(anticycle_tests, TestChain100Setup)

// When an attacker RBF-evicts a CPFP child whose parent survives, the coordinator parks the
// whole {parent, child} 1P1C package (keyed by the parent's input).
BOOST_AUTO_TEST_CASE(parks_1p1c_on_child_eviction)
{
    auto ac = std::make_shared<AntiCycle>(*m_node.mempool, /*max_park_weight=*/4'000'000);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    const COutPoint coin{m_coinbase_txns[0]->GetHash(), 0};

    // Parent A spends the coinbase; child B spends A's output. Both enter the mempool.
    const auto A = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk,
        /*output_amount=*/49 * COIN, /*submit=*/true));
    const auto B = MakeTransactionRef(CreateValidMempoolTransaction(
        A, /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk,
        /*output_amount=*/48 * COIN, /*submit=*/true));

    // Attacker B2 spends A's output at a higher fee -> RBF-evicts the child B (A survives).
    const auto B2 = MakeTransactionRef(CreateValidMempoolTransaction(
        A, /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk,
        /*output_amount=*/40 * COIN, /*submit=*/false));
    const auto result = m_node.chainman->ProcessTransaction(B2);
    BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // The coordinator parked the {A, B} 1P1C package, keyed by A's input (the coinbase).
    const auto* pkg = ac->buffer().FindByInput(coin);
    BOOST_REQUIRE(pkg != nullptr);
    BOOST_CHECK_EQUAL(pkg->txns.size(), 2U);

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

BOOST_AUTO_TEST_SUITE_END()
