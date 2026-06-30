// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <node/anticycle.h>
#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <validation.h>

#include <memory>
#include <optional>

#include <boost/test/unit_test.hpp>

using node::AntiCycle;

BOOST_FIXTURE_TEST_SUITE(anticycle_tests, TestChain100Setup)

// When an attacker RBF-evicts a CPFP child, the coordinator parks the whole CHUNK the victim
// belonged to -- here {A, B}, since B's CPFP bumps A into the same chunk. Parking the chunk (not
// just the evicted child) keeps the package reinstatable even if the now-unbumped parent A is
// later size-evicted. The chunk is reconstructed at eviction from cluster members sharing the
// chunk feerate, so it is exactly the chunk -- never the wider cluster.
BOOST_AUTO_TEST_CASE(parks_displaced_chunk)
{
    auto ac = std::make_shared<AntiCycle>(*m_node.chainman, *m_node.mempool, /*max_park_weight=*/4'000'000);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;

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
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(B2).m_result_type == MempoolAcceptResult::ResultType::VALID);

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // The whole chunk {A, B} is parked (parent first, topologically), keyed by the anchor.
    const auto* pkg = ac->buffer().FindByInput(COutPoint{A->GetHash(), 0});
    BOOST_REQUIRE(pkg != nullptr);
    BOOST_REQUIRE_EQUAL(pkg->txns.size(), 2U);
    BOOST_CHECK(pkg->txns.at(0)->GetHash() == A->GetHash()); // parent before child
    BOOST_CHECK(pkg->txns.at(1)->GetHash() == B->GetHash());
    // The chunk's footprint also covers A's own input (so a cycle on it would be seen too).
    BOOST_CHECK(ac->buffer().FindByInput(COutPoint{m_coinbase_txns[0]->GetHash(), 0}) != nullptr);

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

// The full cycle: a victim child is evicted, the attacker withdraws (freeing the contended
// outpoint), and the coordinator reinstates the victim through normal validation.
BOOST_AUTO_TEST_CASE(reinstates_victim_when_outpoint_frees)
{
    auto ac = std::make_shared<AntiCycle>(*m_node.chainman, *m_node.mempool, /*max_park_weight=*/4'000'000);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    // Mature a second coinbase so the attacker has its own cycling input.
    CreateAndProcessBlock({}, spk);
    CreateAndProcessBlock({}, spk);

    // Victim package {A, B}: parent A spends coinbase[0]; child B spends A's output.
    const auto A = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk, 49 * COIN, /*submit=*/true));
    const auto B = MakeTransactionRef(CreateValidMempoolTransaction(
        A, /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk, 48 * COIN, /*submit=*/true));
    BOOST_REQUIRE(m_node.mempool->exists(B->GetHash()));

    // Attacker B2 spends A's output + its own coin at a higher fee -> evicts child B (A survives).
    const auto B2 = MakeTransactionRef(CreateValidTransaction(
        {A, m_coinbase_txns[1]},
        {COutPoint{A->GetHash(), 0}, COutPoint{m_coinbase_txns[1]->GetHash(), 0}},
        /*input_height=*/0, {coinbaseKey, coinbaseKey}, {CTxOut{95 * COIN, spk}},
        /*feerate=*/std::nullopt, /*fee_output=*/std::nullopt).first);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(B2).m_result_type == MempoolAcceptResult::ResultType::VALID);
    BOOST_REQUIRE(!m_node.mempool->exists(B->GetHash())); // victim evicted

    // Attacker B3 spends only its own coin (not A's output) at a higher fee -> replaces B2 and
    // frees A's output -- the cycling withdrawal.
    const auto B3 = MakeTransactionRef(CreateValidTransaction(
        {m_coinbase_txns[1]}, {COutPoint{m_coinbase_txns[1]->GetHash(), 0}},
        /*input_height=*/0, {coinbaseKey}, {CTxOut{45 * COIN, spk}},
        /*feerate=*/std::nullopt, /*fee_output=*/std::nullopt).first);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(B3).m_result_type == MempoolAcceptResult::ResultType::VALID);

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // The coordinator reinstated the victim B once A's output became spendable again.
    BOOST_CHECK(m_node.mempool->exists(B->GetHash()));

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

// A parked package is dropped once its contended outpoint is spent on-chain by a non-member
// (the attacker's replacement confirms): the victim can never be reinstated, so don't keep it.
BOOST_AUTO_TEST_CASE(drains_parked_package_when_outpoint_spent_onchain)
{
    auto ac = std::make_shared<AntiCycle>(*m_node.chainman, *m_node.mempool, /*max_park_weight=*/4'000'000);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    CreateAndProcessBlock({}, spk);
    CreateAndProcessBlock({}, spk);

    const auto A = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk, 49 * COIN, /*submit=*/true));
    const auto B = MakeTransactionRef(CreateValidMempoolTransaction(
        A, /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk, 48 * COIN, /*submit=*/true));

    // Attacker B2 spends A's output + own coin -> evicts B; coordinator parks {A, B}.
    const auto B2 = CreateValidTransaction(
        {A, m_coinbase_txns[1]},
        {COutPoint{A->GetHash(), 0}, COutPoint{m_coinbase_txns[1]->GetHash(), 0}},
        /*input_height=*/0, {coinbaseKey, coinbaseKey}, {CTxOut{95 * COIN, spk}},
        /*feerate=*/std::nullopt, /*fee_output=*/std::nullopt).first;
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(MakeTransactionRef(B2)).m_result_type == MempoolAcceptResult::ResultType::VALID);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(ac->buffer().FindByInput(COutPoint{A->GetHash(), 0}) != nullptr);

    // Confirm A and B2 in a block: B2 spends A's output on-chain, so {A, B} can never reinstate.
    CreateAndProcessBlock({CMutableTransaction(*A), B2}, spk);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_CHECK(ac->buffer().FindByInput(COutPoint{A->GetHash(), 0}) == nullptr);

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

// "Above thresh": an eviction whose chunk feerate is below the cached next-block line is not
// parked -- a cheap squatter cannot take a slot -- while a near-top eviction is.
BOOST_AUTO_TEST_CASE(does_not_park_below_next_block_line)
{
    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    // Mature a second coinbase so the two txs can spend independent inputs.
    CreateAndProcessBlock({}, spk);
    CreateAndProcessBlock({}, spk);

    // A high-fee tx and a low-fee tx, in independent clusters.
    const auto hi = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 0, coinbaseKey, spk, /*output_amount=*/40 * COIN, /*submit=*/true));
    const auto lo = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[1], 0, 0, coinbaseKey, spk, /*output_amount=*/4999 * COIN / 100, /*submit=*/true));

    // A line weight that fits only the higher-feerate chunk, putting the low-fee tx below the line.
    auto ac = std::make_shared<AntiCycle>(*m_node.chainman, *m_node.mempool, /*max_park_weight=*/4'000'000,
                                          /*line_weight=*/GetTransactionWeight(*hi) * 3 / 2);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    // Evicting the BELOW-line tx must NOT park it.
    const auto lo2 = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[1], 0, 0, coinbaseKey, spk, /*output_amount=*/49 * COIN, /*submit=*/false));
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(lo2).m_result_type == MempoolAcceptResult::ResultType::VALID);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(ac->buffer().FindByInput(COutPoint{m_coinbase_txns[1]->GetHash(), 0}) == nullptr);

    // Evicting the ABOVE-line tx parks it.
    const auto hi2 = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 0, coinbaseKey, spk, /*output_amount=*/39 * COIN, /*submit=*/false));
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(hi2).m_result_type == MempoolAcceptResult::ResultType::VALID);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(ac->buffer().FindByInput(COutPoint{m_coinbase_txns[0]->GetHash(), 0}) != nullptr);

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

// B->A clear: when a top-feerate tx (re-)takes a protected outpoint of a parked victim from a free
// state, the stale victim is dropped (honest-user protection / acquisition reset). Here the victim
// V spends O and P; after V is parked, an unrelated tx retakes the now-free P, clearing V.
BOOST_AUTO_TEST_CASE(clears_parked_victim_when_outpoint_retaken)
{
    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;
    CreateAndProcessBlock({}, spk);  // mature coinbase[1] and [2]
    CreateAndProcessBlock({}, spk);
    CreateAndProcessBlock({}, spk);

    auto ac = std::make_shared<AntiCycle>(*m_node.chainman, *m_node.mempool, /*max_park_weight=*/4'000'000);
    m_node.validation_signals->RegisterSharedValidationInterface(ac);

    const COutPoint O{m_coinbase_txns[0]->GetHash(), 0};
    const COutPoint P{m_coinbase_txns[1]->GetHash(), 0};
    const COutPoint C2{m_coinbase_txns[2]->GetHash(), 0};
    const auto two_in = [&](const CTransactionRef& a, const COutPoint& ai, const CTransactionRef& b,
                            const COutPoint& bi, CAmount out) {
        return MakeTransactionRef(CreateValidTransaction({a, b}, {ai, bi}, /*input_height=*/0,
            {coinbaseKey, coinbaseKey}, {CTxOut{out, spk}}, std::nullopt, std::nullopt).first);
    };

    // Victim V spends O and P. Attacker grab G spends O + its own coin -> RBF-evicts V; V is parked,
    // keyed by both O and P.
    const auto V = two_in(m_coinbase_txns[0], O, m_coinbase_txns[1], P, 95 * COIN);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(V).m_result_type == MempoolAcceptResult::ResultType::VALID);
    const auto G = two_in(m_coinbase_txns[0], O, m_coinbase_txns[2], C2, 94 * COIN);
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(G).m_result_type == MempoolAcceptResult::ResultType::VALID);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(ac->buffer().FindByInput(O) != nullptr);
    BOOST_REQUIRE(ac->buffer().FindByInput(P) != nullptr);

    // An unrelated top tx takes the now-free P (a victim footprint outpoint): B->A -> clear V.
    const auto X = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[1], 0, 0, coinbaseKey, spk, 49 * COIN, /*submit=*/false));
    BOOST_REQUIRE(m_node.chainman->ProcessTransaction(X).m_result_type == MempoolAcceptResult::ResultType::VALID);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(ac->buffer().FindByInput(O) == nullptr);
    BOOST_CHECK(ac->buffer().FindByInput(P) == nullptr);

    m_node.validation_signals->UnregisterSharedValidationInterface(ac);
}

BOOST_AUTO_TEST_SUITE_END()

// The state-machine decision logic in isolation -- no transactions or mempool required.
BOOST_AUTO_TEST_SUITE(anticycle_transition_tests)

BOOST_AUTO_TEST_CASE(state_machine_transitions)
{
    using node::CycleAction;
    using node::OutpointTransition;

    // top -> top, different spender: a next-block victim was displaced (the cycling move) -> park.
    BOOST_CHECK(OutpointTransition(/*prev_above=*/true, /*now_above=*/true, /*spender_changed=*/true) == CycleAction::kPark);
    // top -> top, same spender: nothing changed.
    BOOST_CHECK(OutpointTransition(true, true, false) == CycleAction::kNone);
    // top -> free/low: the top spender withdrew -> reinstate.
    BOOST_CHECK(OutpointTransition(true, false, true) == CycleAction::kReinstate);
    BOOST_CHECK(OutpointTransition(true, false, false) == CycleAction::kReinstate);
    // free/low -> top: legitimately refilled -> clear the stale victim (honest-user protection).
    BOOST_CHECK(OutpointTransition(false, true, true) == CycleAction::kClear);
    BOOST_CHECK(OutpointTransition(false, true, false) == CycleAction::kClear);
    // free/low -> free/low: nothing.
    BOOST_CHECK(OutpointTransition(false, false, true) == CycleAction::kNone);
    BOOST_CHECK(OutpointTransition(false, false, false) == CycleAction::kNone);
}

BOOST_AUTO_TEST_SUITE_END()
