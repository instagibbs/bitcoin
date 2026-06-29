// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
struct ReplacementRecorder final : public CValidationInterface {
    std::vector<MempoolReplacementInfo> events;
    void MempoolTransactionsReplaced(const MempoolReplacementInfo& info) override { events.push_back(info); }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(mempool_replacement_feed_tests, TestChain100Setup)

// An RBF replacement fires MempoolTransactionsReplaced carrying the evicted victim and the
// replacing transaction.
BOOST_AUTO_TEST_CASE(rbf_fires_replacement_feed)
{
    ReplacementRecorder recorder;
    m_node.validation_signals->RegisterValidationInterface(&recorder);

    const CScript spk = m_coinbase_txns[0]->vout[0].scriptPubKey;

    // Victim: spends the mature coinbase at a low fee.
    const CMutableTransaction victim = CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk,
        /*output_amount=*/50 * COIN - 10'000, /*submit=*/true);

    // Replacement: same input, higher fee (smaller output) -> RBF evicts the victim.
    const CMutableTransaction replacement = CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0, coinbaseKey, spk,
        /*output_amount=*/50 * COIN - 100'000, /*submit=*/false);
    const auto result = m_node.chainman->ProcessTransaction(MakeTransactionRef(replacement));
    BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    BOOST_REQUIRE_EQUAL(recorder.events.size(), 1U);
    BOOST_REQUIRE_EQUAL(recorder.events[0].replaced.size(), 1U);
    BOOST_CHECK(recorder.events[0].replaced[0].tx->GetHash() == victim.GetHash());
    // The victim was the only mempool tx, so it was in the next-block set: nonzero chunk feerate.
    BOOST_CHECK(recorder.events[0].replaced[0].mining_feerate.fee > 0);
    BOOST_CHECK(recorder.events[0].replaced[0].mining_feerate.size > 0);
    BOOST_REQUIRE_EQUAL(recorder.events[0].replacement.size(), 1U);
    BOOST_CHECK(recorder.events[0].replacement[0]->GetHash() == replacement.GetHash());

    m_node.validation_signals->UnregisterValidationInterface(&recorder);
}

BOOST_AUTO_TEST_SUITE_END()
