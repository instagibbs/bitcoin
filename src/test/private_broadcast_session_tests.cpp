// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <primitives/transaction.h>
#include <private_broadcast.h>
#include <private_broadcast_session.h>
#include <protocol.h>
#include <test/util/setup_common.h>
#include <util/time.h>

#include <optional>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

CTransactionRef MakeDummyTx(uint32_t id)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = id;
    return MakeTransactionRef(mtx);
}

CService MakeAddr(uint16_t port)
{
    in_addr ipv4{};
    ipv4.s_addr = 0xa0b0c001;
    return CService{ipv4, port};
}

struct RecordingSink final : public PrivateBroadcastSession::Sink {
    std::optional<uint256> sent_inv;
    std::optional<uint256> sent_tx_hash; // GetHash of CTransaction sent
    int pings_queued{0};
    std::optional<std::string> disconnect_reason;

    void SendInv(const uint256& txid) override { sent_inv = txid; }
    void SendTx(const CTransaction& tx) override { sent_tx_hash = tx.GetHash().ToUint256(); }
    void QueuePing() override { ++pings_queued; }
    void Disconnect(std::string_view reason) override { disconnect_reason.emplace(reason); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(private_broadcast_session_tests, BasicTestingSetup)

using State = PrivateBroadcastSession::State;

BOOST_AUTO_TEST_CASE(verack_with_no_tx_disconnects)
{
    PrivateBroadcast pb;
    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;

    BOOST_CHECK(session.state() == State::AwaitingVerack);

    session.OnVerack(sink);

    BOOST_CHECK(!sink.sent_inv.has_value());
    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(verack_with_tx_sends_inv)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(1)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;

    session.OnVerack(sink);

    BOOST_REQUIRE(sink.sent_inv.has_value());
    BOOST_CHECK(*sink.sent_inv == tx->GetHash().ToUint256());
    BOOST_CHECK(!sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::AwaitingGetData);
}

BOOST_AUTO_TEST_CASE(getdata_before_verack_disconnects)
{
    PrivateBroadcast pb;
    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;

    // No prior OnVerack -- session is in AwaitingVerack with no picked tx.
    session.OnGetData(sink, {});

    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(getdata_with_matching_inv_sends_tx_and_pings)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(2)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);
    BOOST_REQUIRE(session.state() == State::AwaitingGetData);

    std::vector<CInv> inv{CInv{MSG_TX, tx->GetHash().ToUint256()}};
    session.OnGetData(sink, inv);

    BOOST_REQUIRE(sink.sent_tx_hash.has_value());
    BOOST_CHECK(*sink.sent_tx_hash == tx->GetHash().ToUint256());
    BOOST_CHECK_EQUAL(sink.pings_queued, 1);
    BOOST_CHECK(!sink.disconnect_reason.has_value());
    // State stays AwaitingGetData so we can re-serve on repeated GETDATA.
    BOOST_CHECK(session.state() == State::AwaitingGetData);
}

BOOST_AUTO_TEST_CASE(getdata_repeated_with_matching_inv_re_serves)
{
    // Re-serving the same tx to the same peer matches normal tx relay and
    // leaks nothing the original INV did not.
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(20)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);

    std::vector<CInv> inv{CInv{MSG_TX, tx->GetHash().ToUint256()}};
    session.OnGetData(sink, inv);
    BOOST_REQUIRE(sink.sent_tx_hash.has_value());
    BOOST_CHECK_EQUAL(sink.pings_queued, 1);

    // Reset captured tx hash so the second send is observable.
    sink.sent_tx_hash.reset();
    session.OnGetData(sink, inv);

    BOOST_REQUIRE(sink.sent_tx_hash.has_value());
    BOOST_CHECK(*sink.sent_tx_hash == tx->GetHash().ToUint256());
    BOOST_CHECK_EQUAL(sink.pings_queued, 2);
    BOOST_CHECK(!sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::AwaitingGetData);
}

BOOST_AUTO_TEST_CASE(getdata_with_wrong_hash_disconnects)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(3)};
    const auto other_tx{MakeDummyTx(4)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);

    std::vector<CInv> inv{CInv{MSG_TX, other_tx->GetHash().ToUint256()}};
    session.OnGetData(sink, inv);

    BOOST_CHECK(!sink.sent_tx_hash.has_value());
    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(getdata_with_multiple_invs_disconnects)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(5)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);

    std::vector<CInv> inv{
        CInv{MSG_TX, tx->GetHash().ToUint256()},
        CInv{MSG_TX, tx->GetHash().ToUint256()},
    };
    session.OnGetData(sink, inv);

    BOOST_CHECK(!sink.sent_tx_hash.has_value());
    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(getdata_with_non_tx_inv_disconnects)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(6)};
    BOOST_CHECK(pb.Add(tx));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);

    // MSG_BLOCK instead of MSG_TX: matches the hash but wrong type.
    std::vector<CInv> inv{CInv{MSG_BLOCK, tx->GetHash().ToUint256()}};
    session.OnGetData(sink, inv);

    BOOST_CHECK(!sink.sent_tx_hash.has_value());
    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(pong_confirms_and_disconnects)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(7)};
    BOOST_CHECK(pb.Add(tx));

    const NodeId nodeid{7};
    PrivateBroadcastSession session{nodeid, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);
    session.OnGetData(sink, {CInv{MSG_TX, tx->GetHash().ToUint256()}});
    BOOST_REQUIRE(session.state() == State::AwaitingGetData);

    BOOST_CHECK(!pb.DidNodeConfirmReception(nodeid));
    session.OnPong(sink);

    BOOST_CHECK(pb.DidNodeConfirmReception(nodeid));
    BOOST_REQUIRE(sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::Done);
}

BOOST_AUTO_TEST_CASE(pong_in_wrong_state_is_noop)
{
    PrivateBroadcast pb;
    const NodeId nodeid{7};
    PrivateBroadcastSession session{nodeid, MakeAddr(1111), pb};
    RecordingSink sink;

    // OnPong fires while still AwaitingVerack -- defensive no-op.
    session.OnPong(sink);
    BOOST_CHECK(!pb.DidNodeConfirmReception(nodeid));
    BOOST_CHECK(!sink.disconnect_reason.has_value());
    BOOST_CHECK(session.state() == State::AwaitingVerack);
}

BOOST_AUTO_TEST_CASE(finalize_unconfirmed_with_pending_requests_replacement)
{
    PrivateBroadcast pb;
    const auto tx_a{MakeDummyTx(8)};
    const auto tx_b{MakeDummyTx(9)};
    BOOST_CHECK(pb.Add(tx_a));
    BOOST_CHECK(pb.Add(tx_b));

    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink); // picks one of the txs
    // No GETDATA, no PONG -- conn dies unconfirmed.

    BOOST_CHECK(session.OnFinalize());
}

BOOST_AUTO_TEST_CASE(finalize_confirmed_does_not_request_replacement)
{
    PrivateBroadcast pb;
    const auto tx{MakeDummyTx(10)};
    BOOST_CHECK(pb.Add(tx));

    const NodeId nodeid{7};
    PrivateBroadcastSession session{nodeid, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink);
    session.OnGetData(sink, {CInv{MSG_TX, tx->GetHash().ToUint256()}});
    session.OnPong(sink);
    BOOST_REQUIRE(session.state() == State::Done);

    BOOST_CHECK(!session.OnFinalize());
}

BOOST_AUTO_TEST_CASE(finalize_with_no_pending_does_not_request_replacement)
{
    PrivateBroadcast pb;
    PrivateBroadcastSession session{/*nodeid=*/7, MakeAddr(1111), pb};
    RecordingSink sink;
    session.OnVerack(sink); // queue empty -> Done

    BOOST_CHECK(!session.OnFinalize());
}

BOOST_AUTO_TEST_SUITE_END()
