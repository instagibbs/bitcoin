// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <net_transport.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <policy/packages.h>
#include <policy/policy.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <compat/compat.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace privbcast;

extern std::chrono::milliseconds g_socks5_recv_timeout;
using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(privbcast_tests, BasicTestingSetup)

namespace {

CTransactionRef MakeTx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    mtx.vin[0].scriptWitness.stack.push_back({1, 2, 3});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    return MakeTransactionRef(mtx);
}

CSerializedNetMsg PeerVersion(int version = 70016, uint64_t services = NODE_NETWORK | NODE_WITNESS, bool relay = true)
{
    return NetMsg::Make(NetMsgType::VERSION, version, services, int64_t{0},
                        uint64_t{0}, CNetAddr::V1(CService{}),
                        services, CNetAddr::V1(CService{}),
                        uint64_t{42}, std::string{"/peer:1.0/"}, int{100}, relay);
}

/** Comma-joined message types, for readable comparisons. */
std::string Types(const std::vector<CSerializedNetMsg>& msgs)
{
    std::string out;
    for (const auto& m : msgs) out += (out.empty() ? "" : ",") + m.m_type;
    return out;
}

struct Harness {
    CTransactionRef tx{MakeTx()};
    FastRandomContext rng{/*fDeterministic=*/true};
    Clock::time_point t0{Clock::now()};
    Session session{tx, t0, rng};

    void Feed(const CSerializedNetMsg& msg, Clock::time_point now)
    {
        DataStream payload{msg.data};
        session.OnMessage(msg.m_type, payload, now);
    }
    void FeedRaw(const std::string& type, std::vector<uint8_t> bytes, Clock::time_point now)
    {
        DataStream payload{bytes};
        session.OnMessage(type, payload, now);
    }
    /** Run the handshake up to and including the announcement (INV handed to the transport). */
    CSerializedNetMsg Announce(Clock::time_point now)
    {
        BOOST_REQUIRE_EQUAL(Types(session.TakeOutbound()), "version");
        Feed(PeerVersion(), now);
        BOOST_REQUIRE_EQUAL(Types(session.TakeOutbound()), "wtxidrelay,verack");
        Feed(NetMsg::Make(NetMsgType::WTXIDRELAY), now);
        Feed(NetMsg::Make(NetMsgType::VERACK), now);
        auto out{session.TakeOutbound()};
        BOOST_REQUIRE_EQUAL(Types(out), "inv");
        BOOST_CHECK(!session.Announced()); // queued is not announced
        session.OnMessageHandedToTransport(NetMsgType::INV, now);
        BOOST_CHECK(session.Announced());
        return std::move(out[0]);
    }
    /** After GETDATA: the transport wrote TX and PING. */
    void Written(Clock::time_point now)
    {
        session.OnMessageHandedToTransport(NetMsgType::TX, now);
        session.OnMessageWritten(NetMsgType::TX, now);
        session.OnMessageHandedToTransport(NetMsgType::PING, now);
        session.OnMessageWritten(NetMsgType::PING, now);
    }
    CSerializedNetMsg Request() const
    {
        return NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, tx->GetWitnessHash().ToUint256()}});
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(session_happy_path)
{
    Harness h;
    // The VERSION we send is the fixed profile.
    auto out{h.session.TakeOutbound()};
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    {
        DataStream ds{out[0].data};
        int version;
        uint64_t services, addr_services;
        int64_t time;
        CService addr_recv, addr_from;
        uint64_t nonce;
        std::string user_agent;
        int height;
        bool relay;
        ds >> version >> services >> time >> addr_services >> CNetAddr::V1(addr_recv) >> addr_services >> CNetAddr::V1(addr_from) >> nonce >> user_agent >> height >> relay;
        BOOST_CHECK_EQUAL(version, 70017);
        BOOST_CHECK_EQUAL(services, uint64_t{NODE_WITNESS});
        BOOST_CHECK_EQUAL(time, 0);
        BOOST_CHECK(!addr_recv.IsValid());
        BOOST_CHECK(!addr_from.IsValid());
        BOOST_CHECK_EQUAL(user_agent, "/pynode:0.0.1/");
        BOOST_CHECK_EQUAL(height, 0);
        BOOST_CHECK(!relay);
        BOOST_CHECK(ds.empty());
    }
    h.Feed(PeerVersion(), h.t0 + 1s);
    BOOST_CHECK_EQUAL(h.session.GetEvidence().peer_version.value_or(0), 70016);
    BOOST_CHECK_EQUAL(h.session.GetEvidence().peer_user_agent, "/peer:1.0/");
    BOOST_CHECK(!h.session.Finished());
    BOOST_CHECK(!h.session.Announced());
    BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "wtxidrelay,verack");

    h.Feed(NetMsg::Make(NetMsgType::WTXIDRELAY), h.t0 + 1s);
    h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0 + 2s);
    out = h.session.TakeOutbound();
    BOOST_REQUIRE_EQUAL(Types(out), "inv");
    BOOST_CHECK(!h.session.Announced()); // not until the transport takes it
    h.session.OnMessageHandedToTransport(NetMsgType::INV, h.t0 + 2s);
    BOOST_CHECK(h.session.Announced());
    BOOST_CHECK(h.session.GetEvidence().inv_handed.has_value());
    {
        DataStream ds{out[0].data};
        std::vector<CInv> inv;
        ds >> inv;
        BOOST_REQUIRE_EQUAL(inv.size(), 1U);
        BOOST_CHECK_EQUAL(inv[0].type, MSG_WTX);
        BOOST_CHECK(inv[0].hash == h.tx->GetWitnessHash().ToUint256());
    }

    h.Feed(h.Request(), h.t0 + 3s);
    out = h.session.TakeOutbound();
    BOOST_REQUIRE_EQUAL(Types(out), "tx,ping");
    {
        DataStream ds{out[0].data};
        CMutableTransaction received;
        ds >> TX_WITH_WITNESS(received);
        BOOST_CHECK(CTransaction{received}.GetWitnessHash() == h.tx->GetWitnessHash());
        DataStream ping{out[1].data};
        uint64_t nonce;
        ping >> nonce;
        BOOST_CHECK_EQUAL(nonce, h.session.PingNonce());
    }

    h.Written(h.t0 + 3s);
    h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce() + 1), h.t0 + 4s);
    BOOST_CHECK(!h.session.Finished());
    h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), h.t0 + 5s);
    BOOST_REQUIRE(h.session.Finished());
    BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
    BOOST_CHECK(IsPostAnnouncement(h.session.GetOutcome()));
    BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 0U);
    BOOST_CHECK(h.session.GetEvidence().getdata_received.has_value());
    BOOST_CHECK(h.session.GetEvidence().pong_received.has_value());
    BOOST_CHECK(h.session.GetEvidence().tx_written.has_value());
    BOOST_CHECK(h.session.GetEvidence().ping_written.has_value());
    // A finished session sends nothing further.
    BOOST_CHECK(h.session.TakeOutbound().empty());
}

BOOST_AUTO_TEST_CASE(session_wtxid_relay_required)
{
    // Announced and served by wtxid only: the txid form of the request is not answered.
    {
        Harness h;
        h.Announce(h.t0);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, h.tx->GetHash().ToUint256()}}), h.t0 + 1s);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 1U);
        h.Feed(h.Request(), h.t0 + 1s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,ping");
    }
    // A peer that does not send WTXIDRELAY before its VERACK is left before anything is announced.
    for (const bool late : {false, true}) {
        Harness h;
        h.session.TakeOutbound();
        h.Feed(PeerVersion(), h.t0);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "wtxidrelay,verack");
        h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0);
        if (late) h.Feed(NetMsg::Make(NetMsgType::WTXIDRELAY), h.t0); // BIP339: too late to count
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "no wtxid relay");
        BOOST_CHECK(!h.session.Announced());
    }
}

BOOST_AUTO_TEST_CASE(session_serves_once_and_only_the_profile_request)
{
    Harness h;
    h.Announce(h.t0);
    const auto txid{h.tx->GetHash().ToUint256()};
    // Requests our profile does not make possible are ignored, not answered.
    h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_TX, txid}}), h.t0 + 1s);
    h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, txid}}), h.t0 + 1s);
    const CInv wtx{MSG_WTX, h.tx->GetWitnessHash().ToUint256()};
    h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{wtx, wtx}), h.t0 + 1s);
    h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, uint256{7}}}), h.t0 + 1s);
    BOOST_CHECK(h.session.TakeOutbound().empty());
    BOOST_CHECK(!h.session.Finished());
    BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 4U);

    h.Feed(h.Request(), h.t0 + 2s);
    BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,ping");
    // A second identical request gets nothing.
    h.Feed(h.Request(), h.t0 + 3s);
    BOOST_CHECK(h.session.TakeOutbound().empty());
    BOOST_CHECK(!h.session.Finished());
    BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 5U);
}

BOOST_AUTO_TEST_CASE(session_peer_admission)
{
    {
        Harness h;
        h.Feed(PeerVersion(70016, NODE_NETWORK | NODE_WITNESS, /*relay=*/false), h.t0);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "relay=false");
        BOOST_CHECK(!IsPostAnnouncement(h.session.GetOutcome()));
    }
    {
        Harness h;
        h.Feed(PeerVersion(70015), h.t0); // below BIP339 wtxid relay
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "protocol version too old");
    }
    {
        Harness h;
        h.Feed(PeerVersion(70016, NODE_NETWORK), h.t0);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "no NODE_WITNESS");
    }
    {
        Harness h;
        auto msg{PeerVersion()};
        msg.data.resize(msg.data.size() - 1); // relay field missing
        h.Feed(msg, h.t0);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "malformed version");
    }
    {
        // Version 70016, the first with wtxid relay, is the minimum.
        Harness h;
        h.Feed(PeerVersion(70016), h.t0);
        BOOST_CHECK(!h.session.Finished());
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "version,wtxidrelay,verack");
    }
}

BOOST_AUTO_TEST_CASE(session_ignores_everything_else)
{
    Harness h;
    (void)h.session.TakeOutbound();
    // Before the peer's VERSION nothing else is acted on.
    h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0);
    h.Feed(h.Request(), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::PING, uint64_t{1}), h.t0);
    h.FeedRaw("bogus", {1, 2, 3}, h.t0);
    BOOST_CHECK(h.session.TakeOutbound().empty());
    BOOST_CHECK(!h.session.Finished());
    BOOST_CHECK(!h.session.Announced());

    h.Feed(PeerVersion(), h.t0);
    (void)h.session.TakeOutbound();
    // Honest 70016 peers send these before VERACK.
    h.Feed(NetMsg::Make(NetMsgType::WTXIDRELAY), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::SENDADDRV2), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::SENDTXRCNCL, uint32_t{1}, uint64_t{5}), h.t0);
    h.Feed(PeerVersion(), h.t0); // redundant
    BOOST_CHECK(h.session.TakeOutbound().empty());
    BOOST_CHECK(!h.session.Announced());

    h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0);
    BOOST_CHECK(!h.session.Announced()); // queued is not announced
    (void)h.session.TakeOutbound();
    h.session.OnMessageHandedToTransport(NetMsgType::INV, h.t0);
    BOOST_CHECK(h.session.Announced());
    h.Feed(NetMsg::Make(NetMsgType::PING, uint64_t{1}), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, uint64_t{2}), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::FEEFILTER, int64_t{1000}), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::SENDTXRCNCL, uint32_t{1}, uint64_t{5}), h.t0);
    h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0);
    h.FeedRaw(NetMsgType::ADDR, {0xff, 0xff, 0xff}, h.t0);
    BOOST_CHECK(h.session.TakeOutbound().empty());
    BOOST_CHECK(!h.session.Finished());
    BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 0U);
}

BOOST_AUTO_TEST_CASE(session_deadlines_are_strict)
{
    {
        Harness h;
        h.session.OnTick(h.t0 + wire::HANDSHAKE_TIMEOUT - 1ms);
        BOOST_CHECK(!h.session.Finished());
        h.session.OnTick(h.t0 + wire::HANDSHAKE_TIMEOUT);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "handshake timeout");
        BOOST_CHECK(!IsPostAnnouncement(h.session.GetOutcome()));
    }
    {
        Harness h;
        const auto t1{h.t0 + 10s};
        h.Announce(t1);
        h.session.OnTick(t1 + wire::REQUEST_WINDOW - 1ms);
        BOOST_CHECK(!h.session.Finished());
        // A request arriving at the deadline is not processed.
        h.Feed(h.Request(), t1 + wire::REQUEST_WINDOW);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::ANNOUNCED_NOT_REQUESTED);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK(!h.session.GetEvidence().getdata_received.has_value());
    }
    {
        // The PONG wait counts from PING being fully written, not from the request.
        Harness h;
        const auto t1{h.t0 + 10s};
        h.Announce(t1);
        const auto t2{t1 + 5s};
        h.Feed(h.Request(), t2);
        (void)h.session.TakeOutbound();
        const auto t3{t2 + 2s};
        h.Written(t3);
        h.session.OnTick(t3 + wire::PONG_WAIT - 1ms);
        BOOST_CHECK(!h.session.Finished());
        h.session.OnTick(t3 + wire::PONG_WAIT);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::TX_WRITTEN_NO_PONG);
    }
    {
        // INV queued but never taken by the transport within the handshake budget: nothing
        // was announced, so the failure is replaceable.
        Harness h;
        (void)h.session.TakeOutbound();
        h.Feed(PeerVersion(), h.t0);
        (void)h.session.TakeOutbound();
        h.Feed(NetMsg::Make(NetMsgType::WTXIDRELAY), h.t0 + 1s);
        h.Feed(NetMsg::Make(NetMsgType::VERACK), h.t0 + 1s);
        BOOST_REQUIRE_EQUAL(Types(h.session.TakeOutbound()), "inv");
        BOOST_CHECK(!h.session.Announced());
        h.session.OnTick(h.t0 + wire::HANDSHAKE_TIMEOUT);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "inv not handed to transport");
        BOOST_CHECK(!IsPostAnnouncement(h.session.GetOutcome()));
    }
    {
        // Requested, but TX/PING never got written before the request window ended.
        Harness h;
        const auto t1{h.t0 + 10s};
        h.Announce(t1);
        h.Feed(h.Request(), t1 + 5s);
        (void)h.session.TakeOutbound();
        h.session.OnTick(t1 + wire::REQUEST_WINDOW);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
        BOOST_CHECK_EQUAL(h.session.Reason(), "tx not written in time");
    }
    {
        Harness h;
        const auto t1{h.t0 + 10s};
        h.Announce(t1);
        h.Feed(h.Request(), t1 + 5s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageWritten(NetMsgType::TX, t1 + 6s);
        h.session.OnTick(t1 + wire::REQUEST_WINDOW);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
        BOOST_CHECK_EQUAL(h.session.Reason(), "ping not written in time");
    }
}

BOOST_AUTO_TEST_CASE(session_failures_are_classified_by_announcement)
{
    {
        Harness h;
        h.session.Fail("peer closed");
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "peer closed");
    }
    {
        Harness h;
        h.session.Fail("socks connect failed");
        BOOST_CHECK(h.session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(h.session.Reason(), "socks connect failed");
        BOOST_CHECK(!IsPostAnnouncement(h.session.GetOutcome()));
    }
    {
        Harness h;
        h.Announce(h.t0);
        h.session.Fail("peer closed");
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
    }
    {
        // Malformed acted-on messages end the attempt.
        Harness h;
        h.Announce(h.t0);
        h.FeedRaw(NetMsgType::GETDATA, {0xfd, 0xff}, h.t0);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
    }
    {
        Harness h;
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0);
        // Before our PING is written no PONG is judged, malformed or not.
        h.FeedRaw(NetMsgType::PONG, {1, 2, 3, 4, 5, 6, 7}, h.t0);
        BOOST_CHECK(!h.session.Finished());
        h.Written(h.t0);
        h.FeedRaw(NetMsgType::PONG, {1, 2, 3, 4, 5, 6, 7}, h.t0);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
        BOOST_CHECK_EQUAL(h.session.Reason(), "malformed pong");
    }
}

BOOST_AUTO_TEST_SUITE_END()
