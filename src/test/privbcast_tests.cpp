// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <net_transport.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/discovery.h>
#include <core_io.h>
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <policy/packages.h>
#include <policy/policy.h>
#include <privbcast/input.h>
#include <privbcast/job.h>
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
#include <optional>
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

/** A transaction spending output 0 of `parent`: the child of a one-parent-one-child package. */
CTransactionRef MakeChildOf(const CTransactionRef& parent)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{parent->GetHash(), 0});
    mtx.vin[0].scriptWitness.stack.push_back({4, 5, 6});
    mtx.vout.emplace_back(500, CScript{} << OP_TRUE);
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
    CTransactionRef parent; //!< set for a package: `tx` is then its child
    CTransactionRef tx{MakeTx()};
    FastRandomContext rng{/*fDeterministic=*/true};
    Clock::time_point t0{Clock::now()};
    Session session{tx, t0, rng, parent};

    Harness() = default;
    /** A package: `tx` becomes a child spending the given parent. */
    explicit Harness(CTransactionRef parent_) : parent{std::move(parent_)}, tx{MakeChildOf(parent)}, session{tx, t0, rng, parent} {}

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
    CSerializedNetMsg ParentRequest() const
    {
        return NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, parent->GetHash().ToUint256()}});
    }
};


/** A job config with no proxy to reach: `onions` bundled onion candidates and nothing else. */
JobConfig OnionJobConfig(int onions)
{
    JobConfig cfg;
    cfg.tx = MakeTx();
    cfg.chain = "regtest";
    cfg.tor = Proxy{LookupNumeric("127.0.0.1", 9050), /*tor_stream_isolation=*/true};
    cfg.interrupted = [] { return false; };
    for (int i = 0; i < onions; ++i) {
        std::vector<uint8_t> pubkey(32, static_cast<uint8_t>(i + 1));
        CNetAddr addr;
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(pubkey)));
        cfg.discovery.bundled.emplace_back(addr, 8333);
    }
    return cfg;
}

/**
 * The run_job tests run a whole job on the mocked clock. Time moves only while every job thread is
 * parked in a wait, and then straight to the wait that is due next, so a test sees exactly the
 * schedule the code computes, at any host speed. A mock that has to stall waits on that clock too.
 */
class JobTestEnv
{
public:
    JobTestEnv()
    {
        g_socks5_interrupt.reset();
        mocktime::Start();
    }
    ~JobTestEnv()
    {
        mocktime::Stop();
        // A job leaves the process-wide SOCKS settings and interrupt alone: in bitcoind they
        // belong to ordinary connections.
        BOOST_CHECK_EQUAL(nConnectTimeout, m_connect_timeout);
        BOOST_CHECK(g_socks5_recv_timeout == m_socks_timeout);
        BOOST_CHECK(!g_socks5_interrupt);
    }
    /** Run the job, advancing the clock between waits; `each_step` runs after every advance. */
    JobReport Run(const JobConfig& cfg_in, const std::function<void()>& each_step = {})
    {
        std::atomic<bool> abort{false};
        JobConfig cfg{cfg_in};
        cfg.interrupted = [&, interrupted = cfg_in.interrupted] { return abort.load() || interrupted(); };
        std::optional<JobReport> report;
        std::atomic<bool> done{false};
        std::thread runner([&] {
            report.emplace(RunJob(cfg));
            done = true;
        });
        bool parked{true};
        while (!done) {
            if (!mocktime::Settle(30s, [&] { return done.load(); })) {
                parked = false;
                abort = true;
                WakeWaiters();
                break;
            }
            if (done) break;
            if (const auto next{mocktime::NextWait()}) {
                mocktime::Advance(std::max(*next, 1s));
            } else {
                // Only unbounded waits are pending (the watcher, a blocked connector): nothing on the
                // job side needs time, so none passes; the job's last timestamp stays where its
                // schedule put it. A test that wants the clock to move anyway does so in `each_step`.
                std::this_thread::sleep_for(1ms);
            }
            if (each_step) each_step();
        }
        runner.join();
        BOOST_REQUIRE_MESSAGE(parked, "job threads did not park");
        return *report;
    }
    /** Block the calling job thread (a stalling mock) until the mocked clock reaches `until`. */
    static void StallUntil(Clock::time_point until) { WaitUntil(until, [] { return false; }); }

private:
    const int m_connect_timeout{nConnectTimeout};
    const std::chrono::milliseconds m_socks_timeout{g_socks5_recv_timeout};
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

BOOST_AUTO_TEST_CASE(run_session_over_v1_transport)
{
    // The peer's side of a complete exchange, framed with a real V1 transport.
    const CTransactionRef tx{MakeTx()};
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto t0{Clock::now()};
    Session session{tx, t0, rng};
    auto pipes{std::make_shared<DynSock::Pipes>()};
    pipes->recv.PushNetMsg(NetMsgType::VERSION, 70016, uint64_t{NODE_NETWORK | NODE_WITNESS}, int64_t{0},
                           uint64_t{0}, CNetAddr::V1(CService{}), uint64_t{0}, CNetAddr::V1(CService{}),
                           uint64_t{42}, std::string{"/peer:1.0/"}, int{100}, true);
    pipes->recv.PushNetMsg(NetMsgType::WTXIDRELAY);
    pipes->recv.PushNetMsg(NetMsgType::VERACK);
    pipes->recv.PushNetMsg(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, tx->GetWitnessHash().ToUint256()}});
    pipes->recv.PushNetMsg(NetMsgType::PONG, session.PingNonce());
    AttemptResult result;
    {
        DynSock sock{pipes};
        V1Transport transport{NodeId{0}};
        RunSession(sock, transport, session, result, t0 + wire::ATTEMPT_MAX, [] { return false; });
    }
    BOOST_CHECK(session.GetOutcome() == Outcome::PONG_RECEIVED);
    BOOST_CHECK(session.GetEvidence().inv_handed.has_value());
    BOOST_CHECK(session.GetEvidence().inv_written.has_value());
    BOOST_CHECK(session.GetEvidence().tx_written.has_value());
    BOOST_CHECK(session.GetEvidence().ping_written.has_value());
    BOOST_CHECK(result.bytes_sent > 0 && result.bytes_recv > 0);
    std::string sent;
    while (const auto msg{pipes->send.GetNetMsg()}) sent += (sent.empty() ? "" : ",") + msg->m_type;
    BOOST_CHECK_EQUAL(sent, "version,wtxidrelay,verack,inv,tx,ping");
}

BOOST_AUTO_TEST_CASE(run_session_receive_cap_and_peer_close)
{
    const CTransactionRef tx{MakeTx()};
    FastRandomContext rng{/*fDeterministic=*/true};
    {
        // Enough ignorable bytes to exceed the cap before any handshake progress.
        const auto t0{Clock::now()};
        Session session{tx, t0, rng};
        auto pipes{std::make_shared<DynSock::Pipes>()};
        for (uint64_t i = 0; i < 3000; ++i) pipes->recv.PushNetMsg(NetMsgType::PING, i);
        AttemptResult result;
        {
            DynSock sock{pipes};
            V1Transport transport{NodeId{0}};
            RunSession(sock, transport, session, result, t0 + wire::ATTEMPT_MAX, [] { return false; });
        }
        BOOST_CHECK(session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(session.Reason(), "receive cap");
        BOOST_CHECK(result.bytes_recv > wire::MAX_RECV_BYTES);
    }
    {
        const auto t0{Clock::now()};
        Session session{tx, t0, rng};
        auto pipes{std::make_shared<DynSock::Pipes>()};
        pipes->recv.Eof();
        AttemptResult result;
        {
            DynSock sock{pipes};
            V1Transport transport{NodeId{0}};
            RunSession(sock, transport, session, result, t0 + wire::ATTEMPT_MAX, [] { return false; });
        }
        BOOST_CHECK(session.GetOutcome() == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(session.Reason(), "peer closed");
    }
}

BOOST_AUTO_TEST_CASE(discovery_freeze)
{
    DiscoveryPlan plan;
    plan.dns_seeds = {"a.seed.", "b.seed.", "c.seed."};
    plan.port = 8333;
    const auto ip = [](const std::string& s) { return LookupHost(s, /*fAllowLookup=*/false).value(); };
    SeedAnswers answers(3);
    // Seed a: one repeat within the seed. Seed b: a public IPv6 and one endpoint shared with a.
    // The RFC5737 and RFC3849 documentation ranges are non-routable and must be rejected.
    answers[0] = {ip("8.0.0.1"), ip("8.0.0.2"), ip("192.0.2.9"), ip("8.0.0.1")};
    answers[1] = {ip("8.0.0.1"), ip("8.0.1.1"), ip("8.0.1.2"), ip("8.0.1.3"), ip("8.0.1.4"), ip("2606:4700:4700::1111")};
    answers[2] = {};
    FastRandomContext rng{/*fDeterministic=*/true};
    const std::vector<size_t> tie_order{1, 0, 2};
    const DiscoveryResult r{Freeze(plan, answers, tie_order, rng)};
    BOOST_CHECK_EQUAL(r.seeds[1].answers, 6U);
    BOOST_CHECK_EQUAL(r.seeds[1].accepted, 6U); // a public IPv6 is a valid answer
    BOOST_CHECK_EQUAL(r.seeds[1].kept, disc::MAX_PER_SEED);
    BOOST_CHECK_EQUAL(r.seeds[0].answers, 4U);
    BOOST_CHECK_EQUAL(r.seeds[0].accepted, 1U); // only 8.0.0.2 is new: 8.0.0.1 went to seed b, 192.0.2.9 rejected, 8.0.0.1 repeated
    BOOST_CHECK_EQUAL(r.seeds[0].kept, 1U);
    BOOST_CHECK_EQUAL(r.seeds[2].kept, 0U);
    BOOST_CHECK_EQUAL(r.duplicates, 2U); // 8.0.0.1 within seed a, and 8.0.0.1 across a/b
    BOOST_CHECK_EQUAL(r.rejected, 1U);   // 192.0.2.9 (documentation range)
    BOOST_CHECK_EQUAL(r.NumExitPath(), 4U);
    for (const auto& per_seed : r.per_seed) {
        for (const auto& c : per_seed) {
            BOOST_CHECK_EQUAL(c.addr.GetPort(), 8333);
            BOOST_CHECK(c.source == Source::DNS_SEED);
        }
    }
    for (const auto& c : r.per_seed[0]) BOOST_CHECK_EQUAL(c.provenance, "a.seed.");
    BOOST_CHECK(r.tie_order == tie_order);
}

BOOST_AUTO_TEST_CASE(discovery_freeze_bundled_onions)
{
    DiscoveryPlan plan;
    plan.port = 8333;
    std::vector<CService> onions;
    for (int i = 0; i < 10; ++i) {
        // More distinct torv3 addresses (from distinct pubkeys) than are kept.
        std::vector<uint8_t> pubkey(32, static_cast<uint8_t>(i + 1));
        CNetAddr addr;
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(pubkey)));
        onions.emplace_back(addr, 8333);
    }
    plan.bundled = onions;
    plan.bundled.push_back(onions[0]);                                        // duplicate
    plan.bundled.emplace_back(LookupHost("1.2.3.4", false).value(), 8333);    // not onion
    FastRandomContext rng{/*fDeterministic=*/true};
    const DiscoveryResult r{Freeze(plan, SeedAnswers{}, std::vector<size_t>{}, rng)};
    BOOST_CHECK_EQUAL(r.onion.size(), disc::MAX_BUNDLED);
    for (const auto& c : r.onion) {
        BOOST_CHECK(c.addr.IsTor());
        BOOST_CHECK(c.source == Source::BUNDLED);
        BOOST_CHECK_EQUAL(c.provenance, "bundled");
    }
    BOOST_CHECK_EQUAL(r.NumExitPath(), 0U);
}

BOOST_AUTO_TEST_CASE(schedule_is_fixed_at_start)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto t0{Clock::now()};
    bool late_pair_at_minimum_gap{false};
    for (int i = 0; i < 200; ++i) {
        const Schedule s{Schedule::Draw(t0, rng)};
        BOOST_CHECK(s.DeliveryStart() == t0 + disc::WINDOW);
        std::vector<std::chrono::seconds> late;
        for (uint32_t slot = 0; slot < plan::SLOTS; ++slot) {
            const auto p{s.primary[slot]};
            switch (StratumOfSlot(slot)) {
            case Stratum::PROMPT: BOOST_CHECK(p == 0s); break;
            case Stratum::MID: BOOST_CHECK(p >= plan::MID_MIN && p <= plan::MID_MAX); break;
            case Stratum::LATE:
                BOOST_CHECK(p >= plan::LATE_MIN && p <= plan::LATE_MAX);
                late.push_back(p);
                break;
            }
            BOOST_CHECK(s.OpportunityStart(slot, 0) == s.DeliveryStart() + p);
            for (uint32_t k = 1; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
                const auto b{s.backup[slot][k - 1]};
                BOOST_CHECK(b >= plan::BACKUP_MIN && b <= plan::BACKUP_MAX);
                BOOST_CHECK(s.OpportunityStart(slot, k) == s.OpportunityStart(slot, k - 1) + b);
                // A backup never opens before the previous opportunity's pre-announcement outcome is known.
                BOOST_CHECK(s.OpportunityStart(slot, k) >= s.OpportunityStart(slot, k - 1) + wire::HANDSHAKE_TIMEOUT + plan::START_GRACE);
            }
            for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
                BOOST_CHECK(s.AttemptDeadline(slot, k) == s.OpportunityStart(slot, k) + wire::ATTEMPT_MAX);
            }
            BOOST_CHECK(s.SlotEnd(slot) <= s.OpportunityStart(slot, 0) + plan::SLOT_MAX);
            BOOST_CHECK(s.SlotEnd(slot) <= t0 + plan::SCHEDULED_BOUND);
        }
        BOOST_REQUIRE_EQUAL(late.size(), 2U);
        std::sort(late.begin(), late.end());
        BOOST_CHECK(late[1] - late[0] >= plan::PRIMARY_SEPARATION);
        if (late[1] - late[0] == plan::PRIMARY_SEPARATION) late_pair_at_minimum_gap = true;
    }
    BOOST_CHECK(late_pair_at_minimum_gap); // the minimum gap does occur, drawn or repaired; the repair itself is tested below
}

BOOST_AUTO_TEST_CASE(schedule_layout_and_separation)
{
    // The slot layout is the approved one, pinned independently of the table.
    const std::vector<SlotClass> classes{SlotClass::EXIT_PATH, SlotClass::EXIT_PATH, SlotClass::ONION,
                                         SlotClass::ONION, SlotClass::EXIT_PATH, SlotClass::EXIT_PATH};
    const std::vector<Stratum> strata{Stratum::PROMPT, Stratum::PROMPT, Stratum::PROMPT, Stratum::MID, Stratum::LATE, Stratum::LATE};
    BOOST_REQUIRE_EQUAL(plan::SLOTS, 6U);
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        BOOST_CHECK(ClassOfSlot(s) == classes[s]);
        BOOST_CHECK(StratumOfSlot(s) == strata[s]);
    }
    BOOST_CHECK_EQUAL(plan::ONION_SLOTS, 2U);
    // The schedule is a function of the seed alone.
    FastRandomContext rng_a{/*fDeterministic=*/true}, rng_b{/*fDeterministic=*/true};
    const auto t0{Clock::now()};
    for (int i = 0; i < 20; ++i) {
        const Schedule a{Schedule::Draw(t0, rng_a)}, b{Schedule::Draw(t0, rng_b)};
        BOOST_CHECK(a.primary == b.primary);
        BOOST_CHECK(a.backup == b.backup);
    }
    // Separation: already apart is untouched, order is normalised, a collision moves the later
    // draw forward, and at the top of the window it moves the earlier draw back instead.
    using std::chrono::seconds;
    const seconds gap{plan::PRIMARY_SEPARATION}, hi{plan::LATE_MAX};
    BOOST_CHECK(SeparateDraws(seconds{190}, seconds{200}, gap, hi) == std::make_pair(seconds{190}, seconds{200}));
    BOOST_CHECK(SeparateDraws(seconds{200}, seconds{190}, gap, hi) == std::make_pair(seconds{190}, seconds{200}));
    BOOST_CHECK(SeparateDraws(seconds{200}, seconds{201}, gap, hi) == std::make_pair(seconds{200}, seconds{205}));
    BOOST_CHECK(SeparateDraws(seconds{238}, seconds{239}, gap, hi) == std::make_pair(seconds{234}, seconds{239}));
    BOOST_CHECK(SeparateDraws(seconds{240}, seconds{240}, gap, hi) == std::make_pair(seconds{235}, seconds{240}));
}

BOOST_AUTO_TEST_CASE(assignment_spreads_seeds_and_reserves_onions)
{
    const auto ip = [](const std::string& s) { return CService{LookupHost(s, false).value(), 8333}; };
    DiscoveryResult d;
    const size_t n{7};
    d.per_seed.resize(n);
    for (size_t i = 0; i < n; ++i) {
        d.tie_order.push_back(i);
        for (size_t j = 0; j < disc::MAX_PER_SEED; ++j) {
            d.per_seed[i].push_back(Candidate{ip(strprintf("%d.%d.0.1", 10 + i, j)), Source::DNS_SEED, strprintf("seed%d", i)});
        }
    }
    for (uint32_t i = 0; i < plan::ONION_SLOTS * plan::OPPORTUNITIES_PER_SLOT; ++i) {
        std::vector<uint8_t> pubkey(32, static_cast<uint8_t>(i + 1));
        CNetAddr addr;
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(pubkey)));
        d.onion.push_back(Candidate{CService{addr, 8333}, Source::BUNDLED, "bundled"});
    }
    const Assignment a{AssignCandidates(d)};
    std::set<std::string> endpoints;
    std::map<std::string, int> per_seed_use;
    std::set<std::string> exit_primary_seeds;
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        std::set<std::string> seeds_in_slot;
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
            BOOST_REQUIRE(a[s][k].has_value());
            const Candidate& c{*a[s][k]};
            BOOST_CHECK(endpoints.insert(c.addr.ToStringAddrPort()).second); // never reused
            if (ClassOfSlot(s) == SlotClass::ONION) {
                BOOST_CHECK(c.source == Source::BUNDLED);
            } else {
                BOOST_CHECK(c.source == Source::DNS_SEED);
                ++per_seed_use[c.provenance];
                BOOST_CHECK(seeds_in_slot.insert(c.provenance).second); // a different seed at every opportunity
                if (k == 0) BOOST_CHECK(exit_primary_seeds.insert(c.provenance).second); // primaries from different seeds
            }
        }
    }
    for (const auto& [seed, uses] : per_seed_use) BOOST_CHECK(uses <= static_cast<int>(disc::MAX_PER_SEED));

    std::vector<uint32_t> exit_slots, onion_slots;
    for (uint32_t s = 0; s < plan::SLOTS; ++s) (ClassOfSlot(s) == SlotClass::ONION ? onion_slots : exit_slots).push_back(s);
    BOOST_REQUIRE_EQUAL(exit_slots.size(), plan::SLOTS - plan::ONION_SLOTS);

    // Exactly as many productive seeds as exit-path slots: a naive round-robin would hand each
    // slot the same seed at every opportunity; the per-slot avoidance must still spread them.
    // Four seeds of three candidates fill three opportunities per slot; the rest stay empty.
    {
        DiscoveryResult four{d};
        four.per_seed.resize(exit_slots.size());
        four.tie_order.clear();
        for (size_t i = 0; i < exit_slots.size(); ++i) four.tie_order.push_back(i);
        const Assignment b4{AssignCandidates(four)};
        for (const uint32_t s : exit_slots) {
            std::set<std::string> seeds_in_slot;
            for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
                if (k >= disc::MAX_PER_SEED) {
                    BOOST_CHECK(!b4[s][k].has_value());
                    continue;
                }
                BOOST_REQUIRE(b4[s][k].has_value());
                BOOST_CHECK(seeds_in_slot.insert(b4[s][k]->provenance).second);
            }
        }
    }
    // A single productive seed with three candidates: primaries come first across all slots, so
    // three exit-path slots get a primary, the last one stays empty, and nobody gets a backup.
    {
        DiscoveryResult one{d};
        one.per_seed.resize(1);
        one.tie_order = {0};
        const Assignment b1{AssignCandidates(one)};
        for (size_t i = 0; i < exit_slots.size(); ++i) BOOST_CHECK_EQUAL(b1[exit_slots[i]][0].has_value(), i + 1 < exit_slots.size());
        for (const uint32_t s : exit_slots) {
            for (uint32_t k = 1; k < plan::OPPORTUNITIES_PER_SLOT; ++k) BOOST_CHECK(!b1[s][k].has_value());
        }
    }
    // A single seed with enough candidates has to repeat itself rather than leave slots empty.
    {
        DiscoveryResult one{d};
        one.per_seed.resize(1);
        one.tie_order = {0};
        for (int i = 0; one.per_seed[0].size() < exit_slots.size() * plan::OPPORTUNITIES_PER_SLOT; ++i) {
            one.per_seed[0].push_back(Candidate{CService{LookupNumeric(strprintf("203.0.113.%d", 100 + i), 8333)}, Source::DNS_SEED, one.per_seed[0][0].provenance});
        }
        const Assignment b1{AssignCandidates(one)};
        for (const uint32_t s : exit_slots) {
            for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
                BOOST_CHECK(b1[s][k].has_value() && b1[s][k]->provenance == one.per_seed[0][0].provenance);
            }
        }
    }

    // Without onions the onion slots fall back to exit-path candidates; without exit-path
    // candidates the exit-path slots stay empty rather than taking onions.
    DiscoveryResult no_onion{d};
    no_onion.onion.clear();
    const Assignment b{AssignCandidates(no_onion)};
    BOOST_CHECK(b[onion_slots[0]][0].has_value() && b[onion_slots[0]][0]->source == Source::DNS_SEED);
    DiscoveryResult only_onion{d};
    for (auto& v : only_onion.per_seed) v.clear();
    const Assignment c{AssignCandidates(only_onion)};
    for (const uint32_t s : onion_slots) BOOST_CHECK(c[s][0].has_value() && c[s][0]->source == Source::BUNDLED);
    for (const uint32_t s : exit_slots) {
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) BOOST_CHECK(!c[s][k].has_value());
    }
}

BOOST_AUTO_TEST_CASE(input_parse_tor_is_loopback_only)
{
    std::string error;
    for (const auto& ok : {"127.0.0.1:9050", "127.0.0.1", "127.255.0.7:1", "[::1]:9150"}) {
        BOOST_CHECK_MESSAGE(ParseTor(ok, error).has_value(), ok);
    }
    for (const auto& bad : {"0.0.0.0:9050", "10.0.0.1:9050", "8.8.8.8:9050", "[::2]:9050", "[fe80::1]:9050", "localhost:9050", "not an address", ""}) {
        BOOST_CHECK_MESSAGE(!ParseTor(bad, error).has_value(), bad);
    }
#ifdef HAVE_SOCKADDR_UN
    const auto unix_sock{ParseTor("unix:/tmp/tor.sock", error)};
    BOOST_REQUIRE(unix_sock.has_value());
    BOOST_CHECK(unix_sock->m_is_unix_socket);
    BOOST_CHECK(unix_sock->m_tor_stream_isolation);
#endif
}

BOOST_AUTO_TEST_CASE(input_read_bounded)
{
    std::string out, error;
    {
        std::istringstream in{"  deadbeef\n"};
        BOOST_REQUIRE(ReadBounded(in, 100, out, error));
        BOOST_CHECK_EQUAL(out, "deadbeef");
    }
    {
        std::istringstream in{"   \n\t"};
        BOOST_CHECK(!ReadBounded(in, 100, out, error));
        BOOST_CHECK_EQUAL(error, "no transaction on stdin");
    }
    {
        std::istringstream in{std::string(101, 'a')};
        BOOST_CHECK(!ReadBounded(in, 100, out, error));
        BOOST_CHECK_EQUAL(error, "stdin too large");
    }
    {
        std::istringstream in{std::string(100, 'a')};
        BOOST_CHECK(ReadBounded(in, 100, out, error));
        BOOST_CHECK_EQUAL(out.size(), 100U);
    }
}

BOOST_AUTO_TEST_CASE(input_parse_and_check_transaction)
{
    std::string error;
    const CTransactionRef tx{MakeTx()};
    DataStream ds;
    ds << TX_WITH_WITNESS(*tx);
    const std::string hex{HexStr(ds)};
    BOOST_REQUIRE(ParseAndCheckTransaction(hex, 0, error).has_value());
    BOOST_CHECK(!ParseAndCheckTransaction("zz", 0, error).has_value());
    BOOST_CHECK_EQUAL(error, "transaction decode failed");

    CMutableTransaction coinbase{*tx};
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << OP_0 << OP_0; // satisfies bad-cb-length
    DataStream cb;
    cb << TX_WITH_WITNESS(CTransaction{coinbase});
    BOOST_CHECK(!ParseAndCheckTransaction(HexStr(cb), 0, error).has_value());
    BOOST_CHECK_EQUAL(error, "transaction is a coinbase");

    CMutableTransaction burn{*tx};
    burn.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(20, 0x42);
    burn.vout[0].nValue = 1000;
    DataStream b;
    b << TX_WITH_WITNESS(CTransaction{burn});
    BOOST_CHECK(!ParseAndCheckTransaction(HexStr(b), 999, error).has_value());
    BOOST_CHECK(ParseAndCheckTransaction(HexStr(b), 1000, error).has_value());

    CMutableTransaction heavy{*tx};
    heavy.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(100'001, 0x42);
    heavy.vout[0].nValue = 0;
    DataStream hv;
    hv << TX_WITH_WITNESS(CTransaction{heavy});
    BOOST_CHECK(!ParseAndCheckTransaction(HexStr(hv), 0, error).has_value());
    BOOST_CHECK_EQUAL(error, "transaction weight exceeds the standard maximum");
}

BOOST_AUTO_TEST_CASE(input_decode_fixed_seeds)
{
    std::vector<CService> seeds;
    seeds.emplace_back(LookupHost("1.2.3.4", false).value(), 8333);
    std::vector<uint8_t> pubkey(32, 0x07);
    CNetAddr onion;
    BOOST_REQUIRE(onion.SetSpecial(OnionToString(pubkey)));
    seeds.emplace_back(onion, 8333);
    DataStream ds;
    ParamsStream ps{ds, CAddress::V2_NETWORK};
    for (const auto& s : seeds) ps << s;
    const auto span{MakeUCharSpan(ds)};
    const std::vector<uint8_t> bytes(span.begin(), span.end());
    const auto decoded{DecodeFixedSeeds(bytes)};
    BOOST_REQUIRE_EQUAL(decoded.size(), 2U);
    BOOST_CHECK(decoded[0] == seeds[0]);
    BOOST_CHECK(decoded[1] == seeds[1]);
    // A truncated list yields what could be decoded.
    const auto partial{DecodeFixedSeeds(std::span<const uint8_t>{bytes}.first(bytes.size() - 3))};
    BOOST_CHECK_EQUAL(partial.size(), 1U);
    BOOST_CHECK(DecodeFixedSeeds({}).empty());
}

BOOST_AUTO_TEST_CASE(run_attempt_decisions)
{
    const CTransactionRef tx{MakeTx()};
    const auto never = [] { return false; };
    Candidate onion{CService{}, Source::BUNDLED, "bundled"};
    {
        std::vector<uint8_t> pubkey(32, 0x09);
        CNetAddr addr;
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(pubkey)));
        onion.addr = CService{addr, 8333};
    }
    const Candidate exit_path{CService{LookupHost("8.0.0.1", false).value(), 8333}, Source::DNS_SEED, "a.seed."};

    // Reaching the opportunity after its grace, or once the job is cancelled: nothing is dialled.
    {
        bool connected{false};
        const Connector connect = [&](bool&) -> std::unique_ptr<Sock> { connected = true; return nullptr; };
        const auto start{Clock::now() - 10s};
        BOOST_CHECK(!RunAttempt(connect, exit_path, tx, start, start + plan::START_GRACE, start + wire::ATTEMPT_MAX, never).has_value());
        BOOST_CHECK(!connected);
        const auto cancelled = [] { return true; };
        const auto now{Clock::now()};
        BOOST_CHECK(!RunAttempt(connect, exit_path, tx, now, now + plan::START_GRACE, now + wire::ATTEMPT_MAX, cancelled).has_value());
        BOOST_CHECK(!connected);
    }
    // Proxy unreachable versus SOCKS failure.
    {
        const Connector proxy_down = [](bool& failed) -> std::unique_ptr<Sock> { failed = true; return nullptr; };
        const auto res{RunAttempt(proxy_down, exit_path, tx, Clock::now(), Clock::now() + 10s, Clock::now() + 10s, never).value()};
        BOOST_CHECK(res.outcome == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(res.reason, "proxy unreachable");
        const Connector socks_fail = [](bool&) -> std::unique_ptr<Sock> { return nullptr; };
        const auto res2{RunAttempt(socks_fail, exit_path, tx, Clock::now(), Clock::now() + 10s, Clock::now() + 10s, never).value()};
        BOOST_CHECK(res2.outcome == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(res2.reason, "socks connect failed");
    }
    // A peer that closes the attempt without sending a byte (a v1-only peer facing the v2 handshake)
    // is a transport failure for every class of endpoint: there is no v1 retry, the slot's next
    // pre-assigned peer is tried instead.
    const auto closed_peer = [](bool&) -> std::unique_ptr<Sock> {
        auto pipes{std::make_shared<DynSock::Pipes>()};
        pipes->recv.Eof();
        return std::make_unique<DynSock>(pipes);
    };
    {
        const auto res{RunAttempt(closed_peer, onion, tx, Clock::now(), Clock::now() + 10s, Clock::now() + 10s, never).value()};
        BOOST_CHECK(res.outcome == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK(res.bytes_sent >= 24U); // the v2 key went out first
    }
    {
        const auto res{RunAttempt(closed_peer, exit_path, tx, Clock::now(), Clock::now() + 10s, Clock::now() + 10s, never).value()};
        BOOST_CHECK(res.outcome == Outcome::NOT_ANNOUNCED);
        BOOST_CHECK_EQUAL(res.reason, "peer closed");
    }
}

BOOST_AUTO_TEST_CASE(session_package_child_then_parent)
{
    // The peer asks for the child, then for the parent within the hold: each served once, PING after the parent.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        BOOST_CHECK(!h.session.HoldEnd());
        h.Feed(h.Request(), h.t0 + 1s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx"); // no PING yet: the hold is for the parent request
        BOOST_CHECK(!h.session.HoldEnd()); // the hold starts once the child has been written
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 1s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        BOOST_REQUIRE(h.session.HoldEnd());
        BOOST_CHECK(*h.session.HoldEnd() == h.t0 + 2s + wire::PARENT_HOLD);
        BOOST_CHECK(h.session.GetEvidence().tx_written == h.t0 + 2s);
        h.Feed(h.ParentRequest(), h.t0 + 5s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,ping");
        BOOST_CHECK(h.session.GetEvidence().parent_requested == h.t0 + 5s);
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 5s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 6s);
        BOOST_CHECK(h.session.GetEvidence().parent_written == h.t0 + 6s);
        h.session.OnMessageHandedToTransport(NetMsgType::PING, h.t0 + 6s);
        h.session.OnMessageWritten(NetMsgType::PING, h.t0 + 6s);
        // Further requests for either transaction are counted, never served again.
        h.Feed(h.ParentRequest(), h.t0 + 7s);
        h.Feed(h.Request(), h.t0 + 7s);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 2U);
        h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), h.t0 + 8s);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
    }
    // No request for the parent within the hold: PING at the hold's end, a late request not served, then PONG.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 1s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        const auto hold_end{h.t0 + 2s + wire::PARENT_HOLD};
        BOOST_CHECK(*h.session.HoldEnd() == hold_end);
        h.session.OnTick(hold_end - 1ms);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        h.session.OnTick(hold_end);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "ping");
        BOOST_CHECK(h.session.GetEvidence().hold_expired == hold_end);
        BOOST_CHECK(h.session.Deadline() == h.t0 + wire::REQUEST_WINDOW); // a prompt hold end never moves the window
        h.session.OnMessageHandedToTransport(NetMsgType::PING, hold_end);
        h.session.OnMessageWritten(NetMsgType::PING, hold_end);
        h.Feed(h.ParentRequest(), hold_end + 1s); // in TX_SENT now: counted, never served
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 1U);
        BOOST_CHECK(!h.session.GetEvidence().parent_requested);
        h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), hold_end + 2s);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
    }
    // A late child: the capped hold is already over when the child is written, so the next tick sends
    // the PING and gives it PONG_WAIT past the window's end; the attempt no longer fails with it unsent.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        const auto window_end{h.session.Deadline()};
        h.Feed(h.Request(), window_end - 2s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageHandedToTransport(NetMsgType::TX, window_end - 2s);
        h.session.OnMessageWritten(NetMsgType::TX, window_end - 1s);
        BOOST_CHECK(*h.session.HoldEnd() == window_end - wire::PONG_WAIT); // capped, already in the past
        BOOST_CHECK(h.session.TakeOutbound().empty()); // the write's own tick ran before the hold was set
        h.session.OnTick(window_end - 1s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "ping");
        BOOST_CHECK(h.session.GetEvidence().hold_expired == window_end - 1s);
        BOOST_CHECK(h.session.Deadline() == window_end - 1s + wire::PONG_WAIT);
        h.session.OnMessageHandedToTransport(NetMsgType::PING, window_end - 1s);
        h.session.OnMessageWritten(NetMsgType::PING, window_end);
        h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), window_end + 1s);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
    }
    // Ticks landing at and past the window's end after a late child: the PING queued by the first tick
    // survives the runner's repeated deadline checks until it is written.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        const auto window_end{h.session.Deadline()};
        h.Feed(h.Request(), window_end - 2s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageWritten(NetMsgType::TX, window_end - 1s);
        h.session.OnTick(window_end); // fires the hold and queues the PING
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "ping");
        h.session.OnTick(window_end);      // the runner's next tick
        h.session.OnTick(window_end + 1s); // and a later one, still before the PING is written
        BOOST_CHECK(!h.session.Finished());
        h.session.OnMessageHandedToTransport(NetMsgType::PING, window_end + 1s);
        h.session.OnMessageWritten(NetMsgType::PING, window_end + 2s);
        h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), window_end + 3s);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
        // The pending PING is bounded: unwritten for PONG_WAIT after the hold fired, the attempt fails.
        Harness g{MakeTx()};
        g.Announce(g.t0);
        const auto end{g.session.Deadline()};
        g.Feed(g.Request(), end - 2s);
        (void)g.session.TakeOutbound();
        g.session.OnMessageWritten(NetMsgType::TX, end - 1s);
        g.session.OnTick(end);
        g.session.OnTick(end + wire::PONG_WAIT);
        BOOST_CHECK(g.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
        BOOST_CHECK_EQUAL(g.session.Reason(), "ping not written in time");
    }
    // A child that is never written fails at the window's end, as a single transaction would.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        h.session.OnTick(h.session.Deadline());
        BOOST_CHECK(h.session.GetOutcome() == Outcome::POST_ANNOUNCEMENT_FAILURE);
        BOOST_CHECK_EQUAL(h.session.Reason(), "tx not written in time");
    }
    // Without a parent nothing changes: TX and PING together, no hold.
    {
        Harness h;
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,ping");
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 1s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        BOOST_CHECK(!h.session.HoldEnd());
    }
}

BOOST_AUTO_TEST_CASE(session_package_parent_only)
{
    // A recipient that already holds the child as an orphan (learned from another peer) adds us as an
    // announcer on our wtxid INV and asks only for the parent: served once, then PING.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.ParentRequest(), h.t0 + 4s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,ping");
        BOOST_CHECK(h.session.GetEvidence().parent_requested == h.t0 + 4s);
        BOOST_CHECK(!h.session.GetEvidence().getdata_received);
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 4s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 5s);
        // The one TX written is the parent, not the child.
        BOOST_CHECK(h.session.GetEvidence().parent_written == h.t0 + 5s);
        BOOST_CHECK(!h.session.GetEvidence().tx_written);
        BOOST_CHECK(!h.session.HoldEnd());
        h.session.OnMessageHandedToTransport(NetMsgType::PING, h.t0 + 5s);
        h.session.OnMessageWritten(NetMsgType::PING, h.t0 + 5s);
        // The child is not sent afterwards: the peer has it. Repeats are counted, never served.
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, h.tx->GetWitnessHash().ToUint256()}}), h.t0 + 6s);
        h.Feed(h.ParentRequest(), h.t0 + 6s);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 2U);
        h.Feed(NetMsg::Make(NetMsgType::PONG, h.session.PingNonce()), h.t0 + 7s);
        BOOST_CHECK(h.session.GetOutcome() == Outcome::PONG_RECEIVED);
    }
    // Batched with an unrelated input, as orphan resolution may ask: the parent, then NOTFOUND for the rest.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, h.parent->GetHash().ToUint256()},
                                                                  CInv{MSG_WITNESS_TX, uint256{7}}}), h.t0 + 4s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx,notfound,ping");
    }
    // A request that does not ask for the parent is not answered at all before the child is requested.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, uint256{7}}}), h.t0 + 4s);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 1U);
    }
    // The parent batched with the child before the child was served, in either order or by the
    // child's txid: a peer we have not served cannot have learned the child's inputs from us, so
    // nothing is answered. The profile request still serves the child afterwards.
    for (const bool child_by_wtxid : {true, false}) {
        for (const bool parent_first : {false, true}) {
            Harness h{MakeTx()};
            h.Announce(h.t0);
            const CInv child{child_by_wtxid ? CInv{MSG_WTX, h.tx->GetWitnessHash().ToUint256()} : CInv{MSG_WITNESS_TX, h.tx->GetHash().ToUint256()}};
            const CInv parent{MSG_WITNESS_TX, h.parent->GetHash().ToUint256()};
            const std::vector<CInv> inv{parent_first ? std::vector<CInv>{parent, child} : std::vector<CInv>{child, parent}};
            h.Feed(NetMsg::Make(NetMsgType::GETDATA, inv), h.t0 + 4s);
            BOOST_CHECK(h.session.TakeOutbound().empty());
            BOOST_CHECK(!h.session.GetEvidence().parent_requested);
            BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 1U);
            h.Feed(h.Request(), h.t0 + 5s);
            BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "tx");
        }
    }
}

BOOST_AUTO_TEST_CASE(session_package_parent_request_batched)
{
    const uint256 junk1{uint256{101}};
    const uint256 junk2{uint256{102}};
    // The peer batches our parent with unrelated inputs: serve the parent once, NOTFOUND the rest, then PING.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageHandedToTransport(NetMsgType::TX, h.t0 + 1s);
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        // Our child by wtxid and a block request are in the batch too: neither is served nor NOTFOUND.
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{
                   CInv{MSG_WITNESS_TX, junk1}, CInv{MSG_WITNESS_TX, h.parent->GetHash().ToUint256()}, CInv{MSG_WTX, h.tx->GetWitnessHash().ToUint256()},
                   CInv{MSG_WITNESS_TX, junk2}, CInv{MSG_BLOCK, junk1}}),
               h.t0 + 3s);
        auto out{h.session.TakeOutbound()};
        BOOST_CHECK_EQUAL(Types(out), "tx,notfound,ping");
        std::vector<CInv> nf;
        DataStream{out[1].data} >> nf;
        BOOST_REQUIRE_EQUAL(nf.size(), 2U); // exactly the two unrelated entries, in order
        BOOST_CHECK(nf[0].type == MSG_WITNESS_TX && nf[0].hash == junk1);
        BOOST_CHECK(nf[1].type == MSG_WITNESS_TX && nf[1].hash == junk2);
        BOOST_CHECK(h.session.GetEvidence().parent_requested == h.t0 + 3s);
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 0U);
    }
    // A request with none of our transactions: NOTFOUND everything, serve nothing, keep waiting.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, junk1}, CInv{MSG_WITNESS_TX, junk2}}), h.t0 + 3s);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "notfound");
        BOOST_CHECK(!h.session.GetEvidence().parent_requested);
        // The hold still ends the wait with a PING; nothing was mis-served.
        h.session.OnTick(h.t0 + 2s + wire::PARENT_HOLD);
        BOOST_CHECK_EQUAL(Types(h.session.TakeOutbound()), "ping");
    }
    // A repeat request for the child, or the parent by the wrong type: our own transactions, never NOTFOUND, never re-served.
    {
        Harness h{MakeTx()};
        h.Announce(h.t0);
        h.Feed(h.Request(), h.t0 + 1s);
        (void)h.session.TakeOutbound();
        h.session.OnMessageWritten(NetMsgType::TX, h.t0 + 2s);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WITNESS_TX, h.tx->GetHash().ToUint256()}}), h.t0 + 3s);
        h.Feed(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_TX, h.parent->GetHash().ToUint256()}}), h.t0 + 3s);
        BOOST_CHECK(h.session.TakeOutbound().empty());
        BOOST_CHECK_EQUAL(h.session.GetEvidence().extra_requests, 2U);
        BOOST_CHECK(!h.session.GetEvidence().parent_requested);
    }
}

BOOST_AUTO_TEST_CASE(input_package_ordering)
{
    std::string error;
    const CTransactionRef parent{MakeTx()};
    const CTransactionRef child{MakeChildOf(parent)};
    const std::string parent_hex{EncodeHexTx(*parent)};
    const std::string child_hex{EncodeHexTx(*child)};
    // One transaction: no parent.
    {
        const auto pkg{ParseAndCheckPackage(parent_hex, 0, error)};
        BOOST_REQUIRE(pkg);
        BOOST_CHECK(pkg->tx->GetHash() == parent->GetHash());
        BOOST_CHECK(!pkg->parent);
    }
    // Two, in either order and with any whitespace: ordered by who spends whom.
    for (const std::string& text : {parent_hex + "\n" + child_hex, child_hex + " \t " + parent_hex + "\n"}) {
        const auto pkg{ParseAndCheckPackage(text, 0, error)};
        BOOST_REQUIRE_MESSAGE(pkg, error);
        BOOST_CHECK(pkg->tx->GetHash() == child->GetHash());
        BOOST_REQUIRE(pkg->parent);
        BOOST_CHECK(pkg->parent->GetHash() == parent->GetHash());
    }
    // Refused: an unrelated pair, the same transaction twice, three transactions, a bad blob, nothing.
    const CTransactionRef other{MakeChildOf(MakeChildOf(parent))}; // a grandchild: neither spends the other
    BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " " + EncodeHexTx(*other), 0, error));
    BOOST_CHECK_EQUAL(error, "the two transactions are not a parent and its child");
    BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " " + parent_hex, 0, error));
    BOOST_CHECK_EQUAL(error, "the same transaction was given twice");
    BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " " + child_hex + " " + EncodeHexTx(*other), 0, error));
    BOOST_CHECK_EQUAL(error, "more than two transactions on stdin; give one, or a parent and its child");
    BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " zz", 0, error));
    BOOST_CHECK_EQUAL(error, "transaction decode failed");
    BOOST_CHECK(!ParseAndCheckPackage("   ", 0, error));
    BOOST_CHECK_EQUAL(error, "no transaction on stdin");
    // The child must spend outputs the parent actually has.
    {
        CMutableTransaction bad;
        bad.vin.emplace_back(COutPoint{parent->GetHash(), 5}); // parent has a single output
        bad.vin[0].scriptWitness.stack.push_back({7});
        bad.vout.emplace_back(400, CScript{} << OP_TRUE);
        BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " " + EncodeHexTx(CTransaction{bad}), 0, error));
        BOOST_CHECK_EQUAL(error, "the child spends an output the parent does not have");
    }
    // The two must not spend the same coin.
    {
        CMutableTransaction conflict;
        conflict.vin.emplace_back(COutPoint{parent->GetHash(), 0});
        conflict.vin.emplace_back(parent->vin[0].prevout); // the parent's own input
        conflict.vout.emplace_back(300, CScript{} << OP_TRUE);
        BOOST_CHECK(!ParseAndCheckPackage(parent_hex + " " + EncodeHexTx(CTransaction{conflict}), 0, error));
        BOOST_CHECK_EQUAL(error, "the two transactions spend the same output");
    }
    // The child must not spend an unspendable output of the parent.
    {
        CMutableTransaction burn{*parent};
        burn.vout.emplace_back(0, CScript{} << OP_RETURN);
        const CTransactionRef burn_parent{MakeTransactionRef(burn)};
        CMutableTransaction spend;
        spend.vin.emplace_back(COutPoint{burn_parent->GetHash(), 1});
        spend.vout.emplace_back(300, CScript{} << OP_TRUE);
        BOOST_CHECK(!ParseAndCheckPackage(EncodeHexTx(*burn_parent) + " " + EncodeHexTx(CTransaction{spend}), 0, error));
        BOOST_CHECK_EQUAL(error, "the child spends an unspendable output of the parent");
    }
    // Each transaction standard on its own, together over the package weight limit.
    {
        CMutableTransaction big;
        big.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{9}), 0});
        big.vout.emplace_back(1000, CScript{} << OP_TRUE);
        const std::vector<unsigned char> nops(99'900, OP_NOP);
        big.vout.emplace_back(0, CScript(nops.begin(), nops.end())); // zero value: no burn to account for
        const CTransactionRef big_parent{MakeTransactionRef(big)};
        BOOST_CHECK(GetTransactionWeight(*big_parent) <= MAX_STANDARD_TX_WEIGHT);
        CMutableTransaction kid;
        kid.vin.emplace_back(COutPoint{big_parent->GetHash(), 0});
        const std::vector<unsigned char> pad(1200, OP_NOP);
        kid.vout.emplace_back(500, CScript(pad.begin(), pad.end()));
        const CTransactionRef big_child{MakeTransactionRef(kid)};
        BOOST_CHECK(GetTransactionWeight(*big_parent) + GetTransactionWeight(*big_child) > int64_t{MAX_PACKAGE_WEIGHT});
        BOOST_CHECK(!ParseAndCheckPackage(EncodeHexTx(*big_parent) + " " + EncodeHexTx(*big_child), 0, error));
        BOOST_CHECK_EQUAL(error, "the two transactions exceed the package weight limit");
    }
}

BOOST_AUTO_TEST_CASE(run_job_end_to_end_with_mock_connector)
{
    // A whole job: fixed schedule, primaries first, a connector that overruns its opportunity,
    // empty opportunities, and the report contract.
    JobTestEnv env;
    JobConfig cfg{OnionJobConfig(8)};
    // The first connect (the prompt onion slot's) stalls past the whole middle window: its slot's
    // three backups (and their grace) are overrun while the middle onion slot's opportunities fall
    // due. Every other connect fails at once.
    std::atomic<int> connects{0};
    cfg.connector = [&](const Candidate&, const Socks5Params&) -> Connector {
        return [&](bool& proxy_failed) -> std::unique_ptr<Sock> {
            if (connects.fetch_add(1) == 0) JobTestEnv::StallUntil(Clock::now() + plan::MID_MAX + plan::START_GRACE + 1s);
            proxy_failed = false;
            return nullptr;
        };
    };
    const JobReport report{env.Run(cfg)};
    const UniValue& summary{report.json["summary"]};
    // No stretching: the job ends by its scheduled bound.
    BOOST_CHECK(summary["duration_ms"].getInt<int64_t>() <= Ticks<std::chrono::milliseconds>(plan::SCHEDULED_BOUND));
    BOOST_CHECK_EQUAL(report.exit_code, 2);
    BOOST_CHECK_EQUAL(summary["interrupted"].get_bool(), false);
    BOOST_CHECK_EQUAL(summary["slots_completed"].getInt<int>(), static_cast<int>(plan::SLOTS));
    BOOST_CHECK_EQUAL(summary["announcements_written"].getInt<int>(), 0);
    // Only the onion slots have candidates (eight onions cover two slots x four opportunities); the
    // exit-path slots see empty opportunities only.
    uint32_t attempts{0}, missed{0}, empty{0};
    for (const UniValue& slot : report.json["slots"].getValues()) {
        attempts += slot["attempts"].size();
        missed += slot["missed_opportunities"].getInt<int>();
        empty += slot["empty_opportunities"].getInt<int>();
        if (slot["class"].get_str() == "exit_path") {
            BOOST_CHECK_EQUAL(slot["attempts"].size(), 0U);
            BOOST_CHECK_EQUAL(slot["empty_opportunities"].getInt<int>(), static_cast<int>(plan::OPPORTUNITIES_PER_SLOT));
        }
        for (const UniValue& a : slot["attempts"].getValues()) {
            BOOST_CHECK_EQUAL(a["outcome"].get_str(), "not_announced");
            BOOST_CHECK_EQUAL(a["reason"].get_str(), "socks connect failed");
            BOOST_CHECK_EQUAL(a["source"].get_str(), "bundled");
        }
    }
    // The onion slot whose first connect stalled had its next three opportunities missed rather
    // than dialled late; the other onion slot's four connects failed at once. Every opportunity is
    // exactly one of attempted, missed or empty.
    BOOST_CHECK_EQUAL(attempts + missed + empty, plan::SLOTS * plan::OPPORTUNITIES_PER_SLOT);
    BOOST_CHECK_EQUAL(missed, plan::OPPORTUNITIES_PER_SLOT - 1);
    BOOST_CHECK_EQUAL(attempts, 1U + plan::OPPORTUNITIES_PER_SLOT);
    BOOST_CHECK_EQUAL(empty, (plan::SLOTS - plan::ONION_SLOTS) * plan::OPPORTUNITIES_PER_SLOT);
    BOOST_CHECK_EQUAL(summary["connections"].getInt<int>(), static_cast<int>(attempts));
    // No slot waits for another: the middle slot dialled while the prompt slot's connect was still stalled.
    const auto find_slot = [&](const std::string& stratum) -> const UniValue& {
        for (const UniValue& slot : report.json["slots"].getValues()) {
            if (slot["stratum"].get_str() == stratum && slot["class"].get_str() == "onion") return slot;
        }
        BOOST_FAIL("no onion slot in stratum " + stratum);
        return report.json["slots"][0];
    };
    const UniValue& prompt_onion{find_slot("prompt")};
    const UniValue& mid_onion{find_slot("mid")};
    BOOST_REQUIRE_EQUAL(prompt_onion["attempts"].size(), 1U);
    BOOST_CHECK_EQUAL(prompt_onion["missed_opportunities"].getInt<int>(), static_cast<int>(plan::OPPORTUNITIES_PER_SLOT - 1));
    BOOST_REQUIRE_EQUAL(mid_onion["attempts"].size(), plan::OPPORTUNITIES_PER_SLOT);
    BOOST_CHECK(mid_onion["attempts"][0]["started_ms"].getInt<int64_t>() < prompt_onion["attempts"][0]["ended_ms"].getInt<int64_t>());
}

BOOST_AUTO_TEST_CASE(run_job_slow_preparation_is_a_miss)
{
    // Preparing an attempt (logging, the connector) can stall on a loaded host. The grace check is the
    // last step before the dial, so a stall past the grace skips the opportunity instead of dialling late.
    JobTestEnv env;
    JobConfig cfg{OnionJobConfig(8)};
    std::atomic<int> factory_calls{0};
    cfg.connector = [&](const Candidate&, const Socks5Params&) -> Connector {
        if (factory_calls.fetch_add(1) == 0) JobTestEnv::StallUntil(Clock::now() + plan::START_GRACE + 1s);
        return [](bool& proxy_failed) -> std::unique_ptr<Sock> {
            proxy_failed = false;
            return nullptr;
        };
    };
    const JobReport report{env.Run(cfg)};
    const int64_t grace_ms{Ticks<std::chrono::milliseconds>(plan::START_GRACE)};
    uint32_t attempts{0}, missed{0};
    for (const UniValue& slot : report.json["slots"].getValues()) {
        attempts += slot["attempts"].size();
        missed += slot["missed_opportunities"].getInt<int>();
        for (const UniValue& a : slot["attempts"].getValues()) {
            BOOST_CHECK(a["started_ms"].getInt<int64_t>() - a["scheduled_start_ms"].getInt<int64_t>() <= grace_ms); // started is the very timestamp the grace check used
        }
    }
    // The stalled first opportunity is the one miss; every other onion opportunity is dialled on time.
    BOOST_CHECK_EQUAL(missed, 1U);
    BOOST_CHECK_EQUAL(attempts, plan::ONION_SLOTS * plan::OPPORTUNITIES_PER_SLOT - 1);
    BOOST_CHECK_EQUAL(report.json["summary"]["connections"].getInt<int>(), static_cast<int>(attempts));
}

BOOST_AUTO_TEST_CASE(run_job_slot_failure_is_contained)
{
    // A connector that throws ends its own slot with an error; the other slots run to completion
    // and the job neither aborts nor reports an interrupt.
    JobTestEnv env;
    for (const std::string& message : {std::string{"connector blew up"}, std::string{}}) {
        JobConfig cfg{OnionJobConfig(8)};
        std::atomic<int> connects{0};
        cfg.connector = [&](const Candidate&, const Socks5Params&) -> Connector {
            return [&](bool& proxy_failed) -> std::unique_ptr<Sock> {
                if (connects.fetch_add(1) == 0) throw std::runtime_error(message);
                proxy_failed = false;
                return nullptr;
            };
        };
        const JobReport report{env.Run(cfg)};
        const UniValue& summary{report.json["summary"]};
        BOOST_CHECK_EQUAL(summary["interrupted"].get_bool(), false);
        BOOST_CHECK_EQUAL(summary["slots_completed"].getInt<int>(), static_cast<int>(plan::SLOTS - 1)); // failure does not depend on the message
        int failed{0};
        for (const UniValue& slot : report.json["slots"].getValues()) {
            if (slot["error"].isNull()) continue;
            ++failed;
            BOOST_CHECK_EQUAL(slot["error"].get_str(), message);
            BOOST_CHECK_EQUAL(slot["attempts"].size(), 0U); // the attempt never produced a result
            BOOST_CHECK_EQUAL(slot["class"].get_str(), "onion");
        }
        BOOST_CHECK_EQUAL(failed, 1);
    }
}

BOOST_AUTO_TEST_CASE(run_job_cancel_during_preparation_does_not_dial)
{
    // Cancellation that lands while an attempt is being prepared is seen by the check right before
    // the dial: nothing is connected, and the job ends interrupted.
    JobTestEnv env;
    std::atomic<bool> stop{false};
    JobConfig cfg{OnionJobConfig(8)};
    cfg.interrupted = [&] { return stop.load(); };
    std::atomic<bool> dialled{false};
    cfg.connector = [&](const Candidate&, const Socks5Params&) -> Connector {
        stop = true; // cancelled between preparation and the dial
        return [&](bool& proxy_failed) -> std::unique_ptr<Sock> {
            dialled = true;
            proxy_failed = false;
            return nullptr;
        };
    };
    const JobReport report{env.Run(cfg)};
    BOOST_CHECK(!dialled);
    BOOST_CHECK_EQUAL(report.json["summary"]["connections"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(report.json["summary"]["interrupted"].get_bool(), true);
    BOOST_CHECK(report.json["summary"]["slots_completed"].getInt<int>() < static_cast<int>(plan::SLOTS));
}

BOOST_AUTO_TEST_CASE(run_job_no_slot_waits_for_another)
{
    // All three prompt connects stall for the whole middle window; the middle slot's primary still
    // opens at its own time. Four attempts overlap, so any limiter of three or fewer would fail this;
    // that the slot loop has no limiter at all is a matter of inspection.
    JobTestEnv env;
    DiscoveryResult found;
    found.per_seed.resize(1);
    found.seeds.resize(1);
    found.tie_order = {0};
    for (uint32_t i = 0; i < (plan::SLOTS - plan::ONION_SLOTS) * plan::OPPORTUNITIES_PER_SLOT; ++i) {
        found.per_seed[0].push_back(Candidate{CService{LookupNumeric(strprintf("203.0.113.%d", 10 + i), 8333)}, Source::DNS_SEED, "seed0"});
    }
    for (uint32_t i = 0; i < plan::ONION_SLOTS * plan::OPPORTUNITIES_PER_SLOT; ++i) {
        std::vector<uint8_t> pubkey(32, static_cast<uint8_t>(i + 1));
        CNetAddr addr;
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(pubkey)));
        found.onion.push_back(Candidate{CService{addr, 8333}, Source::BUNDLED, "bundled"});
    }
    JobConfig cfg{OnionJobConfig(0)};
    cfg.discover = [found] { return found; };
    std::atomic<int> connects{0};
    cfg.connector = [&](const Candidate&, const Socks5Params&) -> Connector {
        return [&](bool& proxy_failed) -> std::unique_ptr<Sock> {
            if (connects.fetch_add(1) < static_cast<int>(CountSlots(Stratum::PROMPT))) {
                JobTestEnv::StallUntil(Clock::now() + plan::MID_MAX + plan::START_GRACE + 1s);
            }
            proxy_failed = false;
            return nullptr;
        };
    };
    const JobReport report{env.Run(cfg)};
    int64_t prompt_ended{std::numeric_limits<int64_t>::max()};
    std::optional<int64_t> mid_started;
    for (const UniValue& slot : report.json["slots"].getValues()) {
        const UniValue& attempts{slot["attempts"]};
        if (slot["stratum"].get_str() == "prompt") {
            BOOST_REQUIRE_EQUAL(attempts.size(), 1U); // stalled once; its backups fell due meanwhile and were missed
            BOOST_CHECK_EQUAL(slot["missed_opportunities"].getInt<int>(), static_cast<int>(plan::OPPORTUNITIES_PER_SLOT - 1));
            prompt_ended = std::min(prompt_ended, attempts[0]["ended_ms"].getInt<int64_t>());
        } else if (slot["stratum"].get_str() == "mid") {
            BOOST_REQUIRE_EQUAL(attempts.size(), plan::OPPORTUNITIES_PER_SLOT); // every connect failed at once
            mid_started = attempts[0]["started_ms"].getInt<int64_t>();
        }
    }
    BOOST_REQUIRE(mid_started.has_value());
    BOOST_CHECK(*mid_started < prompt_ended); // dialled while all three prompt connects were still stalled
}

BOOST_AUTO_TEST_CASE(run_job_interrupt_reaches_blocked_connector)
{
    // Cancellation must reach a thread blocked inside the connector (a SOCKS exchange in bitcoind):
    // the watcher turns the flag into the job's SOCKS interrupt, and the job ends at once.
    JobTestEnv env;
    JobConfig cfg{OnionJobConfig(1)};
    std::atomic<bool> stop{false};
    cfg.interrupted = [&] { return stop.load(); };
    std::atomic<bool> connector_entered{false};
    cfg.connector = [&](const Candidate&, const Socks5Params& socks) -> Connector {
        BOOST_REQUIRE(socks.interrupt != nullptr);
        BOOST_CHECK(socks.interrupt != &g_socks5_interrupt); // the job's own, not the process-wide latch
        return [&, interrupt = socks.interrupt](bool& proxy_failed) -> std::unique_ptr<Sock> {
            connector_entered = true;
            // Like a SOCKS exchange: returns only when interrupted.
            WaitUntil(Clock::time_point::max(), [interrupt] { return bool(*interrupt); });
            proxy_failed = false;
            return nullptr;
        };
    };
    // Cancel once the empty slots have run out their opportunities: after that nothing but the
    // blocked connector is alive on the job side, so only the watcher can turn the flag into a
    // SOCKS interrupt. Nothing bounded is pending by then, so the clock is pushed on here.
    const auto cancel_at{Clock::now() + plan::SCHEDULED_BOUND + 1s};
    const JobReport report{env.Run(cfg, [&] {
        if (stop) return;
        if (Clock::now() >= cancel_at) {
            stop = true;
            WakeWaiters();
        } else if (!mocktime::NextWait()) {
            mocktime::Advance(1s);
        }
    })};
    BOOST_CHECK(connector_entered);
    BOOST_CHECK_EQUAL(report.exit_code, 2);
    const UniValue& summary{report.json["summary"]};
    BOOST_CHECK_EQUAL(summary["interrupted"].get_bool(), true);
    BOOST_CHECK(summary["slots_completed"].getInt<int>() < static_cast<int>(plan::SLOTS));
    // The job ended with the cancellation, not at its hard cap.
    const int64_t duration_ms{summary["duration_ms"].getInt<int64_t>()};
    BOOST_CHECK(duration_ms >= Ticks<std::chrono::milliseconds>(plan::SCHEDULED_BOUND));
    BOOST_CHECK(duration_ms < Ticks<std::chrono::milliseconds>(plan::JOB_CAP));
}

BOOST_AUTO_TEST_CASE(run_job_no_replacement_after_announcement)
{
    // The replaceability boundary is INV being handed to the transport, not its bytes leaving.
    // A peer that completes the handshake, receives the INV and then breaks the connection has
    // been announced to: its slot makes no further attempt.
    struct BreakSock : ZeroSock {
        BreakSock() : m_peer(std::make_unique<V2Transport>(NodeId{2}, /*initiating=*/false)) {} // the tool speaks v2 only
        BreakSock& operator=(Sock&&) override { assert(false && "Move of Sock into BreakSock not allowed."); return *this; }
        ssize_t Recv(void* buf, size_t len, int flags) const override
        {
            Pump();
            if (m_to_tool.empty()) { errno = WSAEWOULDBLOCK; return -1; }
            const size_t n{std::min(len, m_to_tool.size())};
            std::memcpy(buf, m_to_tool.data(), n);
            if ((flags & MSG_PEEK) == 0) m_to_tool.erase(m_to_tool.begin(), m_to_tool.begin() + n);
            return static_cast<ssize_t>(n);
        }
        ssize_t Send(const void* data, size_t len, int) const override
        {
            if (m_app_seen >= 3) { errno = ECONNRESET; return -1; } // our INV or later: refuse the write
            std::span<const uint8_t> bytes{static_cast<const uint8_t*>(data), len};
            while (!bytes.empty()) {
                if (!m_peer->ReceivedBytes(bytes)) { errno = ECONNRESET; return -1; }
                if (m_peer->ReceivedMessageComplete()) {
                    bool reject{false};
                    const CNetMessage msg{m_peer->GetReceivedMessage(NodeClock::now(), reject)};
                    if (!reject && msg.m_type == NetMsgType::VERSION) {
                        m_pending.push_back(PeerVersion());
                        m_pending.push_back(NetMsg::Make(NetMsgType::WTXIDRELAY));
                        m_pending.push_back(NetMsg::Make(NetMsgType::VERACK));
                    }
                    ++m_app_seen;
                }
            }
            return static_cast<ssize_t>(len);
        }
        void Pump() const
        {
            while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
            while (true) {
                const auto [b, more, type] = m_peer->GetBytesToSend(!m_pending.empty());
                if (b.empty()) break;
                m_to_tool.insert(m_to_tool.end(), b.begin(), b.end());
                m_peer->MarkBytesSent(b.size());
                while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
            }
        }
        const std::unique_ptr<Transport> m_peer;
        mutable std::vector<uint8_t> m_to_tool;
        mutable std::deque<CSerializedNetMsg> m_pending;
        mutable size_t m_app_seen{0};
    };

    JobTestEnv env;

    // Eight onions, so each onion slot has four: opportunities 1 to 3 are there to be used only
    // if opportunity 0 failed before announcing.

    // Every attempt announces then breaks. Each onion slot announces at opportunity 0 and is done;
    // opportunities 1 to 3 are never used, so no replacement is made after an announcement.
    {
        JobConfig cfg{OnionJobConfig(8)};
        cfg.connector = [](const Candidate&, const Socks5Params&) -> Connector {
            return [](bool&) -> std::unique_ptr<Sock> { return std::make_unique<BreakSock>(); };
        };
        const JobReport report{env.Run(cfg)};
        BOOST_CHECK_EQUAL(report.exit_code, 2); // announced but never fully written
        const UniValue& summary{report.json["summary"]};
        BOOST_CHECK_EQUAL(summary["announcements_handed"].getInt<int>(), static_cast<int>(plan::ONION_SLOTS));
        BOOST_CHECK_EQUAL(summary["announcements_written"].getInt<int>(), 0);
        int attempts{0};
        for (const UniValue& slot : report.json["slots"].getValues()) {
            bool seen_announced{false};
            for (const UniValue& a : slot["attempts"].getValues()) {
                BOOST_CHECK(!seen_announced); // nothing runs in a slot after it announced
                ++attempts;
                if (!a["inv_handed_ms"].isNull()) {
                    seen_announced = true;
                    BOOST_CHECK(a["inv_written_ms"].isNull()); // handed over, write refused
                    BOOST_CHECK_EQUAL(a["outcome"].get_str(), "post_announcement_failure");
                }
            }
        }
        BOOST_CHECK_EQUAL(attempts, static_cast<int>(plan::ONION_SLOTS)); // one announcing attempt per onion slot, then it stops
    }

    // Control: the same candidates, but every connect fails before any handshake. Now nothing
    // announces, so each onion slot uses all of its later opportunities: replacements are made.
    {
        JobConfig cfg{OnionJobConfig(8)};
        cfg.connector = [](const Candidate&, const Socks5Params&) -> Connector {
            return [](bool&) -> std::unique_ptr<Sock> { return nullptr; }; // socks connect failed
        };
        const JobReport report{env.Run(cfg)};
        BOOST_CHECK_EQUAL(report.exit_code, 2);
        BOOST_CHECK_EQUAL(report.json["summary"]["announcements_handed"].getInt<int>(), 0);
        int max_in_a_slot{0};
        for (const UniValue& slot : report.json["slots"].getValues()) {
            max_in_a_slot = std::max<int>(max_in_a_slot, slot["attempts"].size());
            for (const UniValue& a : slot["attempts"].getValues()) {
                BOOST_CHECK_EQUAL(a["outcome"].get_str(), "not_announced");
                BOOST_CHECK_EQUAL(a["reason"].get_str(), "socks connect failed");
            }
        }
        BOOST_CHECK_EQUAL(max_in_a_slot, static_cast<int>(plan::OPPORTUNITIES_PER_SLOT)); // replacement happens when nothing announced
    }
}

BOOST_AUTO_TEST_SUITE_END()
