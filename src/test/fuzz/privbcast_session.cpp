// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <netaddress.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace privbcast;

namespace {

CTransactionRef FallbackTx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    mtx.vin[0].scriptWitness.stack.push_back({1, 2, 3});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    return MakeTransactionRef(mtx);
}

/** True for the only inbound types the session ever acts on; everything else must be ignored. */
bool IsActedType(const std::string& type)
{
    return type == NetMsgType::VERSION || type == NetMsgType::WTXIDRELAY || type == NetMsgType::VERACK ||
           type == NetMsgType::GETDATA || type == NetMsgType::PONG;
}

/**
 * Assert an emitted message is byte-for-byte the fixed profile. Nothing the session sends may
 * carry anything host-, node- or user-specific: that identical wire image across all users is
 * the privacy property. Only the two random nonces vary, so VERSION is checked field by field
 * (its nonce is not exposed) and the rest are rebuilt from constants and compared as bytes.
 */
void CheckEmitted(const CSerializedNetMsg& msg, const CTransactionRef& tx, uint64_t ping_nonce)
{
    if (msg.m_type == NetMsgType::VERSION) {
        DataStream s{msg.data};
        int version;
        uint64_t services;
        int64_t time;
        CService addr_recv;
        uint64_t nonce;
        std::string user_agent;
        int32_t height;
        bool relay;
        // The same field layout HandleVersion reads back, so a mismatch here is a real drift.
        s >> version >> Using<CustomUintFormatter<8>>(services) >> time;
        s.ignore(8); // addrRecv services
        s >> CNetAddr::V1(addr_recv);
        s.ignore(26); // addrFrom
        s >> nonce >> LIMITED_STRING(user_agent, wire::MAX_SUBVERSION_LENGTH) >> height >> relay;
        assert(version == wire::PROTOCOL_VERSION);
        assert(services == wire::SERVICES);
        assert(time == 0);
        assert(addr_recv == CService{});
        assert(user_agent == wire::USER_AGENT);
        assert(height == 0);
        assert(!relay);
        assert(s.empty()); // no trailing bytes
    } else if (msg.m_type == NetMsgType::WTXIDRELAY) {
        assert(msg.data.empty());
    } else if (msg.m_type == NetMsgType::VERACK) {
        assert(msg.data == NetMsg::Make(NetMsgType::VERACK).data);
    } else if (msg.m_type == NetMsgType::INV) {
        // Always by wtxid: BIP339 wtxid relay is required.
        assert(msg.data == NetMsg::Make(NetMsgType::INV, std::vector<CInv>{CInv{MSG_WTX, tx->GetWitnessHash().ToUint256()}}).data);
    } else if (msg.m_type == NetMsgType::TX) {
        assert(msg.data == NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)).data);
    } else if (msg.m_type == NetMsgType::PING) {
        assert(msg.data == NetMsg::Make(NetMsgType::PING, ping_nonce).data);
    } else {
        assert(false); // the session never emits any other type
    }
}

/** The deadline is a pure function of the scheduled start and the evidence so far. */
void CheckDeadline(const Session& session, Clock::time_point scheduled_start)
{
    const auto& ev{session.GetEvidence()};
    Clock::time_point expected;
    if (ev.ping_written) {
        expected = *ev.ping_written + Scaled(wire::PONG_WAIT);
    } else if (ev.inv_handed) {
        expected = *ev.inv_handed + Scaled(wire::REQUEST_WINDOW);
    } else {
        expected = scheduled_start + Scaled(wire::HANDSHAKE_TIMEOUT);
    }
    assert(session.Deadline() == expected);
}

bool EvidenceEqual(const Session::Evidence& a, const Session::Evidence& b)
{
    return a.version_received == b.version_received && a.inv_handed == b.inv_handed &&
           a.inv_written == b.inv_written && a.getdata_received == b.getdata_received &&
           a.tx_written == b.tx_written && a.ping_written == b.ping_written &&
           a.pong_received == b.pong_received && a.extra_requests == b.extra_requests;
}

void initialize_privbcast_session()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

} // namespace

FUZZ_TARGET(privbcast_session, .init = initialize_privbcast_session)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    CTransactionRef tx{FallbackTx()};
    if (fdp.ConsumeBool()) {
        if (const auto mtx{ConsumeDeserializable<CMutableTransaction>(fdp, TX_WITH_WITNESS)}) tx = MakeTransactionRef(*mtx);
    }
    // Two sessions from identical deterministic RNGs get identical nonces, so they are byte-for-byte
    // twins. Every meaningful event is applied to both; only `twin` additionally receives traffic the
    // session must ignore. If ignored traffic ever changed anything a recipient can see, the twins'
    // outbound bytes, deadline, outcome or evidence would diverge and one of the asserts below fires.
    FastRandomContext rng_a{/*fDeterministic=*/true};
    FastRandomContext rng_b{/*fDeterministic=*/true};
    const auto start{Clock::time_point{std::chrono::seconds{fdp.ConsumeIntegral<uint32_t>()}}};
    auto now{start};
    Session real{tx, start, rng_a};
    Session twin{tx, start, rng_b};
    assert(real.PingNonce() == twin.PingNonce());
    const uint64_t our_nonce{real.PingNonce()};
    const auto txid{tx->GetHash().ToUint256()};
    const auto wtxid{tx->GetWitnessHash().ToUint256()};

    // Outbound is asserted identical between the twins, so one set of transport bookkeeping serves both.
    std::vector<std::string> queued;
    std::vector<std::string> handed;
    size_t tx_messages{0};
    size_t inv_messages{0};
    size_t wtxidrelay_messages{0};

    const auto drain_and_check = [&] {
        auto a{real.TakeOutbound()};
        auto b{twin.TakeOutbound()};
        assert(a.size() == b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            assert(a[i].m_type == b[i].m_type);
            assert(a[i].data == b[i].data); // ignored traffic to the twin changed nothing on the wire
            CheckEmitted(a[i], tx, our_nonce);
            if (a[i].m_type == NetMsgType::TX) ++tx_messages;
            if (a[i].m_type == NetMsgType::WTXIDRELAY) ++wtxidrelay_messages;
            if (a[i].m_type == NetMsgType::INV) ++inv_messages;
            queued.push_back(a[i].m_type);
        }
        // Observable equivalence of the twins.
        assert(real.Deadline() == twin.Deadline());
        assert(real.GetOutcome() == twin.GetOutcome());
        assert(real.Announced() == twin.Announced());
        assert(EvidenceEqual(real.GetEvidence(), twin.GetEvidence()));
        CheckDeadline(real, start);
        // Serve once, announce once.
        assert(tx_messages <= 1);
        assert(inv_messages <= 1);
        assert(wtxidrelay_messages <= 1);
        if (real.Finished()) {
            assert(real.GetOutcome() != Outcome::PENDING);
            assert(IsPostAnnouncement(real.GetOutcome()) == real.Announced());
        } else {
            assert(real.GetOutcome() == Outcome::PENDING);
        }
        // Evidence ordering follows the protocol.
        const auto& ev{real.GetEvidence()};
        if (inv_messages == 1) assert(wtxidrelay_messages == 1); // never announced without offering wtxid relay
        if (ev.inv_written) assert(ev.inv_handed);
        if (ev.getdata_received) assert(ev.inv_handed);
        if (ev.tx_written) assert(ev.getdata_received);
        if (ev.ping_written) assert(ev.getdata_received);
        if (ev.pong_received) assert(ev.getdata_received && real.GetOutcome() == Outcome::PONG_RECEIVED);
        if (tx_messages == 1) assert(ev.getdata_received);
        assert(!OutcomeName(real.GetOutcome()).empty()); // every outcome has a stable name
    };

    // Feed one complete message, identical bytes, to both twins.
    const auto feed_both = [&](const std::string& type, const std::vector<unsigned char>& bytes) {
        DataStream pa{bytes};
        real.OnMessage(type, pa, now);
        DataStream pb{bytes};
        twin.OnMessage(type, pb, now);
    };

    drain_and_check(); // the constructor's VERSION

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 300)
    {
        CallOneOf(
            fdp,
            [&] {
                // Any message type with an arbitrary payload: the session must ignore it or fail cleanly.
                const std::string type{fdp.ConsumeBool() ? std::string{fdp.PickValueInArray(ALL_NET_MESSAGE_TYPES)} : fdp.ConsumeRandomLengthString(12)};
                feed_both(type, ConsumeRandomLengthByteVector(fdp));
            },
            [&] {
                // VERSION with fuzzed admission fields, optionally truncated.
                const int version{fdp.PickValueInArray<int>({70017, 70016, 70015, 70001, 70000, 60002, 31800, 0, -1, fdp.ConsumeIntegral<int>()})};
                const uint64_t services{fdp.PickValueInArray<uint64_t>({NODE_NETWORK | NODE_WITNESS, NODE_WITNESS, NODE_NETWORK, 0, fdp.ConsumeIntegral<uint64_t>()})};
                auto msg{NetMsg::Make(NetMsgType::VERSION, version, services, fdp.ConsumeIntegral<int64_t>(),
                                      uint64_t{0}, CNetAddr::V1(CService{}), uint64_t{0}, CNetAddr::V1(CService{}),
                                      fdp.ConsumeIntegral<uint64_t>(), fdp.ConsumeRandomLengthString(300),
                                      fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBool())};
                if (fdp.ConsumeBool()) msg.data.resize(fdp.ConsumeIntegralInRange<size_t>(0, msg.data.size()));
                feed_both(msg.m_type, msg.data);
            },
            [&] {
                // BIP339 WTXIDRELAY, before or after VERACK, optionally with a stray payload.
                std::vector<unsigned char> bytes;
                if (fdp.ConsumeBool()) bytes = ConsumeRandomLengthByteVector(fdp, 8);
                feed_both(NetMsgType::WTXIDRELAY, bytes);
            },
            [&] {
                auto msg{NetMsg::Make(NetMsgType::VERACK)};
                if (fdp.ConsumeBool()) msg.data = ConsumeRandomLengthByteVector(fdp, 64);
                feed_both(msg.m_type, msg.data);
            },
            [&] {
                // GETDATA: the one profile request, its near misses, repeats, and malformed forms.
                std::vector<CInv> inv;
                const size_t n{fdp.ConsumeIntegralInRange<size_t>(0, 3)};
                for (size_t i = 0; i < n; ++i) {
                    const uint32_t type{fdp.PickValueInArray<uint32_t>({MSG_TX, MSG_WITNESS_TX, MSG_WTX, MSG_BLOCK, MSG_WITNESS_TX, fdp.ConsumeIntegral<uint32_t>()})};
                    const uint256 hash{fdp.ConsumeBool() ? txid : fdp.ConsumeBool() ? wtxid : ConsumeUInt256(fdp)};
                    inv.emplace_back(type, hash);
                }
                auto msg{NetMsg::Make(NetMsgType::GETDATA, inv)};
                if (fdp.ConsumeBool()) {
                    // Trailing junk or truncation.
                    if (fdp.ConsumeBool()) {
                        const auto junk{ConsumeRandomLengthByteVector(fdp, 16)};
                        msg.data.insert(msg.data.end(), junk.begin(), junk.end());
                    } else {
                        msg.data.resize(fdp.ConsumeIntegralInRange<size_t>(0, msg.data.size()));
                    }
                }
                feed_both(msg.m_type, msg.data);
            },
            [&] {
                auto msg{NetMsg::Make(NetMsgType::PONG, fdp.ConsumeBool() ? our_nonce : fdp.ConsumeIntegral<uint64_t>())};
                if (fdp.ConsumeBool()) msg.data.resize(fdp.ConsumeIntegralInRange<size_t>(0, 12));
                feed_both(msg.m_type, msg.data);
            },
            [&] {
                // Ticks: arbitrary advances and the exact deadline (strictness boundary).
                if (fdp.ConsumeBool()) {
                    now = std::max(now, real.Deadline() - std::chrono::milliseconds{fdp.ConsumeIntegralInRange<int>(0, 1)});
                } else {
                    now += std::chrono::seconds{fdp.ConsumeIntegralInRange<uint32_t>(0, 200)};
                }
                real.OnTick(now);
                twin.OnTick(now);
            },
            [&] {
                // Legal transport handover: only for a message the session emitted, in order.
                if (!queued.empty()) {
                    const std::string type{queued.front()};
                    queued.erase(queued.begin());
                    handed.push_back(type);
                    real.OnMessageHandedToTransport(type, now);
                    twin.OnMessageHandedToTransport(type, now);
                }
            },
            [&] {
                // Legal completion: only for a message the transport has taken, in order.
                if (!handed.empty()) {
                    const std::string type{handed.front()};
                    handed.erase(handed.begin());
                    real.OnMessageWritten(type, now);
                    twin.OnMessageWritten(type, now);
                }
            },
            [&] {
                // Illegal callbacks for types never emitted must be harmless no-ops.
                const std::string type{fdp.PickValueInArray(ALL_NET_MESSAGE_TYPES)};
                const bool emitted{std::find(queued.begin(), queued.end(), type) != queued.end() ||
                                   std::find(handed.begin(), handed.end(), type) != handed.end()};
                if (!emitted && type != NetMsgType::INV && type != NetMsgType::TX && type != NetMsgType::PING) {
                    const auto br{real.GetEvidence()};
                    const auto bt{twin.GetEvidence()};
                    real.OnMessageHandedToTransport(type, now);
                    real.OnMessageWritten(type, now);
                    twin.OnMessageHandedToTransport(type, now);
                    twin.OnMessageWritten(type, now);
                    assert(EvidenceEqual(real.GetEvidence(), br));
                    assert(EvidenceEqual(twin.GetEvidence(), bt));
                }
            },
            [&] {
                const bool announced{real.Announced()};
                real.Fail("fuzz");
                twin.Fail("fuzz");
                assert(real.Finished());
                assert(IsPostAnnouncement(real.GetOutcome()) == announced);
            },
            [&] {
                // Traffic the session ignores in every state, delivered to the twin alone: excluding the
                // four acted-on types guarantees it touches neither the wire nor the evidence.
                static constexpr std::array kinds{NetMsgType::ADDR, NetMsgType::ADDRV2, NetMsgType::INV,
                                                  NetMsgType::TX, NetMsgType::HEADERS, NetMsgType::BLOCK,
                                                  NetMsgType::GETHEADERS, NetMsgType::FEEFILTER, NetMsgType::PING,
                                                  NetMsgType::NOTFOUND, NetMsgType::SENDHEADERS, NetMsgType::CMPCTBLOCK};
                std::string type{fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(12) : std::string{fdp.PickValueInArray(kinds)}};
                if (IsActedType(type)) type = NetMsgType::ADDR;
                // OnMessage ticks the twin at `now`; tick the real session identically so only the
                // extra (ignored) message, never a stray deadline crossing, distinguishes the two.
                real.OnTick(now);
                twin.OnTick(now);
                const auto bytes{ConsumeRandomLengthByteVector(fdp)};
                DataStream payload{bytes};
                twin.OnMessage(type, payload, now);
            });
        drain_and_check();
    }
    // Once finished nothing more is ever emitted, by either twin.
    if (real.Finished()) {
        feed_both(NetMsgType::GETDATA, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, wtxid}}).data);
        assert(real.TakeOutbound().empty());
        assert(twin.TakeOutbound().empty());
    }
}
