// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <compat/compat.h>
#include <net_transport.h>
#include <netaddress.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/discovery.h>
#include <privbcast/session.h>
#include <privbcast/timing.h>
#include <protocol.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/sock.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
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

/** Counters the fuzz body keeps; the socket dies inside RunAttempt. */
struct PeerStats {
    size_t tx_seen{0};
    size_t inv_seen{0};
    size_t messages_seen{0};
};

/**
 * A socket whose far end is a scripted, possibly hostile peer. Bytes the tool sends are decoded
 * with the peer's own transport; the peer answers according to fuzz choices (honest replies,
 * near misses, repeats, junk, silence, close) and its bytes reach the tool in fuzz-chosen
 * chunks with occasional EAGAIN, corrupted bytes, resets or a stall. When the script runs out
 * the peer closes, so an attempt only outlives the input when a stall is scripted, and then the
 * session deadlines end it, on a clock the stall itself advances.
 */
class ScriptedPeerSock final : public ZeroSock
{
public:
    ScriptedPeerSock(FuzzedDataProvider& fdp, std::unique_ptr<Transport> peer, CTransactionRef tx, PeerStats& stats)
        : m_fdp{fdp}, m_peer{std::move(peer)}, m_tx{std::move(tx)}, m_stats{stats},
          m_stall_after{m_fdp.ConsumeIntegralInRange<int>(0, 31) == 0 ? m_fdp.ConsumeIntegralInRange<int>(0, 8) : -1} {}

    ScriptedPeerSock& operator=(Sock&&) override
    {
        assert(false && "Move of Sock into ScriptedPeerSock not allowed.");
        return *this;
    }

    ssize_t Send(const void* data, size_t len, int) const override
    {
        if (len == 0) return 0;
        if (m_eagain_budget > 0 && m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) {
            --m_eagain_budget;
            errno = EAGAIN;
            return -1;
        }
        if (m_fdp.ConsumeIntegralInRange<int>(0, 31) == 0) {
            errno = ECONNRESET;
            return -1;
        }
        const size_t n{m_fdp.ConsumeBool() ? m_fdp.ConsumeIntegralInRange<size_t>(1, len) : len};
        if (!m_peer_is_garbage) {
            std::span<const uint8_t> bytes{static_cast<const uint8_t*>(data), n};
            while (!bytes.empty()) {
                if (!m_peer->ReceivedBytes(bytes)) {
                    // The peer could not decode us (e.g. a v1 peer facing our v2 handshake): it drops us.
                    m_closed = true;
                    break;
                }
                if (m_peer->ReceivedMessageComplete()) {
                    bool reject{false};
                    CNetMessage msg{m_peer->GetReceivedMessage(NodeClock::now(), reject)};
                    if (!reject) OnToolMessage(msg);
                }
            }
        }
        PumpPeer();
        return static_cast<ssize_t>(n);
    }

    ssize_t Recv(void* buf, size_t len, int) const override
    {
        PumpPeer();
        if (m_peer_is_garbage && m_to_tool.empty() && m_fdp.remaining_bytes() > 0) {
            // A peer that speaks no transport at all: raw bytes until the input runs out.
            const auto junk{ConsumeRandomLengthByteVector(m_fdp, 512)};
            m_to_tool.insert(m_to_tool.end(), junk.begin(), junk.end());
        }
        if (m_to_tool.empty()) {
            if (m_closed) return 0;
            if (m_stall_after == 0) {
                // Silent forever: the session deadlines have to end this. Each poll finds the
                // clock moved on by a scripted 5 to 60 seconds.
                SetMockTime(GetMockTime() + std::chrono::seconds{5 + m_fdp.ConsumeIntegralInRange<int>(0, 55)});
                errno = EAGAIN;
                return -1;
            }
            if (m_stall_after > 0) --m_stall_after;
            if (m_fdp.remaining_bytes() == 0) return 0;
            if (m_eagain_budget > 0 && m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) {
                --m_eagain_budget;
                errno = EAGAIN;
                return -1;
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 31) == 0) {
                errno = ECONNRESET;
                return -1;
            }
            // Nothing scripted to say: the peer goes away.
            m_closed = true;
            return 0;
        }
        const size_t avail{std::min(len, m_to_tool.size())};
        const size_t n{m_fdp.ConsumeBool() ? m_fdp.ConsumeIntegralInRange<size_t>(1, avail) : avail};
        for (size_t i = 0; i < n; ++i) {
            static_cast<uint8_t*>(buf)[i] = m_to_tool.front();
            m_to_tool.pop_front();
        }
        return static_cast<ssize_t>(n);
    }

    void SetGarbagePeer() { m_peer_is_garbage = true; }

private:
    /** Encode queued replies with the peer transport and move the bytes to the tool's queue. */
    void PumpPeer() const
    {
        while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
        const size_t before{m_to_tool.size()};
        while (true) {
            const auto [bytes, more, type] = m_peer->GetBytesToSend(/*have_next_message=*/!m_pending.empty());
            if (bytes.empty()) break;
            m_to_tool.insert(m_to_tool.end(), bytes.begin(), bytes.end());
            m_peer->MarkBytesSent(bytes.size());
            while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
        }
        if (m_to_tool.size() > before && m_fdp.ConsumeIntegralInRange<int>(0, 15) == 0) {
            // Corrupt one freshly encoded byte: a v2 AEAD failure on the tool's side, or more junk from a peer that never spoke v2.
            m_to_tool[m_fdp.ConsumeIntegralInRange<size_t>(before, m_to_tool.size() - 1)] ^= m_fdp.ConsumeIntegralInRange<uint8_t>(1, 255);
        }
        if (m_inject_garbage) {
            const auto junk{ConsumeRandomLengthByteVector(m_fdp, 64)};
            m_to_tool.insert(m_to_tool.end(), junk.begin(), junk.end());
            m_inject_garbage = false;
        }
    }

    void Reply(CSerializedNetMsg msg) const { m_pending.push_back(std::move(msg)); }

    void OnToolMessage(const CNetMessage& msg) const
    {
        const std::string& type{msg.m_type};
        ++m_stats.messages_seen;
        if (type == NetMsgType::TX) ++m_stats.tx_seen;
        // Whatever the tool sent, a hostile peer may answer with anything at all.
        if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) {
            CSerializedNetMsg junk;
            junk.m_type = m_fdp.PickValueInArray(ALL_NET_MESSAGE_TYPES);
            junk.data = ConsumeRandomLengthByteVector(m_fdp, 40);
            Reply(std::move(junk));
        }
        if (m_fdp.ConsumeIntegralInRange<int>(0, 15) == 0) m_inject_garbage = true;
        if (type == NetMsgType::VERSION) {
            const int version{m_fdp.PickValueInArray<int>({70017, 70016, 70015, 70001, 70000, 60002, m_fdp.ConsumeIntegral<int>()})};
            const uint64_t services{m_fdp.PickValueInArray<uint64_t>({NODE_NETWORK | NODE_WITNESS, NODE_NETWORK | NODE_WITNESS, NODE_WITNESS, NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2, NODE_NETWORK, 0})};
            const bool relay{m_fdp.ConsumeIntegralInRange<int>(0, 7) != 0};
            auto v{NetMsg::Make(NetMsgType::VERSION, version, services, int64_t{0}, uint64_t{0}, CNetAddr::V1(CService{}),
                                 uint64_t{0}, CNetAddr::V1(CService{}), m_fdp.ConsumeIntegral<uint64_t>(),
                                 std::string{"/fuzzpeer:0.1/"}, int{100}, relay)};
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) v.data.resize(m_fdp.ConsumeIntegralInRange<size_t>(0, v.data.size()));
            if (m_fdp.ConsumeIntegralInRange<int>(0, 15) != 0) Reply(std::move(v));
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) != 0) Reply(NetMsg::Make(NetMsgType::WTXIDRELAY));
            if (m_fdp.ConsumeBool()) Reply(NetMsg::Make(NetMsgType::SENDADDRV2));
            if (m_fdp.ConsumeBool()) Reply(NetMsg::Make(NetMsgType::SENDTXRCNCL, uint32_t{1}, m_fdp.ConsumeIntegral<uint64_t>()));
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) != 0) {
                auto va{NetMsg::Make(NetMsgType::VERACK)};
                if (m_fdp.ConsumeIntegralInRange<int>(0, 15) == 0) va.data = {1, 2, 3};
                Reply(std::move(va));
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) Reply(NetMsg::Make(NetMsgType::PING, m_fdp.ConsumeIntegral<uint64_t>()));
        } else if (type == NetMsgType::INV) {
            const uint256 txid{m_tx->GetHash().ToUint256()};
            const uint256 wtxid{m_tx->GetWitnessHash().ToUint256()};
            {
                // The tool announces exactly its transaction, by wtxid (BIP339 is required), and only ever once.
                ++m_stats.inv_seen;
                DataStream is{msg.m_recv};
                std::vector<CInv> tool_inv;
                is >> tool_inv;
                assert(tool_inv.size() == 1 && tool_inv[0].type == MSG_WTX && tool_inv[0].hash == wtxid);
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 15) == 0) {
                // Flood a single well-framed INV larger than the raw receive cap: the tool ignores
                // its contents but must end the attempt on the byte budget, not decode all of it.
                std::vector<CInv> big(3000, CInv{MSG_TX, wtxid}); // ~108 KiB on the wire
                Reply(NetMsg::Make(NetMsgType::INV, big));
            }
            const int requests{m_fdp.ConsumeBool() ? 1 : m_fdp.ConsumeIntegralInRange<int>(0, 3)};
            for (int i = 0; i < requests; ++i) {
                std::vector<CInv> inv;
                switch (m_fdp.ConsumeIntegralInRange<int>(0, 7)) {
                case 0: case 1: case 2: inv.emplace_back(MSG_WTX, wtxid); break;
                case 3: inv.emplace_back(MSG_TX, txid); break;
                case 4: inv.emplace_back(MSG_WITNESS_TX, txid); break;
                case 5: inv.emplace_back(MSG_WTX, wtxid); inv.emplace_back(MSG_WTX, wtxid); break;
                case 6: inv.emplace_back(MSG_WITNESS_TX, ConsumeUInt256(m_fdp)); break;
                default: break; // empty GETDATA
                }
                auto gd{NetMsg::Make(NetMsgType::GETDATA, inv)};
                if (m_fdp.ConsumeIntegralInRange<int>(0, 15) == 0) gd.data.push_back(0);
                Reply(std::move(gd));
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) Reply(NetMsg::Make(NetMsgType::PING, m_fdp.ConsumeIntegral<uint64_t>()));
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) Reply(NetMsg::Make(NetMsgType::INV, std::vector<CInv>{CInv{MSG_WTX, wtxid}}));
        } else if (type == NetMsgType::TX) {
            {
                // The served transaction is exactly ours, witness included.
                CMutableTransaction got;
                DataStream ts{msg.m_recv};
                ts >> TX_WITH_WITNESS(got);
                const CTransaction gtx{got};
                assert(gtx.GetHash() == m_tx->GetHash() && gtx.GetWitnessHash() == m_tx->GetWitnessHash());
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 3) == 0) Reply(NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{MSG_WTX, m_tx->GetWitnessHash().ToUint256()}}));
            if (m_fdp.ConsumeIntegralInRange<int>(0, 3) == 0) Reply(NetMsg::Make(NetMsgType::PONG, m_fdp.ConsumeIntegral<uint64_t>()));
        } else if (type == NetMsgType::PING) {
            uint64_t nonce{0};
            DataStream payload{msg.m_recv};
            if (payload.size() >= sizeof(nonce)) payload >> nonce;
            switch (m_fdp.ConsumeIntegralInRange<int>(0, 5)) {
            case 0: case 1: case 2: Reply(NetMsg::Make(NetMsgType::PONG, nonce)); break;
            case 3: Reply(NetMsg::Make(NetMsgType::PONG, nonce ^ 1)); break;
            case 4: {
                auto p{NetMsg::Make(NetMsgType::PONG, nonce)};
                p.data.resize(m_fdp.ConsumeIntegralInRange<size_t>(0, 7));
                Reply(std::move(p));
                break;
            }
            default: break; // withhold the PONG
            }
            if (m_fdp.ConsumeIntegralInRange<int>(0, 7) == 0) m_closed = true;
        }
    }

    FuzzedDataProvider& m_fdp;
    const std::unique_ptr<Transport> m_peer;
    const CTransactionRef m_tx;
    PeerStats& m_stats;
    mutable std::deque<uint8_t> m_to_tool;
    mutable std::deque<CSerializedNetMsg> m_pending;
    mutable bool m_closed{false};
    mutable bool m_inject_garbage{false};
    mutable int m_eagain_budget{3};
    mutable int m_stall_after;
    bool m_peer_is_garbage{false};
};

void initialize_privbcast_attempt()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

} // namespace

FUZZ_TARGET(privbcast_attempt, .init = initialize_privbcast_attempt)
{
    // RunAttempt draws its VERSION and PING nonces from a fresh FastRandomContext, which seeds
    // from the global PRNG. Pin it, and mock the clock: time then passes only when the scripted
    // peer stays silent (see ScriptedPeerSock::Recv) or the proxy is scripted slow, so every
    // deadline path is reached by the script, never by the host's speed.
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(std::chrono::seconds{1'700'000'000});
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    CTransactionRef tx{FallbackTx()};
    if (fdp.ConsumeBool()) {
        if (const auto mtx{ConsumeDeserializable<CMutableTransaction>(fdp, TX_WITH_WITNESS)}) tx = MakeTransactionRef(*mtx);
    }
    const bool onion{fdp.ConsumeBool()};
    Candidate cand;
    cand.source = onion ? Source::BUNDLED : Source::DNS_SEED;
    cand.provenance = onion ? "bundled" : "fuzz.seed.";
    cand.addr = ConsumeService(fdp);

    // The peer speaks v2, speaks only v1 (facing our v2 handshake it closes without a byte), or
    // emits pure garbage.
    const int peer_kind{fdp.ConsumeIntegralInRange<int>(0, 5)};
    std::unique_ptr<Transport> peer_transport;
    if (peer_kind <= 3) {
        peer_transport = std::make_unique<V2Transport>(NodeId{1}, /*initiating=*/false);
    } else {
        peer_transport = std::make_unique<V1Transport>(NodeId{1});
    }
    PeerStats stats;
    auto sock{std::make_unique<ScriptedPeerSock>(fdp, std::move(peer_transport), tx, stats)};
    if (peer_kind == 5) sock->SetGarbagePeer();

    const int connect_mode{fdp.ConsumeIntegralInRange<int>(0, 15)};
    bool connector_called{false};
    bool connected{false};
    const Connector connect = [&](bool& proxy_failed) -> std::unique_ptr<Sock> {
        connector_called = true;
        if (connect_mode == 0) {
            proxy_failed = true;
            return nullptr;
        }
        if (connect_mode == 1) return nullptr;
        if (connect_mode == 2) SetMockTime(GetMockTime() + wire::HANDSHAKE_TIMEOUT + std::chrono::seconds{1}); // slow proxy
        connected = true;
        return std::move(sock);
    };

    const auto now{Clock::now()};
    const auto scheduled_start{now - std::chrono::milliseconds{fdp.ConsumeBool() ? 0 : fdp.ConsumeIntegralInRange<int>(0, 100)}};
    // Already expired, far away, or cutting into the exchange (the scaled phases take tens of ms).
    const auto hard_deadline{[&] {
        switch (fdp.ConsumeIntegralInRange<int>(0, 7)) {
        case 0: return now - std::chrono::milliseconds{1};
        case 1: case 2: return now + std::chrono::milliseconds{fdp.ConsumeIntegralInRange<int>(1, 150)};
        default: return now + std::chrono::seconds{5};
        }
    }()};
    int calls_until_interrupt{fdp.ConsumeIntegralInRange<int>(0, 7) == 0 ? fdp.ConsumeIntegralInRange<int>(0, 60) : -1};
    const auto interrupted = [&] {
        if (calls_until_interrupt < 0) return false;
        if (calls_until_interrupt == 0) return true;
        --calls_until_interrupt;
        return false;
    };

    // The dial deadline: within grace of the scheduled start, or already passed.
    const auto dial_deadline{fdp.ConsumeBool() ? scheduled_start + Scaled(std::chrono::seconds{5}) : now - std::chrono::milliseconds{1}};
    const auto maybe{RunAttempt(connect, cand, tx, scheduled_start, dial_deadline, hard_deadline, interrupted)};
    if (!maybe) {
        // Not dialled: the job was cancelled or the grace had passed. The connector never ran.
        assert(!connector_called && !connected && stats.messages_seen == 0);
        return;
    }
    const AttemptResult& res{*maybe};

    assert(res.outcome != Outcome::PENDING);
    assert(res.ended >= res.started);
    assert(res.scheduled_start == scheduled_start);
    assert(IsPostAnnouncement(res.outcome) == res.evidence.inv_handed.has_value());
    if (!connected) assert(!res.connected && res.bytes_sent == 0 && res.bytes_recv == 0 && stats.messages_seen == 0);
    if (res.connected) assert(*res.connected >= res.started && *res.connected <= res.ended);
    assert(res.bytes_recv <= wire::MAX_RECV_BYTES + 0x4000);
    // The tool announces and serves the transaction at most once each, whatever the peer asked for.
    assert(stats.tx_seen <= 1);
    assert(stats.inv_seen <= 1);
    const auto& ev{res.evidence};
    if (ev.inv_written) assert(ev.inv_handed && *ev.inv_handed <= *ev.inv_written);
    if (ev.getdata_received) assert(ev.inv_handed);
    if (ev.tx_written) assert(ev.getdata_received);
    if (ev.ping_written) assert(ev.tx_written);
    if (ev.pong_received) assert(ev.ping_written && res.outcome == Outcome::PONG_RECEIVED); // the session ignores a PONG before its PING is written
    if (res.outcome == Outcome::PONG_RECEIVED) assert(ev.pong_received);
    if (res.outcome == Outcome::TX_WRITTEN_NO_PONG) assert(ev.ping_written && !ev.pong_received);
    if (res.outcome == Outcome::ANNOUNCED_NOT_REQUESTED) assert(!ev.getdata_received);
    // Evidence timestamps advance monotonically along the one protocol path, all after the connect.
    if (ev.inv_handed) assert(res.connected && *res.connected <= *ev.inv_handed);
    if (ev.version_received && ev.inv_handed) assert(*ev.version_received <= *ev.inv_handed);
    if (ev.inv_handed && ev.getdata_received) assert(*ev.inv_handed <= *ev.getdata_received);
    if (ev.getdata_received && ev.tx_written) assert(*ev.getdata_received <= *ev.tx_written);
    if (ev.tx_written && ev.ping_written) assert(*ev.tx_written <= *ev.ping_written);
    if (ev.ping_written && ev.pong_received) assert(*ev.ping_written <= *ev.pong_received);
}
