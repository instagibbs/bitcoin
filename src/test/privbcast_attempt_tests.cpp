// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>
#include <key.h>
#include <net_transport.h>
#include <netaddress.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/params.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>
#include <test/util/privbcast.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace privbcast;
using namespace std::chrono_literals;
using std::chrono::milliseconds;

namespace {

/** The opportunity's scheduled start, for every attempt here. */
constexpr milliseconds START{18s};
/** Services of a peer that passes E2. */
constexpr uint64_t PEER_SERVICES{NODE_NETWORK | NODE_WITNESS};

using Types = std::vector<std::string>;

CTransactionRef MakeTx()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{7}), 1});
    tx.vin[0].scriptWitness.stack.push_back({1, 2, 3});
    tx.vout.emplace_back(10'000, CScript{} << OP_TRUE);
    return MakeTransactionRef(std::move(tx));
}

CSerializedNetMsg Msg(std::string type, std::vector<uint8_t> payload = {})
{
    CSerializedNetMsg msg;
    msg.m_type = std::move(type);
    msg.data = std::move(payload);
    return msg;
}

CSerializedNetMsg Version(int version = 70016, uint64_t services = PEER_SERVICES, bool relay = true,
                          const std::string& user_agent = "/Satoshi:30.0.0/")
{
    return NetMsg::Make(NetMsgType::VERSION, version, services, int64_t{1'700'000'000},
                        uint64_t{NODE_NONE}, CNetAddr::V1(CService{}), services, CNetAddr::V1(CService{}),
                        uint64_t{0x0123456789abcdef}, user_agent, int32_t{900'000}, relay);
}

CSerializedNetMsg GetData(std::vector<CInv> request) { return NetMsg::Make(NetMsgType::GETDATA, request); }

CSerializedNetMsg Pong(uint64_t nonce) { return NetMsg::Make(NetMsgType::PONG, nonce); }

uint64_t Nonce(const std::vector<uint8_t>& ping)
{
    uint64_t nonce{0};
    DataStream{ping} >> nonce;
    return nonce;
}

/** A BIP324 responder with its key and garbage drawn from rng. */
V2Transport MakeResponder(FastRandomContext& rng)
{
    CKey key;
    do {
        const uint256 secret{rng.rand256()};
        key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
    } while (!key.IsValid());
    const uint256 ent{rng.rand256()};
    std::vector<uint8_t> garbage{rng.randbytes(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1))};
    return V2Transport{NodeId{1}, /*initiating=*/false, key, MakeByteSpan(ent), std::move(garbage)};
}

/** A message the peer decoded. */
struct Message {
    std::string type;
    std::vector<uint8_t> payload;
};

/** The recipient's end of an attempt's connection: a BIP324 responder, as a node runs one. It
 *  decodes what the attempt writes and sends the messages a test scripts. */
class Peer
{
public:
    explicit Peer(FastRandomContext& rng) : m_transport(MakeResponder(rng)) {}

    /** Queue a message for the attempt. */
    void Send(CSerializedNetMsg msg) { m_queue.push_back(std::move(msg)); }

    /** Pass up to max of the peer's bytes to the attempt at now. Returns how many. */
    size_t Deliver(Attempt& attempt, milliseconds now, size_t max = std::numeric_limits<size_t>::max())
    {
        size_t total{0};
        while (total < max) {
            if (!m_queue.empty() && m_transport.SetMessageToSend(m_queue.front())) m_queue.pop_front();
            const auto& [bytes, _more, _type]{m_transport.GetBytesToSend(/*have_next_message=*/!m_queue.empty())};
            if (bytes.empty()) break;
            const std::vector<uint8_t> chunk{bytes.begin(), bytes.begin() + std::min(bytes.size(), max - total)};
            m_transport.MarkBytesSent(chunk.size());
            attempt.Received(chunk, now);
            total += chunk.size();
            m_delivered += chunk.size();
        }
        return total;
    }

    /** Write up to max of the bytes the attempt offers, marking them sent at now, and decode them.
     *  Returns how many. */
    size_t Read(Attempt& attempt, milliseconds now, size_t max = std::numeric_limits<size_t>::max())
    {
        size_t total{0};
        while (total < max) {
            const std::span<const uint8_t> offered{attempt.BytesToSend()};
            if (offered.empty()) break;
            const std::vector<uint8_t> chunk{offered.begin(), offered.begin() + std::min(offered.size(), max - total)};
            attempt.MarkSent(chunk.size(), now);
            total += chunk.size();
            m_wire.insert(m_wire.end(), chunk.begin(), chunk.end());
            std::span<const uint8_t> rest{chunk};
            while (!rest.empty()) {
                BOOST_REQUIRE(m_transport.ReceivedBytes(rest));
                if (!m_transport.ReceivedMessageComplete()) continue;
                bool reject{false};
                CNetMessage msg{m_transport.GetReceivedMessage({}, reject)};
                BOOST_REQUIRE(!reject);
                const auto payload{MakeUCharSpan(msg.m_recv)};
                m_received.push_back({msg.m_type, {payload.begin(), payload.end()}});
            }
        }
        return total;
    }

    /** Write the message the attempt's transport holds, which goes out in full before the next. */
    size_t ReadMessage(Attempt& attempt, milliseconds now) { return Read(attempt, now, attempt.BytesToSend().size()); }

    /** Both ways, until neither side has anything left to write. */
    void Exchange(Attempt& attempt, milliseconds now)
    {
        while (Read(attempt, now) + Deliver(attempt, now) > 0) {}
    }

    const std::vector<Message>& Received() const { return m_received; }
    Types ReceivedTypes() const
    {
        Types types;
        for (const Message& msg : m_received) types.push_back(msg.type);
        return types;
    }
    /** Every byte the attempt wrote. */
    const std::vector<uint8_t>& Wire() const { return m_wire; }
    /** Every byte passed to the attempt. */
    uint64_t Delivered() const { return m_delivered; }

private:
    V2Transport m_transport;
    std::deque<CSerializedNetMsg> m_queue;
    std::vector<Message> m_received;
    std::vector<uint8_t> m_wire;
    uint64_t m_delivered{0};
};

/** Connect at `at` and run the handshake with a peer that passes E2: the INV is handed and written
 *  at `at`. */
void Announce(Attempt& attempt, Peer& peer, milliseconds at)
{
    attempt.Connected(at);
    peer.Exchange(attempt, at);
    peer.Send(Version());
    peer.Send(Msg(NetMsgType::WTXIDRELAY));
    peer.Send(Msg(NetMsgType::VERACK));
    peer.Exchange(attempt, at);
    BOOST_REQUIRE(attempt.Times().inv_handed == at);
    BOOST_REQUIRE(attempt.Times().inv_written == at);
}

const Types HANDSHAKE{NetMsgType::VERSION, NetMsgType::WTXIDRELAY, NetMsgType::VERACK};
const Types ANNOUNCED{NetMsgType::VERSION, NetMsgType::WTXIDRELAY, NetMsgType::VERACK, NetMsgType::INV};
const Types SERVED{NetMsgType::VERSION, NetMsgType::WTXIDRELAY, NetMsgType::VERACK, NetMsgType::INV,
                   NetMsgType::TX, NetMsgType::PING};

struct AttemptSetup : public BasicTestingSetup {
    const CTransactionRef tx{MakeTx()};
    const uint256 wtxid{tx->GetWitnessHash().ToUint256()};
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(privbcast_attempt_tests, AttemptSetup)

BOOST_AUTO_TEST_CASE(peer_version)
{
    // E2: a low version, no NODE_WITNESS or no relay ends the attempt; it sent only its VERSION.
    FastRandomContext rng{uint256{2}};
    struct Case {
        int version;
        uint64_t services;
        bool relay;
    };
    for (const Case& c : {Case{70015, PEER_SERVICES, true}, Case{70016, NODE_NETWORK, true}, Case{70016, PEER_SERVICES, false}}) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(Version(c.version, c.services, c.relay));
        peer.Send(Msg(NetMsgType::WTXIDRELAY));
        peer.Send(Msg(NetMsgType::VERACK));
        peer.Exchange(attempt, START + 1s);
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.GetOutcome() == Outcome::NotAnnounced);
        BOOST_CHECK(attempt.Times().ended == START + 1s);
        BOOST_CHECK(peer.ReceivedTypes() == Types{NetMsgType::VERSION});
        BOOST_CHECK(attempt.BytesToSend().empty());
    }

    // A good VERSION is answered with WTXIDRELAY, then VERACK, and nothing else.
    {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(Version());
        peer.Exchange(attempt, START + 1s);
        BOOST_CHECK(peer.ReceivedTypes() == HANDSHAKE);
        attempt.Tick(START + 10s);
        peer.Exchange(attempt, START + 10s);
        BOOST_CHECK(!attempt.Ended());
        BOOST_CHECK(peer.ReceivedTypes() == HANDSHAKE);
    }

    // The peer's VERACK without a WTXIDRELAY before it ends the attempt. A WTXIDRELAY after the
    // VERACK does not count, nor does one before the VERSION.
    const std::vector<Types> scripts{
        {NetMsgType::VERSION, NetMsgType::VERACK},
        {NetMsgType::VERSION, NetMsgType::VERACK, NetMsgType::WTXIDRELAY},
        {NetMsgType::WTXIDRELAY, NetMsgType::VERSION, NetMsgType::VERACK},
    };
    for (const Types& script : scripts) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        for (const std::string& type : script) {
            peer.Send(type == NetMsgType::VERSION ? Version() : Msg(type));
            peer.Exchange(attempt, START + 1s);
        }
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.GetOutcome() == Outcome::NotAnnounced);
        BOOST_CHECK(!attempt.Times().inv_handed);
        BOOST_CHECK(peer.ReceivedTypes() == HANDSHAKE);
    }
}

BOOST_AUTO_TEST_CASE(getdata_before_announcement)
{
    // E4: a GETDATA before the announcement point is ignored and not counted.
    FastRandomContext rng{uint256{4}};
    const CInv request{MSG_WTX, wtxid};
    {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(GetData({request}));
        peer.Send(Version());
        peer.Send(GetData({request}));
        peer.Send(Msg(NetMsgType::WTXIDRELAY));
        peer.Send(GetData({request}));
        peer.Exchange(attempt, START + 1s);
        BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 0);
        BOOST_CHECK(!attempt.Times().getdata);
        peer.Send(Msg(NetMsgType::VERACK));
        peer.Exchange(attempt, START + 2s);
        BOOST_CHECK(peer.ReceivedTypes() == ANNOUNCED);
        BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 0);
        // They did not use up the one request that is served.
        peer.Send(GetData({request}));
        peer.Exchange(attempt, START + 3s);
        BOOST_CHECK(attempt.Times().getdata == START + 3s);
        BOOST_CHECK(peer.ReceivedTypes() == SERVED);
    }
    {
        // After the peer's VERACK, while the INV waits for the attempt's VERACK to be written.
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(Version());
        peer.Send(Msg(NetMsgType::WTXIDRELAY));
        peer.Send(Msg(NetMsgType::VERACK));
        peer.Send(GetData({request}));
        peer.Deliver(attempt, START + 1s);
        BOOST_CHECK(!attempt.Times().inv_handed);
        peer.Exchange(attempt, START + 2s);
        BOOST_CHECK(attempt.Times().inv_handed == START + 2s);
        BOOST_CHECK(peer.ReceivedTypes() == ANNOUNCED);
        BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 0);
        BOOST_CHECK(!attempt.Times().getdata);
    }
}

BOOST_AUTO_TEST_CASE(getdata_while_inv_is_written)
{
    // E4: a GETDATA after the INV was handed, before its last byte went, is served after the INV.
    FastRandomContext rng{uint256{5}};
    Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
    Peer peer{rng};
    attempt.Connected(START);
    peer.Exchange(attempt, START);
    peer.Send(Version());
    peer.Send(Msg(NetMsgType::WTXIDRELAY));
    peer.Send(Msg(NetMsgType::VERACK));
    peer.Deliver(attempt, START + 1s);
    peer.ReadMessage(attempt, START + 1s); // WTXIDRELAY
    peer.ReadMessage(attempt, START + 1s); // VERACK
    BOOST_REQUIRE(attempt.Times().inv_handed == START + 1s);
    BOOST_CHECK_EQUAL(peer.Read(attempt, START + 1s, 1), 1U);
    BOOST_CHECK(!attempt.Times().inv_written);
    peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
    peer.Deliver(attempt, START + 2s);
    BOOST_CHECK(attempt.Times().getdata == START + 2s);
    BOOST_CHECK(peer.ReceivedTypes() == HANDSHAKE);
    peer.Exchange(attempt, START + 3s);
    BOOST_CHECK(peer.ReceivedTypes() == SERVED);
    BOOST_CHECK(attempt.Times().inv_written == START + 3s);
    BOOST_CHECK(attempt.Times().tx_written == START + 3s);
}

BOOST_AUTO_TEST_CASE(served_then_malformed_getdata)
{
    // E5, E7: once served, an undecodable GETDATA is only counted; the attempt goes on to its PONG.
    FastRandomContext rng{uint256{17}};
    Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
    Peer peer{rng};
    Announce(attempt, peer, START);
    peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
    peer.Deliver(attempt, START + 1s);
    BOOST_REQUIRE(attempt.Times().getdata == START + 1s);
    // A count of one entry, and no entry.
    peer.Send(Msg(NetMsgType::GETDATA, {0x01}));
    peer.Deliver(attempt, START + 1s);
    BOOST_CHECK(!attempt.Ended());
    BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 1);
    BOOST_CHECK(!attempt.Times().tx_written);
    peer.Exchange(attempt, START + 2s);
    BOOST_REQUIRE(peer.ReceivedTypes() == SERVED);
    // A count cut short.
    peer.Send(Msg(NetMsgType::GETDATA, {0xfd, 0x01}));
    peer.Exchange(attempt, START + 3s);
    BOOST_CHECK(!attempt.Ended());
    BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 2);
    peer.Send(Pong(Nonce(peer.Received().back().payload)));
    peer.Exchange(attempt, START + 4s);
    BOOST_CHECK(attempt.GetOutcome() == Outcome::PongReceived);
    BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 2);
    BOOST_CHECK(peer.ReceivedTypes() == SERVED);
}

BOOST_AUTO_TEST_CASE(ignored_messages)
{
    // E7: messages of other kinds, or out of order, are ignored and answered with nothing.
    FastRandomContext rng{uint256{9}};
    Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
    Peer peer{rng};
    attempt.Connected(START);
    peer.Exchange(attempt, START);
    const auto noise{[&] {
        peer.Send(NetMsg::Make(NetMsgType::PING, uint64_t{7}));
        peer.Send(NetMsg::Make(NetMsgType::SENDTXRCNCL, uint32_t{1}, uint64_t{2}));
        peer.Send(Msg(NetMsgType::ADDR, {0x00}));
        peer.Send(Msg("unknowncmd", {1, 2, 3}));
    }};
    peer.Send(Msg(NetMsgType::VERACK));
    noise();
    peer.Exchange(attempt, START + 1s);
    BOOST_CHECK(!attempt.Ended());
    BOOST_CHECK(peer.ReceivedTypes() == Types{NetMsgType::VERSION});
    peer.Send(Version());
    noise();
    peer.Send(Msg(NetMsgType::WTXIDRELAY));
    noise();
    peer.Send(Msg(NetMsgType::VERACK));
    noise();
    peer.Exchange(attempt, START + 2s);
    BOOST_CHECK(attempt.Times().inv_handed == START + 2s);
    BOOST_CHECK(peer.ReceivedTypes() == ANNOUNCED);
    BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 0);
    BOOST_CHECK(!attempt.Ended());
}

BOOST_AUTO_TEST_CASE(deadlines)
{
    // D2: a GETDATA read at the end of the request window is not processed, with or without a
    // Tick first; without one its bytes still count as read (D3).
    FastRandomContext rng{uint256{11}};
    for (const bool tick : {true, false}) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        const milliseconds announced{START + 1ms};
        Announce(attempt, peer, announced);
        const milliseconds deadline{announced + REQUEST_WINDOW};
        BOOST_CHECK(attempt.NextDeadline() == deadline);
        attempt.Tick(deadline - 1ms);
        BOOST_CHECK(!attempt.Ended());
        if (tick) attempt.Tick(deadline);
        const uint64_t before{peer.Delivered()};
        BOOST_REQUIRE_EQUAL(attempt.BytesRecv(), before);
        peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
        peer.Exchange(attempt, deadline);
        BOOST_REQUIRE(peer.Delivered() > before);
        BOOST_CHECK_EQUAL(attempt.BytesRecv(), tick ? before : peer.Delivered());
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.GetOutcome() == Outcome::AnnouncedNotRequested);
        BOOST_CHECK(attempt.Times().ended == deadline);
        BOOST_CHECK(!attempt.Times().getdata);
        BOOST_CHECK_EQUAL(attempt.ExtraRequests(), 0);
        BOOST_CHECK(peer.ReceivedTypes() == ANNOUNCED);
    }
}

BOOST_AUTO_TEST_CASE(requested_not_written)
{
    // E6: at the request window's end, a TX not written is a failure after the announcement
    // point; a TX written without the PING is tx_written_no_pong.
    FastRandomContext rng{uint256{18}};
    const milliseconds deadline{START + REQUEST_WINDOW};
    for (const bool tx_written : {false, true}) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        Announce(attempt, peer, START);
        peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
        peer.Deliver(attempt, START + 1s);
        BOOST_REQUIRE(attempt.Times().getdata == START + 1s);
        if (tx_written) peer.ReadMessage(attempt, START + 1s);
        // The TX, or the PING, written but for its last byte.
        peer.Read(attempt, START + 1s, attempt.BytesToSend().size() - 1);
        attempt.Tick(deadline - 1ms);
        BOOST_CHECK(!attempt.Ended());
        attempt.Tick(deadline);
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.Times().ended == deadline);
        BOOST_CHECK_EQUAL(attempt.Times().tx_written.has_value(), tx_written);
        BOOST_CHECK(!attempt.Times().ping_written);
        if (tx_written) {
            BOOST_CHECK(attempt.GetOutcome() == Outcome::TxWrittenNoPong);
            BOOST_CHECK_EQUAL(attempt.Reason(), "PING not written in the request window");
        } else {
            BOOST_CHECK(attempt.GetOutcome() == Outcome::PostAnnouncementFailure);
            BOOST_CHECK_EQUAL(attempt.Reason(), "TX not written in the request window");
        }
        BOOST_CHECK(attempt.BytesToSend().empty());
    }
}

BOOST_AUTO_TEST_CASE(receive_cap)
{
    // D3: every byte read counts, the handshake's too; the first past the cap ends the attempt.
    FastRandomContext rng{uint256{12}};
    for (const bool announced : {false, true}) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(Version());
        peer.Send(Msg(NetMsgType::WTXIDRELAY));
        if (announced) peer.Send(Msg(NetMsgType::VERACK));
        peer.Exchange(attempt, START);
        BOOST_CHECK_EQUAL(attempt.Times().inv_handed.has_value(), announced);
        BOOST_CHECK_EQUAL(attempt.BytesRecv(), peer.Delivered());
        BOOST_CHECK_EQUAL(attempt.BytesSent(), peer.Wire().size());
        // A message the attempt ignores, sized to reach the cap exactly: its payload, the long
        // encoding of its type, and BIP324's length, header and tag.
        const uint64_t overhead{1 + CMessageHeader::MESSAGE_TYPE_SIZE + BIP324Cipher::EXPANSION};
        peer.Send(Msg("filler", std::vector<uint8_t>(MAX_RECV_BYTES - attempt.BytesRecv() - overhead)));
        peer.Exchange(attempt, START + 1s);
        BOOST_CHECK_EQUAL(attempt.BytesRecv(), MAX_RECV_BYTES);
        BOOST_CHECK(!attempt.Ended());
        peer.Send(Msg("filler"));
        BOOST_CHECK_EQUAL(peer.Deliver(attempt, START + 2s, 1), 1U);
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.GetOutcome() == (announced ? Outcome::PostAnnouncementFailure : Outcome::NotAnnounced));
        BOOST_CHECK(attempt.Times().ended == START + 2s);
        BOOST_CHECK_EQUAL(attempt.BytesRecv(), MAX_RECV_BYTES + 1);
        BOOST_CHECK_EQUAL(attempt.BytesSent(), peer.Wire().size());
    }
}

BOOST_AUTO_TEST_CASE(written_at_last_byte)
{
    // H2: inv_written, tx_written and ping_written are set when the last byte is marked sent.
    FastRandomContext rng{uint256{13}};
    Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
    Peer peer{rng};
    attempt.Connected(START);
    peer.Exchange(attempt, START);
    peer.Send(Version());
    peer.Send(Msg(NetMsgType::WTXIDRELAY));
    peer.Send(Msg(NetMsgType::VERACK));
    peer.Deliver(attempt, START);
    peer.ReadMessage(attempt, START);
    peer.ReadMessage(attempt, START);
    BOOST_REQUIRE(attempt.Times().inv_handed == START);

    milliseconds now{START};
    const auto written{[&](const std::optional<milliseconds> AttemptTimes::*field) {
        const size_t size{attempt.BytesToSend().size()};
        BOOST_REQUIRE(size > 2);
        BOOST_CHECK_EQUAL(peer.Read(attempt, now += 1ms, 1), 1U);
        BOOST_CHECK(!(attempt.Times().*field));
        BOOST_CHECK_EQUAL(peer.Read(attempt, now += 1ms, size - 2), size - 2);
        BOOST_CHECK(!(attempt.Times().*field));
        BOOST_CHECK_EQUAL(peer.Read(attempt, now += 1ms, 1), 1U);
        BOOST_CHECK(attempt.Times().*field == now);
    }};
    written(&AttemptTimes::inv_written);
    peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
    peer.Deliver(attempt, now);
    written(&AttemptTimes::tx_written);
    written(&AttemptTimes::ping_written);
    BOOST_CHECK(peer.ReceivedTypes() == SERVED);
}

BOOST_AUTO_TEST_CASE(written_at_deadline)
{
    // H2, D2: a last byte written at the request window's end counts, and the attempt ends there.
    FastRandomContext rng{uint256{16}};
    const milliseconds deadline{START + REQUEST_WINDOW};
    struct Case {
        std::string last;
        std::optional<milliseconds> AttemptTimes::*written;
        Outcome outcome;
    };
    for (const Case& c : {Case{NetMsgType::INV, &AttemptTimes::inv_written, Outcome::AnnouncedNotRequested},
                          Case{NetMsgType::TX, &AttemptTimes::tx_written, Outcome::TxWrittenNoPong},
                          Case{NetMsgType::PING, &AttemptTimes::ping_written, Outcome::TxWrittenNoPong}}) {
        Attempt attempt{tx, START, Timing{}, rng, KeysFrom(rng), NodeId{0}};
        Peer peer{rng};
        attempt.Connected(START);
        peer.Exchange(attempt, START);
        peer.Send(Version());
        peer.Send(Msg(NetMsgType::WTXIDRELAY));
        peer.Send(Msg(NetMsgType::VERACK));
        peer.Deliver(attempt, START);
        peer.ReadMessage(attempt, START); // WTXIDRELAY
        peer.ReadMessage(attempt, START); // VERACK
        BOOST_REQUIRE(attempt.Times().inv_handed == START);
        if (c.last != NetMsgType::INV) {
            peer.ReadMessage(attempt, START); // INV
            peer.Send(GetData({CInv{MSG_WTX, wtxid}}));
            peer.Deliver(attempt, START);
            if (c.last == NetMsgType::PING) peer.ReadMessage(attempt, START); // TX
        }
        // All of the message but its last byte, which goes at the deadline.
        peer.Read(attempt, START, attempt.BytesToSend().size() - 1);
        BOOST_CHECK(!(attempt.Times().*c.written));
        BOOST_CHECK_EQUAL(peer.Read(attempt, deadline, 1), 1U);
        BOOST_CHECK(attempt.Times().*c.written == deadline);
        BOOST_CHECK(attempt.Ended());
        BOOST_CHECK(attempt.GetOutcome() == c.outcome);
        BOOST_CHECK(attempt.Times().ended == deadline);
        BOOST_CHECK(!attempt.NextDeadline());
        BOOST_CHECK(attempt.BytesToSend().empty());
        BOOST_REQUIRE(!peer.Received().empty());
        BOOST_CHECK_EQUAL(peer.Received().back().type, c.last);
        BOOST_CHECK_EQUAL(attempt.BytesSent(), peer.Wire().size());
    }
}

BOOST_AUTO_TEST_CASE(keys_from_strong_rng)
{
    // A4: without a key source, as in production, the key comes from the strong RNG, not from rng.
    const uint256 seed{1};
    FastRandomContext rng_a{seed};
    FastRandomContext rng_b{seed};
    Attempt a{tx, START, Timing{}, rng_a, KeySource{}, NodeId{0}};
    Attempt b{tx, START, Timing{}, rng_b, KeySource{}, NodeId{0}};
    a.Connected(START);
    b.Connected(START);
    BOOST_REQUIRE(a.BytesToSend().size() >= 64 && b.BytesToSend().size() >= 64);
    BOOST_CHECK(!std::ranges::equal(a.BytesToSend().first(64), b.BytesToSend().first(64)));
}

BOOST_AUTO_TEST_SUITE_END()
