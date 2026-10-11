// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// End-to-end liveness of parent and child relay (opportunistic 1p1c package relay and orphan
// handling) against adversarial peers, driving a real PeerManager with real P2P messages and real
// validation.
//
// Property: if an honest peer announces the child of an acceptable parent and child, the child ends
// up in our mempool, whatever other peers do. The parent may be too low-fee on its own (1p1c relay)
// or not (the child is then an orphan until the parent arrives). The honest peer may first announce
// versions of the child that do not pay for the pair, each replaced by the next, as a wallet bumping
// the fee would; the property is then about the last version. Adversaries hold no keys: they may
// announce, deliver the parent, any child version or the confirmed transaction funding the child as
// is, stripped of its witness, inflated or with a freely mutated witness, deliver a fake child of
// the parent, send notfound, stall, disconnect and reconnect. The parent may also leave the mempool
// before the child is accepted.
//
// Nothing below PeerManager is modelled: message handling, transaction download, validation ordering
// and result attribution are the production code paths, and the adversary's malleations of the cast
// transactions are not limited to a fixed set. The cast itself is fixed: P2WSH inputs, children in
// three fee versions with one confirmed fee input (an output of an ordinary confirmed transaction, or
// of a coinbase). The oracle is coarse (mempool membership) and each execution pays for real
// validation. Not modelled: the orphanage reaching its limits, and the tip changing during a run.

#include <addresstype.h>
#include <addrman.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <kernel/mempool_removal_reason.h>
#include <net.h>
#include <net_processing.h>
#include <node/txdownloadman.h>
#include <netmessagemaker.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using namespace std::chrono_literals;

TestChain100Setup* g_setup;

/** Coins are P2WSH of {OP_DROP OP_TRUE}, spent with a 64-byte dummy item, so that the witness carries
 * enough weight for stripping it to change the feerate materially. */
const CScript WITNESS_SCRIPT_DROP_TRUE{CScript() << OP_DROP << OP_TRUE};
const CScript P2WSH_DROP_TRUE{GetScriptForDestination(WitnessV0ScriptHash(WITNESS_SCRIPT_DROP_TRUE))};
const std::vector<unsigned char> WITNESS_DUMMY(64, 0);

struct Cast {
    CTransactionRef parent;
    //! Versions of the child, from the parent's output and an output of `confirmed`, each replacing the
    //! previous one with a higher fee. Only the last pays for the pair.
    std::vector<CTransactionRef> children;
    CTransactionRef fake_child; //!< spends the parent and an unknown outpoint
    CTransactionRef confirmed;  //!< confirmed transaction funding the child: CONFIRMED_PARENT, or a coinbase
};
std::vector<Cast> CASTS;
/** Confirmed transaction whose outputs fund half of the children (the other half spend a coinbase output).
 * Confirmed longer ago than the recently-confirmed filter remembers (a fresh PeerManager per input has an
 * empty one), with its outputs in the coins cache. */
CTransactionRef CONFIRMED_PARENT;

CTransactionRef MakeTx(uint32_t version, const std::vector<COutPoint>& inputs, const std::vector<CAmount>& amounts_out)
{
    CMutableTransaction mtx;
    mtx.version = version;
    for (const auto& outpoint : inputs) {
        mtx.vin.emplace_back(outpoint);
        mtx.vin.back().scriptWitness.stack = {WITNESS_DUMMY, std::vector<unsigned char>(WITNESS_SCRIPT_DROP_TRUE.begin(), WITNESS_SCRIPT_DROP_TRUE.end())};
    }
    for (const auto amount : amounts_out) mtx.vout.emplace_back(amount, P2WSH_DROP_TRUE);
    return MakeTransactionRef(mtx);
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();

    // A parent of ~112 vbytes with its witness and ~94 without: 10 sat is below the minimum relay
    // feerate with the witness and above it without, and 200 sat pays for the parent on its own.
    const std::vector<CAmount> parent_fees{0, 10, 200};
    // A child of ~170 vbytes: with 5 or 15 sat the pair stays below the minimum relay feerate for the
    // first two parent fees, and the child alone is below it next to the third; 100 sat pays for all.
    const std::vector<CAmount> child_fees{5, 15, 100};
    const std::vector<uint32_t> versions{2, 3};
    const size_t num_shapes{versions.size() * parent_fees.size()};

    // Coinbases: a parent input per cast (two casts per shape: child funded by CONFIRMED_PARENT or by a
    // coinbase), a funding coinbase per coinbase-funded cast, and the input of CONFIRMED_PARENT.
    std::vector<CTransactionRef> coinbases;
    for (size_t i = 0; i < 3 * num_shapes + 1; ++i) {
        const CBlock block{g_setup->CreateAndProcessBlock({}, P2WSH_DROP_TRUE)};
        coinbases.push_back(block.vtx.at(0));
    }
    g_setup->mineBlocks(COINBASE_MATURITY);
    const CAmount coinbase_value{50 * COIN};
    // CONFIRMED_PARENT: one output per shape, confirmed in its own block.
    constexpr CAmount CONFIRMED_OUTPUT{5 * COIN};
    CONFIRMED_PARENT = MakeTx(2, {COutPoint{coinbases.at(3 * num_shapes)->GetHash(), 0}}, std::vector<CAmount>(num_shapes, CONFIRMED_OUTPUT));
    const CBlock confirmed_block{g_setup->CreateAndProcessBlock({CMutableTransaction{*CONFIRMED_PARENT}}, P2WSH_DROP_TRUE)};
    Assert(confirmed_block.vtx.size() == 2);
    Assert(WITH_LOCK(cs_main, return g_setup->m_node.chainman->ActiveChainstate().CoinsTip().HaveCoin(COutPoint{CONFIRMED_PARENT->GetHash(), 0})));

    size_t shape{0};
    for (const uint32_t version : versions) {
        for (const CAmount parent_fee : parent_fees) {
            for (const bool coinbase_funded : {false, true}) {
                Cast cast;
                cast.parent = MakeTx(version, {COutPoint{coinbases.at(shape + (coinbase_funded ? num_shapes : 0))->GetHash(), 0}}, {coinbase_value - parent_fee});
                cast.confirmed = coinbase_funded ? coinbases.at(2 * num_shapes + shape) : CONFIRMED_PARENT;
                const COutPoint funding{cast.confirmed->GetHash(), coinbase_funded ? 0 : static_cast<uint32_t>(shape)};
                const CAmount funding_value{coinbase_funded ? coinbase_value : CONFIRMED_OUTPUT};
                for (const CAmount child_fee : child_fees) {
                    cast.children.push_back(MakeTx(version, {COutPoint{cast.parent->GetHash(), 0}, funding}, {coinbase_value - parent_fee + funding_value - child_fee}));
                }
                cast.fake_child = MakeTx(version, {COutPoint{cast.parent->GetHash(), 0}, COutPoint{Txid::FromUint256(uint256::ONE), 0}}, {coinbase_value});
                CASTS.push_back(std::move(cast));
            }
            ++shape;
        }
    }
}

CNode* MakePeer(NodeId id, ConnectionType conn_type)
{
    in_addr address{};
    address.s_addr = htonl(0x0a000001U + static_cast<uint32_t>(id));
    return new CNode{id,
                     /*sock=*/nullptr,
                     CAddress{CService{address, static_cast<uint16_t>(18444 + id)}, NODE_NETWORK},
                     /*nKeyedNetGroupIn=*/static_cast<uint64_t>(id),
                     /*nLocalHostNonceIn=*/0,
                     CService{},
                     /*addrNameIn=*/"",
                     conn_type,
                     /*inbound_onion=*/false,
                     /*network_key=*/static_cast<uint64_t>(id + 1)};
}

/** Version handshake with wtxid relay negotiated. */
void Handshake(ConnmanTestMsg& connman, PeerManager& peerman, CNode& peer) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    constexpr ServiceFlags services{NODE_NETWORK | NODE_WITNESS};
    connman.Handshake(peer, /*successfully_connected=*/false, services, services, PROTOCOL_VERSION, /*relay_txs=*/true);
    Assert(connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::WTXIDRELAY)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    Assert(connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::VERACK)));
    peer.fPauseSend = false;
    (void)connman.ProcessMessagesOnce(peer);
    Assert(peerman.SendMessages(peer));
    Assert(peer.fSuccessfullyConnected);
    Assert(!peer.fDisconnect);
    connman.FlushSendBuffer(peer);
}

/** Take everything we sent to this peer, as (message type, payload), and clear the send buffers. */
std::vector<std::pair<std::string, std::vector<unsigned char>>> TakeSentMessages(CNode& node)
{
    std::vector<std::pair<std::string, std::vector<unsigned char>>> ret;
    LOCK(node.cs_vSend);
    // Messages already handed to the (v1) transport: re-parse the framing.
    std::vector<unsigned char> bytes;
    while (true) {
        const auto& [to_send, _more, _msg_type] = node.m_transport->GetBytesToSend(/*have_next_message=*/false);
        if (to_send.empty()) break;
        bytes.insert(bytes.end(), to_send.begin(), to_send.end());
        node.m_transport->MarkBytesSent(to_send.size());
    }
    size_t pos{0};
    while (pos + CMessageHeader::HEADER_SIZE <= bytes.size()) {
        std::span<const unsigned char> header{bytes.data() + pos, CMessageHeader::HEADER_SIZE};
        const auto type_begin{header.begin() + std::tuple_size_v<MessageStartChars>};
        std::string type{type_begin, std::find(type_begin, type_begin + CMessageHeader::MESSAGE_TYPE_SIZE, '\0')};
        const uint32_t size{ReadLE32(header.data() + CMessageHeader::MESSAGE_SIZE_OFFSET)};
        pos += CMessageHeader::HEADER_SIZE;
        Assert(pos + size <= bytes.size());
        ret.emplace_back(std::move(type), std::vector<unsigned char>(bytes.begin() + pos, bytes.begin() + pos + size));
        pos += size;
    }
    Assert(pos == bytes.size());
    // Messages still queued.
    for (auto& msg : node.vSendMsg) ret.emplace_back(std::move(msg.m_type), std::move(msg.data));
    node.vSendMsg.clear();
    node.m_send_memusage = 0;
    return ret;
}

/** Mutate the witness of the first input in ways that keep the txid. */
CTransactionRef MutateWitness(FuzzedDataProvider& fuzzed_data_provider, const CTransactionRef& tx)
{
    CMutableTransaction mtx{*tx};
    auto& stack{mtx.vin[0].scriptWitness.stack};
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 4) {
        CallOneOf(
            fuzzed_data_provider,
            [&] { stack.clear(); },
            [&] {
                // Pad with items of a chosen size (standard size or not).
                const auto num{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 150)};
                const auto size{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 100)};
                stack.insert(stack.begin(), num, std::vector<unsigned char>(size, fuzzed_data_provider.ConsumeIntegral<uint8_t>()));
            },
            [&] {
                // Replace the witness script with a script of sigop-heavy or arbitrary bytes.
                std::vector<unsigned char> script;
                if (fuzzed_data_provider.ConsumeBool()) {
                    script.assign(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000), OP_CHECKMULTISIG);
                } else {
                    script = ConsumeRandomLengthByteVector(fuzzed_data_provider, 200);
                }
                if (stack.empty()) stack.push_back(script); else stack.back() = script;
            },
            [&] {
                // Replace or add an arbitrary item.
                auto item{ConsumeRandomLengthByteVector(fuzzed_data_provider, 100)};
                if (stack.empty() || fuzzed_data_provider.ConsumeBool()) {
                    stack.insert(stack.begin(), std::move(item));
                } else {
                    stack.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, stack.size() - 1)) = std::move(item);
                }
            },
            [&] {
                // Another valid witness: OP_DROP accepts any dummy.
                if (stack.size() == 2) stack.front() = ConsumeRandomLengthByteVector(fuzzed_data_provider, 80);
            });
    }
    return MakeTransactionRef(mtx);
}

} // namespace

FUZZ_TARGET(p2p_1p1c_liveness, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node_ctx{g_setup->m_node};
    auto& chainman{static_cast<TestChainstateManager&>(*node_ctx.chainman)};
    auto& mempool{*node_ctx.mempool};
    Assert(mempool.size() == 0);
    chainman.ResetIbd();
    chainman.JumpOutOfIbd();
    const CBlockIndex* const active_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    NodeSeconds now{active_tip->Time() + 1s};
    g_setup->m_clock.set(now);

    const Cast& cast{PickValue(fuzzed_data_provider, CASTS)};
    std::vector<CTransactionRef> cast_txs{cast.parent, cast.fake_child, cast.confirmed};
    cast_txs.insert(cast_txs.end(), cast.children.begin(), cast.children.end());

    AddrMan addrman{*node_ctx.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0, 0, addrman, *node_ctx.netgroupman, Params()};
    auto peerman{PeerManager::make(connman, addrman, /*banman=*/nullptr, chainman, mempool, *node_ctx.warnings,
                                   PeerManager::Options{.deterministic_rng = true})};
    CConnman::Options connman_options;
    connman_options.m_msgproc = peerman.get();
    connman_options.m_peer_connect_timeout = 99999;
    connman.Init(connman_options);

    LOCK(NetEventsInterface::g_msgproc_mutex);
    NodeId next_id{0};
    const int num_adversaries{fuzzed_data_provider.ConsumeIntegralInRange(1, 3)};
    // peers[0] is the honest peer; the rest are adversaries. Disconnected adversaries are nullptr
    // until they reconnect (as a new node).
    std::vector<CNode*> peers;
    auto connect = [&](ConnectionType conn_type) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        CNode* peer{MakePeer(next_id++, conn_type)};
        connman.AddTestNode(*peer);
        Handshake(connman, *peerman, *peer);
        return peer;
    };
    const bool honest_outbound{fuzzed_data_provider.ConsumeBool()};
    peers.push_back(connect(honest_outbound ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND));
    // Adversaries may hold outbound slots too. Reconnections are inbound: an outbound slot an adversary
    // gives up is assumed refilled by a non-adversary.
    int adversary_outbounds{0};
    for (int i = 0; i < num_adversaries; ++i) {
        const bool outbound{fuzzed_data_provider.ConsumeBool()};
        adversary_outbounds += outbound;
        peers.push_back(connect(outbound ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND));
    }
    CNode* const honest{peers[0]};

    // The child version the honest peer holds: it starts from a fuzzer-chosen one and bumps up to the
    // last, announcing each.
    size_t honest_version{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, cast.children.size() - 1)};
    bool honest_announced{false};
    int reconnects{0};

    // Known liveness holes that need the honest peer to bump its child. They are told apart at the end
    // of a run, and the property is not checked if one of them opened. Both are about when a child
    // version became an orphan announced by the honest peer, which registers the honest peer as a
    // candidate for requesting the parent by txid: on its delivery by the honest peer, on the honest
    // peer's announcement of it while held, or on its delivery by another peer while the honest peer's
    // announcement of it is pending.
    struct {
        //! The honest peer delivered the parent against a request by txid, which completed its
        //! announcement of that txid in TxRequestTracker. A completed announcement is kept while
        //! another peer's announcement of the txid is open, and registering a peer for a txid it has an
        //! announcement of does nothing. So the last child version, held for the honest peer while
        //! another peer's announcement of the parent's txid was open or pending, has no request for the
        //! parent, which is never requested again once the other announcements complete or go away
        //! with their peer. Set when the honest peer delivered the parent before the last version was
        //! held for it, and was never asked for the parent afterwards. (A pending announcement that is
        //! never requested is invisible here, so the other peer's part is not checked.)
        bool completed_parent_request{false};
        //! An older child version was held for the honest peer after the last one, so it is newer in the
        //! honest peer's orphans. When the honest peer delivers the parent, only the package with its
        //! newest child is tried, which fails the feerate, and the parent is not delivered again. Set
        //! when the honest peer delivered the parent after such a version was held, and no more times
        //! than there are such versions.
        bool older_child_newer_orphan{false};
        bool Any() const { return completed_parent_request || older_child_newer_orphan; }
    } holes;
    // For `holes`, numbered in the order they happened: the honest peer's deliveries of the parent, the
    // last request for the parent from it, and when each child version was last held for it.
    uint64_t events{0}, parent_requested_from_honest{0}, parent_from_honest_before_last_held{0};
    std::vector<uint64_t> parent_from_honest;
    std::vector<uint64_t> held_for_honest(cast.children.size(), 0);
    std::vector<bool> is_held_for_honest(cast.children.size(), false);

    auto receive = [&](CNode& peer, CSerializedNetMsg&& msg) { Assert(connman.ReceiveMsgFrom(peer, std::move(msg))); };
    // The honest peer is in sync with us (it announces our tip, and answers pings below), so that it
    // is not disconnected as an outbound peer with an old chain or for a ping timeout.
    receive(*honest, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{CBlock{active_tip->GetBlockHeader()}})));
    // For `holes`: note when each child version becomes an orphan announced by the honest peer.
    auto poll_orphans = [&]() {
        std::vector<bool> held(cast.children.size(), false);
        for (const auto& orphan : peerman->GetOrphanTransactions()) {
            if (!orphan.announcers.contains(honest->GetId())) continue;
            for (size_t i = 0; i < cast.children.size(); ++i) {
                if (orphan.tx->GetWitnessHash() == cast.children[i]->GetWitnessHash()) held[i] = true;
            }
        }
        for (size_t i = 0; i < cast.children.size(); ++i) {
            if (held[i] && !is_held_for_honest[i]) {
                held_for_honest[i] = ++events;
                if (i + 1 == cast.children.size()) {
                    parent_from_honest_before_last_held = parent_from_honest.empty() ? 0 : parent_from_honest.back();
                }
            }
        }
        is_held_for_honest = std::move(held);
    };
    // Let the node process everything pending and send its messages. The honest peer answers our
    // requests immediately with the honest transactions; adversaries never answer here. Peers are
    // serviced round-robin from a fuzzer-chosen peer, as the message handler (which shuffles them) may
    // be anywhere in its loop when a message arrives: work created for a peer whose turn already
    // passed waits for the next round, or for the next call if no peer has more work. As there,
    // peers the node is disconnecting (e.g. for misbehaviour) are skipped, and then they are gone.
    auto process = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const size_t start{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, peers.size() - 1)};
        for (int rounds = 0; rounds < 32; ++rounds) {
            bool more{false};
            for (size_t i = 0; i < peers.size(); ++i) {
                CNode* peer{peers[(start + i) % peers.size()]};
                if (!peer || peer->fDisconnect) continue;
                peer->fPauseSend = false;
                more |= connman.ProcessMessagesOnce(*peer);
                poll_orphans();
                peerman->SendMessages(*peer);
                for (auto& [type, payload] : TakeSentMessages(*peer)) {
                    if (peer != honest) continue;
                    if (type == NetMsgType::PING) {
                        DataStream stream{payload};
                        uint64_t nonce;
                        stream >> nonce;
                        receive(*honest, NetMsg::Make(NetMsgType::PONG, nonce));
                        more = true;
                        continue;
                    }
                    if (type != NetMsgType::GETDATA) continue;
                    DataStream stream{payload};
                    std::vector<CInv> invs;
                    stream >> invs;
                    std::vector<CInv> not_found;
                    const auto& honest_child{cast.children[honest_version]};
                    for (const auto& inv : invs) {
                        if (!inv.IsGenTxMsg()) continue;
                        if (inv.hash == cast.parent->GetHash().ToUint256() || inv.hash == cast.parent->GetWitnessHash().ToUint256()) {
                            parent_requested_from_honest = ++events;
                            parent_from_honest.push_back(++events);
                            receive(*honest, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*cast.parent)));
                        } else if (inv.hash == honest_child->GetHash().ToUint256() || inv.hash == honest_child->GetWitnessHash().ToUint256()) {
                            receive(*honest, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*honest_child)));
                        } else {
                            // Including child versions the honest peer has replaced.
                            not_found.push_back(inv);
                        }
                        more = true;
                    }
                    if (!not_found.empty()) receive(*honest, NetMsg::Make(NetMsgType::NOTFOUND, not_found));
                }
            }
            if (!more) break;
        }
        for (auto& peer : peers) {
            if (peer && peer != honest && peer->fDisconnect) {
                peerman->FinalizeNode(*peer);
                peer = nullptr;
            }
        }
        Assert(!honest->fDisconnect);
    };
    // The honest peer announces the child version it holds or, once it has, replaces it with the next.
    auto honest_step = [&]() {
        if (honest_announced) {
            if (honest_version + 1 == cast.children.size()) return;
            ++honest_version;
        }
        receive(*honest, NetMsg::Make(NetMsgType::INV, std::vector<CInv>{CInv{MSG_WTX, cast.children[honest_version]->GetWitnessHash().ToUint256()}}));
        honest_announced = true;
    };
    auto child_accepted = [&]() { return mempool.exists(cast.children.back()->GetHash()); };

    // One adversary step: an adversary acts (or the parent leaves the mempool, or time passes), then
    // the node processes it.
    auto adversary_step = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const size_t idx{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, peers.size() - 1)};
        CNode* adversary{peers[idx]};
        const auto& tx{PickValue(fuzzed_data_provider, cast_txs)};
        std::optional<size_t> reconnect_idx;
        CallOneOf(
            fuzzed_data_provider,
            [&] { honest_step(); },
            [&] {
                // Announce a cast transaction, a mutated version of it, or an unrelated hash.
                if (!adversary) return;
                uint256 hash{fuzzed_data_provider.ConsumeBool() ? tx->GetWitnessHash().ToUint256() : MutateWitness(fuzzed_data_provider, tx)->GetWitnessHash().ToUint256()};
                if (fuzzed_data_provider.ConsumeBool()) hash = ConsumeUInt256(fuzzed_data_provider);
                const CInv inv{fuzzed_data_provider.ConsumeBool() ? MSG_WTX : MSG_TX, hash};
                receive(*adversary, NetMsg::Make(NetMsgType::INV, std::vector<CInv>{inv}));
            },
            [&] {
                // Deliver a cast transaction as is, stripped of its witness, inflated, or otherwise
                // witness-mutated.
                if (!adversary) return;
                CTransactionRef delivered{tx};
                switch (fuzzed_data_provider.ConsumeIntegralInRange(0, 3)) {
                case 0: break;
                case 1: {
                    CMutableTransaction stripped{*tx};
                    for (auto& txin : stripped.vin) txin.scriptWitness.SetNull();
                    delivered = MakeTransactionRef(std::move(stripped));
                    break;
                }
                case 2: {
                    // A witness script of standard size and sigop count but sigop-heavy: invalid, but
                    // its sigop-adjusted size counts against the feerate, which is checked first.
                    CMutableTransaction inflated{*tx};
                    inflated.vin[0].scriptWitness.stack.back().assign(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, MAX_STANDARD_TX_SIGOPS_COST / MAX_PUBKEYS_PER_MULTISIG), OP_CHECKMULTISIG);
                    delivered = MakeTransactionRef(std::move(inflated));
                    break;
                }
                case 3: delivered = MutateWitness(fuzzed_data_provider, tx); break;
                }
                receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*delivered)));
            },
            [&] {
                if (!adversary) return;
                receive(*adversary, NetMsg::Make(NetMsgType::NOTFOUND, std::vector<CInv>{CInv{fuzzed_data_provider.ConsumeBool() ? MSG_WTX : MSG_TX,
                                                                                            fuzzed_data_provider.ConsumeBool() ? tx->GetHash().ToUint256() : tx->GetWitnessHash().ToUint256()}}));
            },
            [&] {
                if (adversary) {
                    peerman->FinalizeNode(*adversary);
                    adversary->fDisconnect = true;
                    peers[idx] = nullptr;
                } else if (reconnects < 6) {
                    ++reconnects;
                    reconnect_idx = idx;
                }
            },
            [&] {
                now += std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange(0, 5)};
                g_setup->m_clock.set(now);
            },
            [&] {
                // The parent leaves the mempool, as through eviction, replacement or a reorg. The
                // child is not in it (or this loop would have ended).
                LOCK(mempool.cs);
                if (const auto parent{mempool.get(cast.parent->GetHash())}) {
                    mempool.removeRecursive(*parent, MemPoolRemovalReason::SIZELIMIT);
                }
            });
        if (reconnect_idx) peers[*reconnect_idx] = connect(ConnectionType::INBOUND);
        process();
    };

    // Adversarial prefix.
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool() && !child_accepted(), 200) {
        adversary_step();
    }
    while (!honest_announced || honest_version + 1 < cast.children.size()) {
        honest_step();
        process();
    }

    // Drain. Only one request per txhash is in flight at a time, and a preferred (outbound) candidate
    // is chosen over any non-preferred one as soon as the in-flight request completes or times out.
    // So for the child and then for the parent, an outbound honest peer waits for at most one stalled
    // request per adversarial outbound (and the one already in flight), whatever the adversaries do:
    // they keep acting during the drain. An inbound honest peer may have to wait for a request to
    // every adversary connection in turn, which adversaries reconnecting forever could extend without
    // bound; for it the adversaries go quiet (stalling any request made to them) and every connection
    // made so far counts.
    const int max_stalls{honest_outbound ? 2 * (1 + adversary_outbounds) : 2 * (num_adversaries + reconnects)};
    const auto deadline{now + 10s + (max_stalls + 1) * (node::GETDATA_TX_INTERVAL + 1s)};
    while (!child_accepted() && now < deadline) {
        if (honest_outbound && fuzzed_data_provider.ConsumeBool()) {
            adversary_step();
            if (child_accepted()) break;
        }
        now += 1s;
        g_setup->m_clock.set(now);
        process();
    }
    const uint64_t last_held{held_for_honest.back()};
    holes.completed_parent_request = last_held && parent_from_honest_before_last_held && parent_requested_from_honest < last_held;
    if (last_held) {
        // Older versions held for the honest peer after the last one, and the first time that happened.
        int older_held_later{0};
        uint64_t first_older_held_later{std::numeric_limits<uint64_t>::max()};
        for (size_t i = 0; i + 1 < held_for_honest.size(); ++i) {
            if (held_for_honest[i] > last_held) {
                ++older_held_later;
                first_older_held_later = std::min(first_older_held_later, held_for_honest[i]);
            }
        }
        const auto deliveries_after{std::ranges::count_if(parent_from_honest, [&](uint64_t e) { return e > last_held; })};
        const auto first_delivery_after{std::ranges::find_if(parent_from_honest, [&](uint64_t e) { return e > last_held; })};
        holes.older_child_newer_orphan = older_held_later > 0 && deliveries_after > 0 && deliveries_after <= older_held_later &&
                                         *first_delivery_after > first_older_held_later;
    }
    Assert(holes.Any() || child_accepted());

    // Tear down. Descendants (any accepted child version) go with the parent.
    for (CNode* peer : peers) {
        if (peer) peerman->FinalizeNode(*peer);
    }
    connman.ClearTestNodes();
    connman.SetMsgProc(nullptr);
    peerman.reset();
    WITH_LOCK(mempool.cs, mempool.removeRecursive(*cast.parent, MemPoolRemovalReason::REPLACED));
    Assert(mempool.size() == 0);
    node_ctx.validation_signals->SyncWithValidationInterfaceQueue();
}
