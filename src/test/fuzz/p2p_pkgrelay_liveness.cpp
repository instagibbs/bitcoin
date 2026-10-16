// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Liveness of 1-parent-1-child package relay (pkginv, getpkg, pkgtxns, pkgnotfound), driving a real
// PeerManager with real P2P messages and real validation. Together the two targets check that one
// honest sender gets a parent and child, or a transaction without unconfirmed parents, into its
// peer's mempool, whatever other peers do.
//
// pkgrelay_receive_liveness. One honest peer that relays packages holds several transactions, each
// acceptable to our mempool and independent of the others: parent and child pairs (the child spends
// one unconfirmed parent, which has no unconfirmed parents; the parent may pay for itself or not, and
// so may the child) and transactions without unconfirmed parents. It announces them as the protocol
// prescribes (pairs in pkginv, standalone transactions in inv, several in a message; a parent that
// pays for itself may also have been announced on its own) and answers every request. The child of a
// parent that pays for itself may be replaced on the honest sender's side, by a transaction that need
// not reach us; the sender then answers for the pair with pkgnotfound and announces the parent on its
// own (unless it has), and the item becomes the parent. Property: every one of them ends up in our
// mempool, by txid (a version with another witness counts), within a bounded time if the honest peer
// is outbound, unless a transaction conflicting with that one entered our mempool (which exempts no
// other; for the child of a parent that pays for itself, the item becomes the parent). Adversaries
// may announce, request and deliver the honest transactions and packages as is, stripped of
// witnesses, with mutated witnesses, reversed or mixed with each other; deliver witnessless copies of
// the confirmed transactions funding the children and fake children of the parents; fill the
// orphanage; send notfound and pkgnotfound; stall; disconnect and reconnect. They may also spend what
// the honest transactions spend (as a counterparty holding a key would) and the parents' outputs: to
// replace honest transactions or get to our mempool before them (another child of a TRUC parent
// conflicts with its honest one), to add children to the parents, and to replace their own
// transactions in turn (replacement cycling is out of scope). Transactions may leave our mempool,
// except accepted honest ones (an honest sender does not announce them again). Blocks may confirm
// transactions, ours and others (see ConfirmInBlock); they leave the honest sender's mempool too, which
// answers for a pair whose parent confirmed with pkgnotfound and announces the child on its own. An
// item counts once confirmed, and a confirmed conflict exempts it.
//
// pkgrelay_send_liveness. We are the sender. One peer that relays packages requests everything we
// announce. Property: every transaction that stays in our mempool reaches that peer, on its own or in
// a package, unless it entered our mempool more than once (no transaction is announced to a peer
// twice). Checked once the adversaries stop, and while they keep acting too: then within a few rounds
// of messages, for a peer with the NoBan permission (sent inventory without the randomized delay).
// Adversaries may submit the honest pairs and transactions (as our wallet would), and submit their own
// transactions spending outputs of the honest ones and coins of their own: children of the honest
// parents through an output anyone can spend (as an anchor), children that conflict with the honest
// ones, grandchildren, and replacements of all of these, in chains. Transactions may leave our
// mempool, and blocks may confirm transactions, ours and others (see ConfirmInBlock). Adversaries may
// also request packages and transactions from us.
//
// Not modelled: real blocks (see ConfirmInBlock), reorganizations, a full mempool, and a backlog of
// inventory to send (higher scoring transactions arriving faster than the inventory rate limit can
// delay an announcement for as long as they keep coming, which is out of scope).

#include <addresstype.h>
#include <addrman.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <hash.h>
#include <kernel/mempool_entry.h>
#include <kernel/mempool_removal_reason.h>
#include <kernel/types.h>
#include <net.h>
#include <net_processing.h>
#include <node/txdownloadman.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/truc_policy.h>
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
#include <validationinterface.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace std::chrono_literals;

TestChain100Setup* g_setup;

/** Coins are P2WSH of {OP_DROP OP_TRUE}, spent with a 64-byte dummy item, so that the witness carries
 * enough weight for stripping it to change the feerate materially, and anyone can spend them. */
const CScript WITNESS_SCRIPT_DROP_TRUE{CScript() << OP_DROP << OP_TRUE};
const CScript P2WSH_DROP_TRUE{GetScriptForDestination(WitnessV0ScriptHash(WITNESS_SCRIPT_DROP_TRUE))};
const std::vector<unsigned char> WITNESS_DUMMY(64, 0);
constexpr CAmount COINBASE_VALUE{50 * COIN};
/** Value of a parent's second output, which anyone can spend (as an anchor). */
constexpr CAmount ANCHOR_VALUE{1000};

struct Pair {
    CTransactionRef parent;     //!< no unconfirmed parents; output 0 funds the child, output 1 is the anchor
    CTransactionRef child;      //!< spends output 0 of the parent and an output of `funding`
    CTransactionRef fake_child; //!< spends the parent and an unknown outpoint
    CTransactionRef funding;    //!< confirmed transaction funding the child: CONFIRMED_PARENT or a coinbase
    bool parent_pays{false};    //!< whether the parent pays the minimum relay feerate on its own
};
std::vector<Pair> PAIRS;
/** Transactions without unconfirmed parents. */
std::vector<CTransactionRef> STANDALONE;
/** Confirmed coins of COINBASE_VALUE not spent by any of the above, for adversaries' transactions. */
std::vector<COutPoint> SPARE_COINS;
/** Confirmed transaction funding half of the children. */
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

    // Parents of ~155 vbytes: no fee, below the minimum relay feerate, or paying for themselves.
    // Children pay for both, or only for themselves at a lower feerate than their parent.
    struct Shape {
        uint32_t version;
        CAmount parent_fee;
        CAmount child_fee;
    };
    std::vector<Shape> shapes;
    for (const uint32_t version : {2, 3}) {
        for (const CAmount parent_fee : {0, 10, 1000}) shapes.push_back({version, parent_fee, 2000});
        shapes.push_back({version, 1000, 200});
    }
    constexpr size_t NUM_STANDALONE{3};
    constexpr size_t NUM_SPARE{4};

    // Coinbases: a parent input per pair (two pairs per shape: child funded by CONFIRMED_PARENT or by
    // a coinbase), a funding coinbase per coinbase-funded pair, standalone inputs, spare coins, and the
    // input of CONFIRMED_PARENT.
    std::vector<CTransactionRef> coinbases;
    for (size_t i = 0; i < 3 * shapes.size() + NUM_STANDALONE + NUM_SPARE + 1; ++i) {
        const CBlock block{g_setup->CreateAndProcessBlock({}, P2WSH_DROP_TRUE)};
        coinbases.push_back(block.vtx.at(0));
    }
    g_setup->mineBlocks(COINBASE_MATURITY);
    size_t next_coinbase{0};
    auto take_coinbase = [&] { return coinbases.at(next_coinbase++); };

    constexpr CAmount CONFIRMED_OUTPUT{5 * COIN};
    CONFIRMED_PARENT = MakeTx(2, {COutPoint{take_coinbase()->GetHash(), 0}}, std::vector<CAmount>(shapes.size(), CONFIRMED_OUTPUT));
    const CBlock confirmed_block{g_setup->CreateAndProcessBlock({CMutableTransaction{*CONFIRMED_PARENT}}, P2WSH_DROP_TRUE)};
    Assert(confirmed_block.vtx.size() == 2);

    for (size_t i = 0; i < shapes.size(); ++i) {
        const auto& shape{shapes[i]};
        for (const bool coinbase_funded : {false, true}) {
            Pair pair;
            const CAmount parent_out{COINBASE_VALUE - shape.parent_fee - ANCHOR_VALUE};
            pair.parent = MakeTx(shape.version, {COutPoint{take_coinbase()->GetHash(), 0}}, {parent_out, ANCHOR_VALUE});
            pair.funding = coinbase_funded ? take_coinbase() : CONFIRMED_PARENT;
            const COutPoint funding{pair.funding->GetHash(), coinbase_funded ? 0 : static_cast<uint32_t>(i)};
            const CAmount funding_value{coinbase_funded ? COINBASE_VALUE : CONFIRMED_OUTPUT};
            pair.child = MakeTx(shape.version, {COutPoint{pair.parent->GetHash(), 0}, funding}, {parent_out + funding_value - shape.child_fee});
            pair.fake_child = MakeTx(shape.version, {COutPoint{pair.parent->GetHash(), 0}, COutPoint{Txid::FromUint256(uint256::ONE), 0}}, {parent_out});
            PAIRS.push_back(std::move(pair));
        }
    }
    for (size_t i = 0; i < NUM_STANDALONE; ++i) {
        STANDALONE.push_back(MakeTx(2, {COutPoint{take_coinbase()->GetHash(), 0}}, {COINBASE_VALUE - 1000}));
    }
    for (size_t i = 0; i < NUM_SPARE; ++i) SPARE_COINS.emplace_back(take_coinbase()->GetHash(), 0);

    // Check that the cast is acceptable, which the properties assume.
    auto& chainman{*g_setup->m_node.chainman};
    auto& mempool{*g_setup->m_node.mempool};
    LOCK(cs_main);
    for (auto& pair : PAIRS) {
        pair.parent_pays = chainman.ProcessTransaction(pair.parent, /*test_accept=*/true).m_result_type == MempoolAcceptResult::ResultType::VALID;
        const auto result{ProcessNewPackage(chainman.ActiveChainstate(), mempool, {pair.parent, pair.child}, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt)};
        Assert(result.m_state.IsValid());
        WITH_LOCK(mempool.cs, mempool.removeRecursive(*pair.parent, MemPoolRemovalReason::REPLACED));
    }
    for (const auto& tx : STANDALONE) {
        Assert(chainman.ProcessTransaction(tx).m_result_type == MempoolAcceptResult::ResultType::VALID);
        WITH_LOCK(mempool.cs, mempool.removeRecursive(*tx, MemPoolRemovalReason::REPLACED));
    }
    Assert(mempool.size() == 0);
}

CNode* MakePeer(NodeId id, ConnectionType conn_type, NetPermissionFlags permissions)
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
                     /*network_key=*/static_cast<uint64_t>(id + 1),
                     CNodeOptions{.permission_flags = permissions}};
}

/** Version handshake with wtxid relay, and package relay if requested, negotiated. */
void Handshake(ConnmanTestMsg& connman, PeerManager& peerman, CNode& peer, bool pkgrelay) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    constexpr ServiceFlags services{NODE_NETWORK | NODE_WITNESS};
    connman.Handshake(peer, /*successfully_connected=*/false, services, services, PROTOCOL_VERSION, /*relay_txs=*/true);
    std::vector<CSerializedNetMsg> msgs;
    msgs.push_back(NetMsg::Make(NetMsgType::WTXIDRELAY));
    if (pkgrelay) msgs.push_back(NetMsg::Make(NetMsgType::FEATURE, std::string{NetMsgFeature::PKGRELAY_1P1C}, std::vector<unsigned char>{}));
    msgs.push_back(NetMsg::Make(NetMsgType::VERACK));
    for (auto& msg : msgs) {
        Assert(connman.ReceiveMsgFrom(peer, std::move(msg)));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
    }
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

template <typename T>
T Parse(const std::vector<unsigned char>& payload)
{
    DataStream stream{payload};
    T ret;
    stream >> ret;
    return ret;
}

/** The transaction stripped of witnesses, inflated, or with a mutated witness: the txid stays. */
CTransactionRef Malleate(FuzzedDataProvider& fdp, const CTransactionRef& tx)
{
    CMutableTransaction mtx{*tx};
    auto& stack{mtx.vin[0].scriptWitness.stack};
    CallOneOf(
        fdp,
        [&] {
            for (auto& txin : mtx.vin) txin.scriptWitness.SetNull();
        },
        [&] {
            // A witness script of standard size and sigop count but sigop-heavy: invalid, but its
            // sigop-adjusted size counts against the feerate, which is checked first.
            if (!stack.empty()) stack.back().assign(fdp.ConsumeIntegralInRange<size_t>(1, MAX_STANDARD_TX_SIGOPS_COST / MAX_PUBKEYS_PER_MULTISIG), OP_CHECKMULTISIG);
        },
        [&] {
            // Pad with items of a chosen size (standard size or not).
            const auto num{fdp.ConsumeIntegralInRange<size_t>(1, 150)};
            const auto size{fdp.ConsumeIntegralInRange<size_t>(0, 100)};
            stack.insert(stack.begin(), num, std::vector<unsigned char>(size, fdp.ConsumeIntegral<uint8_t>()));
        },
        [&] {
            // Replace or add an arbitrary item.
            auto item{ConsumeRandomLengthByteVector(fdp, 100)};
            if (stack.empty() || fdp.ConsumeBool()) {
                stack.insert(stack.begin(), std::move(item));
            } else {
                stack.at(fdp.ConsumeIntegralInRange<size_t>(0, stack.size() - 1)) = std::move(item);
            }
        },
        [&] {
            // Another valid witness: OP_DROP accepts any dummy.
            if (stack.size() == 2) stack.front() = ConsumeRandomLengthByteVector(fdp, 80);
        });
    return MakeTransactionRef(mtx);
}

/** A replacement of an adversary's transaction, paying 1000 more. */
CTransactionRef Replacement(const CTransaction& old)
{
    std::vector<COutPoint> inputs;
    for (const auto& txin : old.vin) inputs.push_back(txin.prevout);
    return MakeTx(old.version, inputs, {std::max<CAmount>(old.vout[0].nValue - 1000, 0)});
}

/** A transaction of an adversary's own, added to `own`: spending one of its coins, and optionally an
 * output in `spendable`; or a child of one of its earlier transactions; or a replacement of one
 * (repeated, a chain of replacements). */
CTransactionRef MakeAdversaryTx(FuzzedDataProvider& fdp, const std::vector<std::pair<COutPoint, CAmount>>& spendable, std::vector<CTransactionRef>& own)
{
    std::vector<COutPoint> inputs{PickValue(fdp, SPARE_COINS)};
    CAmount value{COINBASE_VALUE};
    CAmount fee{fdp.PickValueInArray<CAmount>({0, 300, 3000, 30'000, 300'000})};
    uint32_t version{fdp.ConsumeBool() ? TRUC_VERSION : 2};
    CTransactionRef replacement;
    CallOneOf(
        fdp,
        [&] {},
        [&] {
            const auto& [outpoint, amount]{PickValue(fdp, spendable)};
            inputs.insert(inputs.begin(), outpoint);
            value += amount;
        },
        [&] {
            if (own.empty()) return;
            const auto& parent{PickValue(fdp, own)};
            inputs = {COutPoint{parent->GetHash(), 0}};
            value = parent->vout[0].nValue;
        },
        [&] {
            if (!own.empty()) replacement = Replacement(*(fdp.ConsumeBool() ? own.back() : PickValue(fdp, own)));
        });
    own.push_back(replacement ? replacement : MakeTx(version, inputs, {std::max<CAmount>(value - fee, 0)}));
    return own.back();
}

/** Calls back for every transaction entering the mempool (validation signals are synchronous while
 * fuzzing). */
struct MempoolAdditions final : CValidationInterface {
    std::function<void(const CTransactionRef&)> m_added;
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t) override
    {
        if (m_added) m_added(tx.info.m_tx);
    }
};

/** A PeerManager under test, with a fresh mempool state, and its peers. */
struct Net {
    node::NodeContext& node_ctx{g_setup->m_node};
    TestChainstateManager& chainman{static_cast<TestChainstateManager&>(*node_ctx.chainman)};
    CTxMemPool& mempool{*node_ctx.mempool};
    NodeSeconds now;
    AddrMan addrman{*node_ctx.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0, 0, addrman, *node_ctx.netgroupman, Params()};
    std::unique_ptr<PeerManager> peerman;
    NodeId next_id{0};
    CBlockHeader tip_header;
    std::shared_ptr<MempoolAdditions> additions{std::make_shared<MempoolAdditions>()};
    /** Transactions ConfirmInBlock confirmed, with the coins they spent, to undo at teardown. */
    std::vector<std::pair<CTransactionRef, std::vector<Coin>>> confirmed;

    Net()
    {
        Assert(mempool.size() == 0);
        chainman.ResetIbd();
        chainman.JumpOutOfIbd();
        const CBlockIndex* const tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
        tip_header = tip->GetBlockHeader();
        now = tip->Time() + 1s;
        g_setup->m_clock.set(now);
        peerman = PeerManager::make(connman, addrman, /*banman=*/nullptr, chainman, mempool, *node_ctx.warnings,
                                    PeerManager::Options{.deterministic_rng = true});
        CConnman::Options connman_options;
        connman_options.m_msgproc = peerman.get();
        connman_options.m_peer_connect_timeout = 99999;
        connman.Init(connman_options);
        node_ctx.validation_signals->RegisterSharedValidationInterface(additions);
        node_ctx.validation_signals->RegisterValidationInterface(peerman.get());
    }

    /** Transactions for a block: some of our mempool's, each after its unconfirmed parents, and some
     * of `others`. */
    std::vector<CTransactionRef> ConsumeBlock(FuzzedDataProvider& fdp, const std::vector<CTransactionRef>& others)
    {
        std::vector<CTransactionRef> txs;
        std::function<void(const CTransactionRef&)> add_with_parents = [&](const CTransactionRef& tx) {
            for (const auto& txin : tx->vin) {
                if (const auto parent{mempool.get(txin.prevout.hash)}) add_with_parents(parent);
            }
            txs.push_back(tx);
        };
        LIMITED_WHILE(fdp.ConsumeBool(), 4) {
            const auto infos{mempool.infoAll()};
            if (!others.empty() && (infos.empty() || fdp.ConsumeBool())) {
                txs.push_back(PickValue(fdp, others));
            } else if (!infos.empty()) {
                add_with_parents(PickValue(fdp, infos).tx);
            }
        }
        return txs;
    }

    /** Confirm transactions as a block would, without making one, and return those confirmed: in
     * order (a parent before its child), each whose inputs are unspent and cover its outputs. Their
     * inputs are spent and their outputs added in the coins view, the mempool drops them and their
     * conflicts, and PeerManager is told of the block and of a tip change. The coins are restored at
     * teardown. Not modelled: the block itself and the chain tip (serving transactions from the latest
     * block, compact blocks, headers). */
    std::vector<CTransactionRef> ConfirmInBlock(const std::vector<CTransactionRef>& txs)
    {
        std::vector<CTransactionRef> block_txs;
        const CBlockIndex* tip;
        {
            LOCK(cs_main);
            tip = chainman.ActiveChain().Tip();
            auto& coins{chainman.ActiveChainstate().CoinsTip()};
            for (const auto& tx : txs) {
                CAmount value_in{0};
                const bool unspent{std::ranges::all_of(tx->vin, [&](const CTxIn& txin) {
                    const Coin& coin{coins.AccessCoin(txin.prevout)};
                    value_in += coin.out.nValue;
                    return !coin.IsSpent();
                })};
                if (!unspent || value_in < tx->GetValueOut()) continue;
                auto& spent{confirmed.emplace_back(tx, std::vector<Coin>{}).second};
                for (const auto& txin : tx->vin) coins.SpendCoin(txin.prevout, &spent.emplace_back());
                AddCoins(coins, *tx, tip->nHeight + 1);
                block_txs.push_back(tx);
            }
            if (block_txs.empty()) return block_txs;
            LOCK(mempool.cs);
            mempool.removeForBlock(block_txs);
        }
        auto block{std::make_shared<CBlock>()};
        block->vtx = block_txs;
        node_ctx.validation_signals->BlockConnected(kernel::ChainstateRole{}, block, tip);
        node_ctx.validation_signals->ActiveTipChange(*tip, /*is_ibd=*/false);
        return block_txs;
    }

    CNode* Connect(ConnectionType conn_type, bool pkgrelay, NetPermissionFlags permissions = NetPermissionFlags::None) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
    {
        CNode* peer{MakePeer(next_id++, conn_type, permissions)};
        connman.AddTestNode(*peer);
        Handshake(connman, *peerman, *peer, pkgrelay);
        return peer;
    }

    void Receive(CNode& peer, CSerializedNetMsg&& msg) { Assert(connman.ReceiveMsgFrom(peer, std::move(msg))); }

    void Advance(std::chrono::seconds secs)
    {
        now += secs;
        g_setup->m_clock.set(now);
    }

    void TearDown(std::vector<CNode*>& peers)
    {
        node_ctx.validation_signals->UnregisterSharedValidationInterface(additions);
        node_ctx.validation_signals->UnregisterValidationInterface(peerman.get());
        for (CNode* peer : peers) {
            if (peer) peerman->FinalizeNode(*peer);
        }
        connman.ClearTestNodes();
        connman.SetMsgProc(nullptr);
        peerman.reset();
        {
            LOCK(mempool.cs);
            for (const auto& info : mempool.infoAll()) {
                if (mempool.exists(info.tx->GetHash())) mempool.removeRecursive(*info.tx, MemPoolRemovalReason::REPLACED);
            }
            Assert(mempool.size() == 0);
        }
        node_ctx.validation_signals->SyncWithValidationInterfaceQueue();
        LOCK(cs_main);
        auto& coins{chainman.ActiveChainstate().CoinsTip()};
        for (auto it{confirmed.rbegin()}; it != confirmed.rend(); ++it) {
            const auto& [tx, spent]{*it};
            for (uint32_t n{0}; n < tx->vout.size(); ++n) coins.SpendCoin(COutPoint{tx->GetHash(), n});
            for (size_t i{0}; i < spent.size(); ++i) coins.AddCoin(tx->vin[i].prevout, Coin{spent[i]}, /*possible_overwrite=*/false);
        }
        // The next run starts from the same coins.
        for (const auto& pair : PAIRS) {
            Assert(coins.HaveCoin(pair.parent->vin[0].prevout) && coins.HaveCoin(pair.child->vin[1].prevout));
            Assert(!coins.HaveCoin(COutPoint{pair.parent->GetHash(), 0}));
        }
        for (const auto& tx : STANDALONE) Assert(coins.HaveCoin(tx->vin[0].prevout));
        for (const auto& coin : SPARE_COINS) Assert(coins.HaveCoin(coin));
    }
};

} // namespace

FUZZ_TARGET(pkgrelay_receive_liveness, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    Net net;
    auto& mempool{net.mempool};

    // The honest peer's transactions: a pair is (parent, child), a standalone transaction (nullptr, tx).
    struct Item {
        const Pair* pair;
        CTransactionRef tx;
        bool announced{false};
        //! Whether the honest sender announced the parent, or the child, on its own, and whether the
        //! parent entered our mempool.
        bool parent_announced{false}, child_announced{false}, parent_entered{false};
        //! Whether the child was replaced on the honest sender's side, making the item its parent.
        bool child_gone{false};
        //! What a transaction conflicting with the parent, or with `tx`, spends: an outpoint it spends,
        //! or for `tx`, a TRUC parent's anchor (another child of it is a sibling `tx` has to evict).
        std::set<COutPoint> contested_parent{}, contested_tx{};
        bool parent_conflicted{false}, tx_conflicted{false};
    };
    std::vector<Item> items;
    for (const auto& pair : PAIRS) {
        if (items.size() < 4 && fdp.ConsumeBool()) items.push_back({&pair, pair.child});
    }
    for (const auto& tx : STANDALONE) {
        if (fdp.ConsumeBool()) items.push_back({nullptr, tx});
    }
    if (items.empty()) items.push_back({&PAIRS.front(), PAIRS.front().child});
    std::vector<CTransactionRef> cast_txs;
    for (const auto& item : items) {
        cast_txs.push_back(item.tx);
        if (item.pair) {
            for (const auto& tx : {item.pair->parent, item.pair->fake_child, item.pair->funding}) cast_txs.push_back(tx);
        }
    }
    // What adversaries can spend besides their own coins: what the honest transactions spend, and the
    // parents' outputs.
    std::vector<std::pair<COutPoint, CAmount>> spendable;
    for (auto& item : items) {
        for (const auto& txin : item.tx->vin) item.contested_tx.insert(txin.prevout);
        const CTransactionRef parent{item.pair ? item.pair->parent : nullptr};
        if (!parent) {
            spendable.emplace_back(item.tx->vin[0].prevout, COINBASE_VALUE);
            continue;
        }
        for (const auto& txin : parent->vin) item.contested_parent.insert(txin.prevout);
        if (parent->version == TRUC_VERSION) item.contested_tx.emplace(parent->GetHash(), 1);
        spendable.emplace_back(parent->vin[0].prevout, COINBASE_VALUE);
        for (const uint32_t n : {0U, 1U}) spendable.emplace_back(COutPoint{parent->GetHash(), n}, parent->vout[n].nValue);
        const COutPoint& funding{item.tx->vin[1].prevout};
        spendable.emplace_back(funding, item.pair->funding->vout[funding.n].nValue);
    }
    std::vector<CTransactionRef> adversary_txs;
    // A transaction that entered our mempool or confirmed.
    auto note_conflicts = [&](const CTransactionRef& tx) {
        auto conflicts = [&](const std::set<COutPoint>& contested) {
            return std::ranges::any_of(tx->vin, [&](const CTxIn& txin) { return contested.contains(txin.prevout); });
        };
        for (auto& item : items) {
            if (tx->GetHash() == item.tx->GetHash() || (item.pair && tx->GetHash() == item.pair->parent->GetHash())) continue;
            item.parent_conflicted |= conflicts(item.contested_parent);
            item.tx_conflicted |= conflicts(item.contested_tx);
        }
    };
    net.additions->m_added = [&](const CTransactionRef& tx) {
        for (auto& item : items) {
            if (item.pair && tx->GetHash() == item.pair->parent->GetHash()) item.parent_entered = true;
        }
        note_conflicts(tx);
    };
    std::set<Txid> confirmed;
    auto confirm = [&](const std::vector<CTransactionRef>& txs) {
        for (const auto& tx : net.ConfirmInBlock(txs)) {
            confirmed.insert(tx->GetHash());
            note_conflicts(tx);
        }
    };
    // What the honest sender's mempool still has of an item.
    auto has_parent = [&](const Item& item) { return item.pair && !confirmed.contains(item.pair->parent->GetHash()); };
    auto has_tx = [&](const Item& item) { return !item.child_gone && !confirmed.contains(item.tx->GetHash()); };
    // The item is the parent once its child is gone, or conflicted while the parent pays for itself.
    auto parent_due = [&](const Item& item) { return item.pair && (item.child_gone || (item.tx_conflicted && item.pair->parent_pays)); };
    auto target = [&](const Item& item) { return (parent_due(item) ? item.pair->parent : item.tx)->GetHash(); };
    auto accepted = [&](const Item& item) { return mempool.exists(target(item)); };
    auto all_done = [&] {
        return std::ranges::all_of(items, [&](const Item& item) {
            return accepted(item) || confirmed.contains(target(item)) || item.parent_conflicted || (item.tx_conflicted && !parent_due(item));
        });
    };
    auto honest_tx = [&](const uint256& hash) -> CTransactionRef {
        for (const auto& item : items) {
            for (const auto& tx : {has_parent(item) ? item.pair->parent : nullptr, has_tx(item) ? item.tx : nullptr}) {
                if (tx && (tx->GetWitnessHash().ToUint256() == hash || tx->GetHash().ToUint256() == hash)) return tx;
            }
        }
        return nullptr;
    };

    LOCK(NetEventsInterface::g_msgproc_mutex);
    const int num_adversaries{fdp.ConsumeIntegralInRange(1, 3)};
    // peers[0] is the honest peer; the rest are adversaries. Disconnected adversaries are nullptr
    // until they reconnect (as a new node).
    std::vector<CNode*> peers;
    const bool honest_outbound{fdp.ConsumeBool()};
    peers.push_back(net.Connect(honest_outbound ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND, /*pkgrelay=*/true));
    // Adversaries may hold outbound slots too. Reconnections are inbound: an outbound slot an adversary
    // gives up is assumed refilled by a non-adversary.
    int adversary_outbounds{0};
    for (int i = 0; i < num_adversaries; ++i) {
        const bool outbound{fdp.ConsumeBool()};
        adversary_outbounds += outbound;
        peers.push_back(net.Connect(outbound ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND, fdp.ConsumeBool()));
    }
    CNode* const honest{peers[0]};
    int reconnects{0};

    // The honest peer is in sync with us (it announces our tip, and answers pings below), so that it
    // is not disconnected as an outbound peer with an old chain or for a ping timeout.
    net.Receive(*honest, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{CBlock{net.tip_header}})));

    // Let the node process everything pending and send its messages. The honest peer answers our
    // requests immediately; adversaries never answer here. Peers are serviced round-robin from a
    // fuzzer-chosen peer, as the message handler may be anywhere in its loop when a message arrives.
    auto process = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const size_t start{fdp.ConsumeIntegralInRange<size_t>(0, peers.size() - 1)};
        for (int rounds = 0; rounds < 32; ++rounds) {
            bool more{false};
            for (size_t i = 0; i < peers.size(); ++i) {
                CNode* peer{peers[(start + i) % peers.size()]};
                if (!peer || peer->fDisconnect) continue;
                peer->fPauseSend = false;
                more |= net.connman.ProcessMessagesOnce(*peer);
                net.peerman->SendMessages(*peer);
                for (auto& [type, payload] : TakeSentMessages(*peer)) {
                    if (peer != honest) continue;
                    if (type == NetMsgType::PING) {
                        net.Receive(*honest, NetMsg::Make(NetMsgType::PONG, Parse<uint64_t>(payload)));
                        more = true;
                    } else if (type == NetMsgType::GETDATA) {
                        std::vector<CInv> not_found;
                        for (const auto& inv : Parse<std::vector<CInv>>(payload)) {
                            if (!inv.IsGenTxMsg()) continue;
                            if (const auto tx{honest_tx(inv.hash)}) {
                                net.Receive(*honest, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
                            } else {
                                not_found.push_back(inv);
                            }
                        }
                        if (!not_found.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::NOTFOUND, not_found));
                        more = true;
                    } else if (type == NetMsgType::GETPKG) {
                        std::vector<PkgInv> not_found;
                        std::vector<CInv> fallback;
                        for (const auto& pkg : Parse<std::vector<PkgInv>>(payload)) {
                            const auto it{std::ranges::find_if(items, [&](const Item& item) {
                                return item.pair && item.pair->parent->GetWitnessHash() == pkg.parent && item.tx->GetWitnessHash() == pkg.child;
                            })};
                            if (it != items.end() && has_parent(*it) && has_tx(*it)) {
                                net.Receive(*honest, NetMsg::Make(NetMsgType::PKGTXNS, TX_WITH_WITNESS(*it->pair->parent), TX_WITH_WITNESS(*it->tx)));
                                continue;
                            }
                            not_found.push_back(pkg);
                            if (it == items.end()) continue;
                            if (has_parent(*it) && !it->parent_announced) {
                                fallback.emplace_back(MSG_WTX, it->pair->parent->GetWitnessHash().ToUint256());
                                it->parent_announced = true;
                            } else if (has_tx(*it) && !it->child_announced) {
                                fallback.emplace_back(MSG_WTX, it->tx->GetWitnessHash().ToUint256());
                                it->child_announced = true;
                            }
                        }
                        if (!not_found.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::PKGNOTFOUND, not_found));
                        if (!fallback.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::INV, fallback));
                        more = true;
                    }
                }
            }
            if (!more) break;
        }
        for (auto& peer : peers) {
            if (peer && peer != honest && peer->fDisconnect) {
                net.peerman->FinalizeNode(*peer);
                peer = nullptr;
            }
        }
        Assert(!honest->fDisconnect);
    };
    // The honest peer announces items not announced yet, all of them or some, together as at an
    // inventory trickle.
    auto announce = [&](bool all) {
        std::vector<PkgInv> pkgs;
        std::vector<CInv> invs;
        for (auto& item : items) {
            if (item.announced || !(all || fdp.ConsumeBool())) continue;
            if (!item.pair) {
                if (has_tx(item)) invs.emplace_back(MSG_WTX, item.tx->GetWitnessHash().ToUint256());
            } else if (has_parent(item) && has_tx(item)) {
                pkgs.push_back({item.pair->parent->GetWitnessHash(), item.tx->GetWitnessHash()});
            } else if (has_parent(item) && !item.parent_announced) {
                invs.emplace_back(MSG_WTX, item.pair->parent->GetWitnessHash().ToUint256());
                item.parent_announced = true;
            } else if (has_tx(item) && !item.child_announced) {
                invs.emplace_back(MSG_WTX, item.tx->GetWitnessHash().ToUint256());
                item.child_announced = true;
            }
            item.announced = true;
        }
        if (!pkgs.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::PKGINV, pkgs));
        if (!invs.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::INV, invs));
    };
    // A package entry built from the cast: the honest pair, reversed, mixed, malleated, or made up.
    auto consume_pkg = [&]() {
        const auto& tx_a{PickValue(fdp, cast_txs)};
        const auto& tx_b{PickValue(fdp, cast_txs)};
        PkgInv pkg{tx_a->GetWitnessHash(), tx_b->GetWitnessHash()};
        CallOneOf(
            fdp,
            [&] {},
            [&] {
                const auto& item{PickValue(fdp, items)};
                if (item.pair) pkg = {item.pair->parent->GetWitnessHash(), item.tx->GetWitnessHash()};
            },
            [&] { pkg.parent = Malleate(fdp, tx_a)->GetWitnessHash(); },
            [&] { pkg.child = Malleate(fdp, tx_b)->GetWitnessHash(); },
            [&] { pkg.child = Wtxid::FromUint256(ConsumeUInt256(fdp)); });
        return pkg;
    };

    auto adversary_step = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const size_t idx{fdp.ConsumeIntegralInRange<size_t>(1, peers.size() - 1)};
        CNode* adversary{peers[idx]};
        const CTransactionRef tx{PickValue(fdp, cast_txs)};
        std::optional<size_t> reconnect_idx;
        CallOneOf(
            fdp,
            [&] { announce(/*all=*/false); },
            [&] {
                // An honest sender may have announced a parent that pays for itself before the child existed.
                auto& item{PickValue(fdp, items)};
                if (has_parent(item) && item.pair->parent_pays && !item.parent_announced) {
                    net.Receive(*honest, NetMsg::Make(NetMsgType::INV, std::vector<CInv>{{MSG_WTX, item.pair->parent->GetWitnessHash().ToUint256()}}));
                    item.parent_announced = true;
                }
            },
            [&] {
                // Not once the honest sender announced the parent on its own and we dropped it: it does
                // not announce it again.
                auto& item{PickValue(fdp, items)};
                if (!item.pair || !item.pair->parent_pays) return;
                if (item.parent_announced && item.parent_entered && !mempool.exists(item.pair->parent->GetHash())) return;
                item.child_gone = true;
            },
            [&] { confirm(net.ConsumeBlock(fdp, cast_txs)); },
            [&] {
                if (!adversary) return;
                std::vector<PkgInv> pkgs;
                LIMITED_WHILE(pkgs.empty() || fdp.ConsumeBool(), 3) pkgs.push_back(consume_pkg());
                net.Receive(*adversary, NetMsg::Make(NetMsgType::PKGINV, pkgs));
            },
            [&] {
                if (!adversary) return;
                uint256 hash{fdp.ConsumeBool() ? tx->GetWitnessHash().ToUint256() : Malleate(fdp, tx)->GetWitnessHash().ToUint256()};
                if (fdp.ConsumeBool()) hash = ConsumeUInt256(fdp);
                net.Receive(*adversary, NetMsg::Make(NetMsgType::INV, std::vector<CInv>{{fdp.ConsumeBool() ? MSG_WTX : MSG_TX, hash}}));
            },
            [&] {
                if (!adversary) return;
                const auto delivered{fdp.ConsumeBool() ? tx : Malleate(fdp, tx)};
                net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*delivered)));
            },
            [&] {
                if (!adversary) return;
                cast_txs.push_back(MakeAdversaryTx(fdp, spendable, adversary_txs));
                net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*cast_txs.back())));
            },
            [&] {
                // A package, solicited or not: the honest one, reversed, mixed, or malleated.
                if (!adversary) return;
                CTransactionRef parent{PickValue(fdp, cast_txs)};
                CTransactionRef child{PickValue(fdp, cast_txs)};
                if (const auto& item{PickValue(fdp, items)}; item.pair && fdp.ConsumeBool()) {
                    parent = item.pair->parent;
                    child = item.tx;
                }
                if (fdp.ConsumeBool()) parent = Malleate(fdp, parent);
                if (fdp.ConsumeBool()) child = Malleate(fdp, child);
                net.Receive(*adversary, NetMsg::Make(NetMsgType::PKGTXNS, TX_WITH_WITNESS(*parent), TX_WITH_WITNESS(*child)));
            },
            [&] {
                if (!adversary) return;
                if (fdp.ConsumeBool()) {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::PKGNOTFOUND, std::vector<PkgInv>{consume_pkg()}));
                } else {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::NOTFOUND, std::vector<CInv>{{fdp.ConsumeBool() ? MSG_WTX : MSG_TX,
                                                                                               fdp.ConsumeBool() ? tx->GetHash().ToUint256() : tx->GetWitnessHash().ToUint256()}}));
                }
            },
            [&] {
                // Request from us, as a peer that wants the honest transactions too.
                if (!adversary) return;
                if (fdp.ConsumeBool()) {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::GETPKG, std::vector<PkgInv>{consume_pkg()}));
                } else {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_WTX, tx->GetWitnessHash().ToUint256()}}));
                }
            },
            [&] {
                // Fill the orphanage: children of parents that do not exist (hashing keeps the fuzzer
                // from learning outpoints that do), some of them large.
                if (!adversary) return;
                LIMITED_WHILE(fdp.ConsumeBool(), 20) {
                    const Txid unknown{Txid::FromUint256((HashWriter{} << ConsumeUInt256(fdp)).GetSHA256())};
                    CMutableTransaction orphan{*MakeTx(2, {COutPoint{unknown, 0}}, {COIN})};
                    orphan.vin[0].scriptWitness.stack.front().resize(fdp.ConsumeIntegralInRange<size_t>(0, 50'000));
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(CTransaction{orphan})));
                }
            },
            [&] {
                if (adversary) {
                    net.peerman->FinalizeNode(*adversary);
                    adversary->fDisconnect = true;
                    peers[idx] = nullptr;
                } else if (reconnects < 6) {
                    ++reconnects;
                    reconnect_idx = idx;
                }
            },
            [&] { net.Advance(std::chrono::seconds{fdp.ConsumeIntegralInRange(0, 5)}); },
            [&] {
                // A transaction leaves the mempool (eviction, expiry, replacement), unless it is an
                // accepted honest one or its parent.
                LOCK(mempool.cs);
                const auto infos{mempool.infoAll()};
                if (infos.empty()) return;
                const auto& removed{PickValue(fdp, infos).tx};
                for (const auto& item : items) {
                    if (!accepted(item)) continue;
                    if (item.tx->GetHash() == removed->GetHash() || (item.pair && item.pair->parent->GetHash() == removed->GetHash())) return;
                }
                mempool.removeRecursive(*removed, MemPoolRemovalReason::SIZELIMIT);
            });
        if (reconnect_idx) peers[*reconnect_idx] = net.Connect(ConnectionType::INBOUND, fdp.ConsumeBool());
        process();
    };

    // Adversarial prefix.
    LIMITED_WHILE(fdp.ConsumeBool() && !all_done(), 200) adversary_step();
    announce(/*all=*/true);
    process();

    // Drain. Only one request per package (or transaction) is in flight at a time, and a preferred
    // (outbound) candidate is chosen over any non-preferred one as soon as the in-flight request
    // completes or times out. So an outbound honest peer waits for at most one stalled request per
    // adversarial outbound (and the one already in flight), whatever the adversaries do: they keep
    // acting during the drain. An inbound honest peer may have to wait for a request to every
    // adversary connection in turn, which adversaries reconnecting forever could extend without
    // bound; for it the adversaries go quiet (stalling any request made to them) and every connection
    // made so far counts. Requests for different transactions and packages run concurrently. A pair the
    // honest sender can no longer serve takes a second round of stalls, for the parent or child it then
    // announces on its own.
    const int max_stalls{honest_outbound ? 1 + adversary_outbounds : num_adversaries + reconnects};
    const auto drain_start{net.now};
    auto deadline = [&] {
        const int rounds{std::ranges::any_of(items, [&](const Item& item) { return item.pair && !(has_parent(item) && has_tx(item)); }) ? 2 : 1};
        return drain_start + rounds * (10s + (max_stalls + 1) * (node::GETDATA_TX_INTERVAL + 1s));
    };
    while (!all_done() && net.now < deadline()) {
        if (honest_outbound && fdp.ConsumeBool()) {
            adversary_step();
            if (all_done()) break;
        }
        net.Advance(1s);
        process();
    }
    Assert(all_done());

    net.TearDown(peers);
}

FUZZ_TARGET(pkgrelay_send_liveness, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    Net net;
    auto& mempool{net.mempool};
    auto& chainman{net.chainman};

    LOCK(NetEventsInterface::g_msgproc_mutex);
    // peers[0] is the recipient; the rest are adversaries. The recipient connects first, so that
    // everything entering our mempool is announced to it.
    std::vector<CNode*> peers;
    const bool no_ban{fdp.ConsumeBool()};
    peers.push_back(net.Connect(fdp.ConsumeBool() ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND, /*pkgrelay=*/true,
                                no_ban ? NetPermissionFlags::NoBan : NetPermissionFlags::None));
    CNode* const recipient{peers[0]};
    const int num_adversaries{fdp.ConsumeIntegralInRange(1, 3)};
    for (int i = 0; i < num_adversaries; ++i) {
        peers.push_back(net.Connect(fdp.ConsumeBool() ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND, fdp.ConsumeBool()));
    }
    net.Receive(*recipient, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{CBlock{net.tip_header}})));

    // What the recipient received.
    std::set<Wtxid> received;
    // When each transaction entered our mempool, in rounds of message processing, and those that
    // entered it more than once.
    int round{0};
    std::map<Wtxid, int> entered;
    std::set<Wtxid> reentered;
    net.additions->m_added = [&](const CTransactionRef& tx) {
        if (!entered.try_emplace(tx->GetWitnessHash(), round).second) reentered.insert(tx->GetWitnessHash());
    };

    // The recipient requests everything we announce. Its requests arrive after the adversaries' next
    // move (as with network latency), so that our mempool can change between an announcement and the
    // request for it: while they act, after that or later; while they keep acting, after that; once
    // they stop, at once.
    enum class Phase { ADVERSARIAL, ACTIVE, QUIET } phase{Phase::ADVERSARIAL};
    bool activity{false};
    std::vector<CSerializedNetMsg> requests;
    auto request = [&](CSerializedNetMsg&& msg) {
        if (phase == Phase::QUIET) {
            net.Receive(*recipient, std::move(msg));
        } else {
            requests.push_back(std::move(msg));
        }
    };
    auto process = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        ++round;
        if (phase != Phase::ADVERSARIAL || fdp.ConsumeBool()) {
            for (auto& msg : requests) net.Receive(*recipient, std::move(msg));
            requests.clear();
        }
        const size_t start{fdp.ConsumeIntegralInRange<size_t>(0, peers.size() - 1)};
        for (int rounds = 0; rounds < 32; ++rounds) {
            bool more{false};
            for (size_t i = 0; i < peers.size(); ++i) {
                CNode* peer{peers[(start + i) % peers.size()]};
                if (!peer || peer->fDisconnect) continue;
                peer->fPauseSend = false;
                more |= net.connman.ProcessMessagesOnce(*peer);
                net.peerman->SendMessages(*peer);
                for (auto& [type, payload] : TakeSentMessages(*peer)) {
                    if (peer != recipient) continue;
                    if (type == NetMsgType::PING) {
                        net.Receive(*recipient, NetMsg::Make(NetMsgType::PONG, Parse<uint64_t>(payload)));
                        more = true;
                    } else if (type == NetMsgType::INV) {
                        std::vector<CInv> invs;
                        for (const auto& inv : Parse<std::vector<CInv>>(payload)) {
                            if (inv.IsMsgWtx()) invs.push_back(inv);
                        }
                        if (!invs.empty()) request(NetMsg::Make(NetMsgType::GETDATA, invs));
                        more = activity = true;
                    } else if (type == NetMsgType::PKGINV) {
                        request(NetMsg::Make(NetMsgType::GETPKG, Parse<std::vector<PkgInv>>(payload)));
                        more = activity = true;
                    } else if (type == NetMsgType::TX) {
                        DataStream stream{payload};
                        CTransactionRef tx;
                        stream >> TX_WITH_WITNESS(tx);
                        received.insert(tx->GetWitnessHash());
                        activity = true;
                    } else if (type == NetMsgType::PKGTXNS) {
                        DataStream stream{payload};
                        CTransactionRef parent, child;
                        stream >> TX_WITH_WITNESS(parent) >> TX_WITH_WITNESS(child);
                        received.insert(parent->GetWitnessHash());
                        received.insert(child->GetWitnessHash());
                        activity = true;
                    } else if (type == NetMsgType::NOTFOUND || type == NetMsgType::PKGNOTFOUND) {
                        activity = true;
                    }
                }
            }
            if (!more) break;
        }
        for (auto& peer : peers) {
            if (peer && peer != recipient && peer->fDisconnect) {
                net.peerman->FinalizeNode(*peer);
                peer = nullptr;
            }
        }
        Assert(!recipient->fDisconnect);
    };

    // Outputs of the honest transactions (the parents' anchors included), which adversaries can spend
    // besides their own coins.
    std::vector<std::pair<COutPoint, CAmount>> honest_outputs;
    for (const auto& pair : PAIRS) {
        honest_outputs.emplace_back(COutPoint{pair.parent->GetHash(), 0}, pair.parent->vout[0].nValue);
        honest_outputs.emplace_back(COutPoint{pair.parent->GetHash(), 1}, pair.parent->vout[1].nValue);
        honest_outputs.emplace_back(COutPoint{pair.child->GetHash(), 0}, pair.child->vout[0].nValue);
    }
    std::vector<CTransactionRef> adversary_txs;

    auto submit = [&](const Package& package) {
        const auto result{WITH_LOCK(::cs_main, return ProcessNewPackage(chainman.ActiveChainstate(), mempool, package, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt))};
        for (const auto& tx : package) {
            const auto it{result.m_tx_results.find(tx->GetWitnessHash())};
            if (it != result.m_tx_results.end() && it->second.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                net.peerman->InitiateTxBroadcastToAll(tx->GetWitnessHash());
            }
        }
    };

    // An adversary replaces its latest transaction, paying more: repeated, the churn that keeps a
    // child changing.
    auto replace_latest = [&](CNode* adversary) {
        if (!adversary || adversary_txs.empty()) return;
        adversary_txs.push_back(Replacement(*adversary_txs.back()));
        net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*adversary_txs.back())));
    };
    auto adversary_action = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const size_t idx{fdp.ConsumeIntegralInRange<size_t>(1, peers.size() - 1)};
        CNode* adversary{peers[idx]};
        bool reconnect{false};
        CallOneOf(
            fdp,
            [&] {
                // Our wallet submits an honest pair or transaction.
                const auto& pair{PickValue(fdp, PAIRS)};
                if (fdp.ConsumeBool()) {
                    submit({pair.parent, pair.child});
                } else if (fdp.ConsumeBool()) {
                    submit({pair.parent});
                } else {
                    submit({PickValue(fdp, STANDALONE)});
                }
            },
            [&] {
                // An adversary relays a transaction of its own to us, which may spend an output of a
                // transaction in our mempool.
                if (!adversary) return;
                std::vector<std::pair<COutPoint, CAmount>> in_mempool;
                for (const auto& info : mempool.infoAll()) {
                    for (uint32_t n{0}; n < info.tx->vout.size(); ++n) in_mempool.emplace_back(COutPoint{info.tx->GetHash(), n}, info.tx->vout[n].nValue);
                }
                const auto& spendable{in_mempool.empty() || fdp.ConsumeBool() ? honest_outputs : in_mempool};
                net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*MakeAdversaryTx(fdp, spendable, adversary_txs))));
            },
            [&] { replace_latest(adversary); },
            [&] {
                // An adversary relays an honest transaction to us, as is or malleated.
                if (!adversary) return;
                const auto& pair{PickValue(fdp, PAIRS)};
                CTransactionRef tx{fdp.PickValueInArray({pair.parent, pair.child, PickValue(fdp, STANDALONE)})};
                if (fdp.ConsumeBool()) tx = Malleate(fdp, tx);
                net.Receive(*adversary, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
            },
            [&] {
                // An adversary requests transactions or packages from us.
                if (!adversary) return;
                const auto infos{mempool.infoAll()};
                if (infos.empty()) return;
                const auto& tx_a{PickValue(fdp, infos).tx};
                const auto& tx_b{PickValue(fdp, infos).tx};
                if (fdp.ConsumeBool()) {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::GETPKG, std::vector<PkgInv>{{tx_a->GetWitnessHash(), tx_b->GetWitnessHash()}}));
                } else {
                    net.Receive(*adversary, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{{MSG_WTX, tx_a->GetWitnessHash().ToUint256()}}));
                }
            },
            [&] {
                // A transaction leaves the mempool (eviction, expiry).
                LOCK(mempool.cs);
                const auto infos{mempool.infoAll()};
                if (infos.empty()) return;
                mempool.removeRecursive(*PickValue(fdp, infos).tx, MemPoolRemovalReason::SIZELIMIT);
            },
            [&] {
                std::vector<CTransactionRef> others{adversary_txs};
                for (const auto& pair : PAIRS) others.insert(others.end(), {pair.parent, pair.child});
                others.insert(others.end(), STANDALONE.begin(), STANDALONE.end());
                net.ConfirmInBlock(net.ConsumeBlock(fdp, others));
            },
            [&] {
                if (adversary) {
                    net.peerman->FinalizeNode(*adversary);
                    adversary->fDisconnect = true;
                    peers[idx] = nullptr;
                } else {
                    reconnect = true;
                }
            },
            [&] { net.Advance(std::chrono::seconds{fdp.ConsumeIntegralInRange(0, 5)}); });
        if (reconnect) peers[idx] = net.Connect(ConnectionType::INBOUND, fdp.ConsumeBool());
    };

    LIMITED_WHILE(fdp.ConsumeBool(), 200) {
        adversary_action();
        process();
    }

    // The adversaries may keep acting. A transaction that stays in our mempool reaches a NoBan
    // recipient within a few rounds whatever they do: we announce it (on its own or in a package) in
    // the round after it enters at the latest, and the request arrives in the next round; if the
    // package cannot be served then, we announce the transaction on its own in that round, and the
    // request for it arrives in the next.
    phase = Phase::ACTIVE;
    const int active_start{round};
    LIMITED_WHILE(fdp.ConsumeBool(), 100) {
        switch (fdp.ConsumeIntegralInRange(0, 2)) {
        case 1: adversary_action(); break;
        case 2: replace_latest(peers[fdp.ConsumeIntegralInRange<size_t>(1, peers.size() - 1)]); break;
        }
        net.Advance(1s);
        process();
        if (!no_ban) continue;
        for (const auto& info : mempool.infoAll()) {
            const Wtxid& wtxid{info.tx->GetWitnessHash()};
            if (reentered.contains(wtxid) || round < std::max(entered.at(wtxid), active_start) + 5) continue;
            Assert(received.contains(wtxid));
        }
    }

    // Drain: the adversaries stop, time passes until a while after the last exchange with the
    // recipient (inventory is sent on a randomized schedule averaging a few seconds).
    phase = Phase::QUIET;
    auto quiet_since{net.now};
    while (net.now < quiet_since + 120s) {
        activity = false;
        net.Advance(1s);
        process();
        if (activity) quiet_since = net.now;
    }
    for (const auto& info : mempool.infoAll()) {
        const Wtxid& wtxid{info.tx->GetWitnessHash()};
        Assert(reentered.contains(wtxid) || received.contains(wtxid));
    }

    net.TearDown(peers);
}
