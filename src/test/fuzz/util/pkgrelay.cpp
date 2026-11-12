// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util/pkgrelay.h>

namespace pkgrelay_fuzz {
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

void Initialize()
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

CTransactionRef Replacement(const CTransaction& old)
{
    std::vector<COutPoint> inputs;
    for (const auto& txin : old.vin) inputs.push_back(txin.prevout);
    return MakeTx(old.version, inputs, {std::max<CAmount>(old.vout[0].nValue - 1000, 0)});
}

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
} // namespace pkgrelay_fuzz
