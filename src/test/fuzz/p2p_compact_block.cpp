// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addrman.h>
#include <blockencodings.h>
#include <chain.h>
#include <consensus/amount.h>
#include <net.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
TestChain100Setup* g_setup;
std::shared_ptr<CBlock> g_block;
const CBlockIndex* g_block_index;

struct CapturedMessages {
    std::vector<std::vector<CInv>> getdata;
    std::vector<BlockTransactionsRequest> getblocktxn;

    void Clear()
    {
        getdata.clear();
        getblocktxn.clear();
    }

    void AssertEmpty() const
    {
        assert(getdata.empty());
        assert(getblocktxn.empty());
    }
};

void ProcessMessage(ConnmanTestMsg& connman, CNode& node, CSerializedNetMsg net_msg)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    connman.FlushSendBuffer(node);
    assert(connman.ReceiveMsgFrom(node, std::move(net_msg)));
    bool more_work{true};
    while (more_work) {
        node.fPauseSend = false;
        more_work = connman.ProcessMessagesOnce(node);
    }
}

CNode& AddPeer(ConnmanTestMsg& connman, PeerManager& peerman, std::vector<CNode*>& peers,
               NodeId id, ConnectionType connection_type, bool high_bandwidth)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    auto* peer{new CNode{
        /*id=*/id,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CService{},
        /*addrNameIn=*/"",
        connection_type,
        /*inbound_onion=*/false,
        /*network_key=*/0}};
    peers.push_back(peer);
    connman.AddTestNode(*peer);

    constexpr ServiceFlags services{NODE_NETWORK | NODE_WITNESS};
    connman.Handshake(
        *peer,
        /*successfully_connected=*/true,
        /*remote_services=*/services,
        /*local_services=*/services,
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);
    assert(peer->fSuccessfullyConnected);
    assert(!peer->fDisconnect);

    ProcessMessage(connman, *peer,
                   NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/true,
                                /*version=*/CMPCTBLOCKS_VERSION));
    assert(peer->m_bip152_highbandwidth_from);
    peer->m_bip152_highbandwidth_to = high_bandwidth;
    assert(peer->m_bip152_highbandwidth_to == high_bandwidth);

    CNodeStateStats stats;
    assert(peerman.GetNodeStateStats(id, stats));
    assert(stats.vHeightInFlight.empty());
    assert(stats.their_services == services);
    connman.FlushSendBuffer(*peer);
    return *peer;
}

CNodeStateStats GetStats(PeerManager& peerman, NodeId id)
{
    CNodeStateStats stats;
    assert(peerman.GetNodeStateStats(id, stats));
    return stats;
}

void AssertInFlight(PeerManager& peerman, const CNode& peer, bool expected)
{
    const auto stats{GetStats(peerman, peer.GetId())};
    assert(stats.vHeightInFlight.size() == static_cast<size_t>(expected));
    if (expected) assert(stats.vHeightInFlight.front() == g_block_index->nHeight);
}

void AssertRequest(const CapturedMessages& captured)
{
    assert(captured.getdata.empty());
    assert(captured.getblocktxn.size() == 1);
    const auto& request{captured.getblocktxn.front()};
    assert(request.blockhash == g_block->GetHash());
    assert(request.indexes == std::vector<uint16_t>({2, 3}));
}

void AssertFullBlockRequest(const CapturedMessages& captured)
{
    assert(captured.getblocktxn.empty());
    assert(captured.getdata.size() == 1);
    assert(captured.getdata.front().size() == 1);
    const CInv& inv{captured.getdata.front().front()};
    assert(inv.type == (MSG_BLOCK | MSG_WITNESS_FLAG));
    assert(inv.hash == g_block->GetHash());
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    g_setup = testing_setup.get();
    g_setup->mineBlocks(4);

    std::vector<CMutableTransaction> transactions;
    for (size_t i{0}; i < 3; ++i) {
        transactions.push_back(g_setup->CreateValidMempoolTransaction(
            g_setup->m_coinbase_txns.at(i),
            /*input_vout=*/0,
            /*input_height=*/static_cast<int>(i + 1),
            g_setup->coinbaseKey,
            P2WSH_OP_TRUE,
            /*output_amount=*/COIN,
            /*submit=*/i == 0));
    }
    g_block = std::make_shared<CBlock>(g_setup->CreateBlock(transactions, P2WSH_OP_TRUE));
    assert(g_block->vtx.size() == 4);

    auto& chainman{static_cast<TestChainstateManager&>(*g_setup->m_node.chainman)};
    BlockValidationState state;
    assert(chainman.ProcessNewBlockHeaders({{*g_block}}, /*min_pow_checked=*/true, state, &g_block_index));
    assert(state.IsValid());
    assert(g_block_index);
    assert(WITH_LOCK(chainman.GetMutex(), return g_block_index->nHeight == chainman.ActiveChain().Height() + 1));
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header) == g_block_index);
    assert(WITH_LOCK(chainman.GetMutex(), return !(g_block_index->nStatus & BLOCK_HAVE_DATA)));
    assert(g_setup->m_node.mempool->size() == 1);
    chainman.CheckBlockIndex();
}
} // namespace

FUZZ_TARGET(p2p_compact_block, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    auto& mempool{*node.mempool};
    chainman.ResetIbd();
    chainman.JumpOutOfIbd();
    g_setup->m_clock.set(g_block->Time());

    const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    CBlockIndex* const active_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    const CBlockIndex* const best_header{WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header)};
    const uint256 coins_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock())};
    const size_t mempool_size{mempool.size()};
    const uint64_t mempool_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};
    assert(active_tip);
    assert(best_header == g_block_index);
    assert(mempool_size == 1);

    AddrMan addrman{*node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0, 0, addrman, *node.netgroupman, Params()};
    auto peerman{PeerManager::make(
        connman, addrman, /*banman=*/nullptr, chainman, mempool, *node.warnings,
        PeerManager::Options{.deterministic_rng = true})};
    CConnman::Options connman_options;
    connman_options.m_msgproc = peerman.get();
    connman_options.m_peer_connect_timeout = 99999;
    connman.Init(connman_options);

    LOCK(NetEventsInterface::g_msgproc_mutex);

    const bool first_is_outbound{fuzzed_data_provider.ConsumeBool()};
    std::vector<CNode*> peers;
    peers.reserve(4);
    CNode& first{AddPeer(connman, *peerman, peers, /*id=*/0,
                         first_is_outbound ? ConnectionType::OUTBOUND_FULL_RELAY : ConnectionType::INBOUND,
                         /*high_bandwidth=*/false)};
    CNode& second{AddPeer(connman, *peerman, peers, /*id=*/1, ConnectionType::INBOUND,
                          /*high_bandwidth=*/true)};
    CNode& third_inbound{AddPeer(connman, *peerman, peers, /*id=*/2, ConnectionType::INBOUND,
                                 /*high_bandwidth=*/true)};
    CNode& outbound{AddPeer(connman, *peerman, peers, /*id=*/3, ConnectionType::OUTBOUND_FULL_RELAY,
                            /*high_bandwidth=*/true)};

    CapturedMessages captured;
    const auto capture_message_orig{CaptureMessage};
    connman.SetCaptureMessages(true);
    CaptureMessage = [&](const CAddress&, const std::string& msg_type,
                         std::span<const unsigned char> data, bool is_incoming) {
        if (is_incoming) return;
        if (msg_type == NetMsgType::GETDATA) {
            std::vector<CInv> invs;
            SpanReader{data} >> invs;
            captured.getdata.push_back(std::move(invs));
        } else if (msg_type == NetMsgType::GETBLOCKTXN) {
            BlockTransactionsRequest request;
            SpanReader{data} >> request;
            captured.getblocktxn.push_back(std::move(request));
        }
    };

    captured.Clear();
    assert(peerman->FetchBlock(first.GetId(), *g_block_index).has_value());
    AssertFullBlockRequest(captured);
    AssertInFlight(*peerman, first, true);
    connman.FlushSendBuffer(first);

    const CBlockHeaderAndShortTxIDs compact_block{*g_block, /*nonce=*/0};
    auto announce = [&](CNode& peer, bool expect_request) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        captured.Clear();
        ProcessMessage(connman, peer, NetMsg::Make(NetMsgType::CMPCTBLOCK, compact_block));
        if (expect_request) {
            AssertRequest(captured);
        } else {
            captured.AssertEmpty();
        }
        connman.FlushSendBuffer(peer);
    };

    announce(first, /*expect_request=*/true);
    AssertInFlight(*peerman, first, true);
    announce(second, /*expect_request=*/true);
    AssertInFlight(*peerman, second, true);

    announce(third_inbound, /*expect_request=*/first_is_outbound);
    AssertInFlight(*peerman, third_inbound, first_is_outbound);
    announce(outbound, /*expect_request=*/!first_is_outbound);
    AssertInFlight(*peerman, outbound, !first_is_outbound);

    CNode& spare{first_is_outbound ? outbound : third_inbound};
    CNode& parallel{first_is_outbound ? third_inbound : outbound};
    AssertInFlight(*peerman, spare, false);
    AssertInFlight(*peerman, parallel, true);

    // Repeated announcements must neither replace a live reconstruction nor
    // circumvent the reserved/final parallel slot.
    announce(first, /*expect_request=*/false);
    announce(spare, /*expect_request=*/false);
    AssertInFlight(*peerman, first, true);
    AssertInFlight(*peerman, second, true);
    AssertInFlight(*peerman, parallel, true);
    AssertInFlight(*peerman, spare, false);

    std::vector<CTransactionRef> valid_missing{g_block->vtx[2], g_block->vtx[3]};
    std::vector<CTransactionRef> failed_missing{valid_missing.rbegin(), valid_missing.rend()};
    auto make_invalid_missing = [&] {
        if (fuzzed_data_provider.ConsumeBool()) {
            return std::vector<CTransactionRef>{valid_missing.front()};
        }
        return std::vector<CTransactionRef>{valid_missing.front(), valid_missing.back(), g_block->vtx.front()};
    };

    auto send_blocktxn = [&](CNode& peer, const uint256& hash,
                             const std::vector<CTransactionRef>& transactions)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        BlockTransactions response;
        response.blockhash = hash;
        response.txn = transactions;
        captured.Clear();
        ProcessMessage(connman, peer, NetMsg::Make(NetMsgType::BLOCKTXN, response));
        connman.FlushSendBuffer(peer);
    };

    // An unrequested peer and an unrelated block hash cannot consume another
    // peer's partial reconstruction or mutate its in-flight ownership.
    send_blocktxn(spare, g_block->GetHash(), valid_missing);
    captured.AssertEmpty();
    uint256 wrong_hash{g_block->GetHash()};
    wrong_hash.begin()[0] ^= 1;
    send_blocktxn(first, wrong_hash, valid_missing);
    captured.AssertEmpty();
    AssertInFlight(*peerman, first, true);
    AssertInFlight(*peerman, second, true);
    AssertInFlight(*peerman, parallel, true);

    CNode& first_secondary{fuzzed_data_provider.ConsumeBool() ? second : parallel};
    CNode& final_secondary{first_secondary.GetId() == second.GetId() ? parallel : second};
    const bool secondary_fails{fuzzed_data_provider.ConsumeBool()};
    send_blocktxn(first_secondary, g_block->GetHash(),
                  secondary_fails ? failed_missing : make_invalid_missing());
    captured.AssertEmpty();
    AssertInFlight(*peerman, first_secondary, false);
    AssertInFlight(*peerman, first, true);
    AssertInFlight(*peerman, final_secondary, true);

    const bool first_fails{fuzzed_data_provider.ConsumeBool()};
    send_blocktxn(first, g_block->GetHash(), first_fails ? failed_missing : make_invalid_missing());
    if (first_fails) {
        AssertFullBlockRequest(captured);
        AssertInFlight(*peerman, first, true);
        // FillBlock deliberately invalidates its partial header after a
        // collision. A second response must remove, rather than reuse, it.
        send_blocktxn(first, g_block->GetHash(), valid_missing);
        captured.AssertEmpty();
    } else {
        captured.AssertEmpty();
    }
    AssertInFlight(*peerman, first, false);
    AssertInFlight(*peerman, final_secondary, true);

    const bool final_fails{fuzzed_data_provider.ConsumeBool()};
    send_blocktxn(final_secondary, g_block->GetHash(),
                  final_fails ? failed_missing : make_invalid_missing());
    if (final_fails) {
        AssertFullBlockRequest(captured);
        AssertInFlight(*peerman, final_secondary, true);
        send_blocktxn(final_secondary, g_block->GetHash(), valid_missing);
        captured.AssertEmpty();
    } else {
        captured.AssertEmpty();
    }
    AssertInFlight(*peerman, final_secondary, false);

    for (CNode* peer : peers) AssertInFlight(*peerman, *peer, false);
    // A valid but late response after all ownership has been cleared is inert.
    send_blocktxn(first_secondary, g_block->GetHash(), valid_missing);
    captured.AssertEmpty();
    for (CNode* peer : peers) AssertInFlight(*peerman, *peer, false);

    CaptureMessage = capture_message_orig;
    connman.SetCaptureMessages(false);
    for (CNode* peer : peers) {
        peerman->FinalizeNode(*peer);
        CNodeStateStats stats;
        assert(!peerman->GetNodeStateStats(peer->GetId(), stats));
    }
    connman.ClearTestNodes();
    connman.SetMsgProc(nullptr);
    peerman.reset();

    chainman.CheckBlockIndex();
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size()) == block_index_size);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) == active_tip);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header) == best_header);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) == coins_tip);
    assert(WITH_LOCK(chainman.GetMutex(), return !(g_block_index->nStatus & BLOCK_HAVE_DATA)));
    assert(mempool.size() == mempool_size);
    assert(mempool.exists(g_block->vtx[1]->GetHash()));
    assert(WITH_LOCK(mempool.cs, return mempool.GetSequence()) == mempool_sequence);
}
