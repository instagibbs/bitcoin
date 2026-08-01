// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addrman.h>
#include <banman.h>
#include <net.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <node/mining_types.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/time.h>

#include <array>
#include <chrono>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
TestingSetup* g_setup;

constexpr std::array CONNECTION_TYPES{
    ConnectionType::INBOUND,
    ConnectionType::OUTBOUND_FULL_RELAY,
    ConnectionType::MANUAL,
    ConnectionType::BLOCK_RELAY,
};

void ProcessMessage(ConnmanTestMsg& connman, PeerManager& peerman, CNode& node, CSerializedNetMsg net_msg)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    connman.FlushSendBuffer(node);
    assert(connman.ReceiveMsgFrom(node, std::move(net_msg)));

    bool more_work{true};
    while (more_work) {
        node.fPauseSend = false;
        more_work = connman.ProcessMessagesOnce(node);
        peerman.SendMessages(node);
    }
}

void SendTipHeader(ConnmanTestMsg& connman, PeerManager& peerman, CNode& node, const CBlockIndex& tip)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    ProcessMessage(
        connman,
        peerman,
        node,
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{CBlock{tip.GetBlockHeader()}})));
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();
    FakeNodeClock clock{1610000000s};
    node::BlockCreateOptions options;
    assert(!MineBlock(g_setup->m_node, options).IsNull());
}
} // namespace

FUZZ_TARGET(p2p_chain_sync_timeout, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& connman{static_cast<ConnmanTestMsg&>(*node.connman)};
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    auto& mempool{*node.mempool};
    connman.Reset();
    // Keep the independent ping timeout from masking the chain-sync boundary.
    connman.SetPeerConnectTimeout(99999s);
    chainman.ResetIbd();
    FakeNodeClock clock{1610000000s};

    const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    CBlockIndex* const active_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    assert(active_tip);
    const uint256 coins_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock())};
    const size_t mempool_size{mempool.size()};
    const uint64_t mempool_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};

    node.banman.reset();
    node.addrman.reset();
    node.peerman.reset();
    node.addrman = std::make_unique<AddrMan>(
        *node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0);
    node.peerman = PeerManager::make(connman, *node.addrman,
                                     /*banman=*/nullptr, chainman,
                                     mempool, *node.warnings,
                                     PeerManager::Options{
                                         .reconcile_txs = true,
                                         .deterministic_rng = true,
                                     });
    connman.SetMsgProc(node.peerman.get());
    connman.SetAddrman(*node.addrman);

    LOCK(NetEventsInterface::g_msgproc_mutex);

    const ConnectionType connection_type{PickValue(fuzzed_data_provider, CONNECTION_TYPES)};
    // 0: never catch up; 1: catch up before the timeout; 2: answer the final
    // challenge; 3: catch up only to the benchmark while our own tip advances.
    const int response_phase{fuzzed_data_provider.ConsumeIntegralInRange(0, 3)};
    const bool advance_chain{response_phase == 3};
    const CBlockIndex* benchmark_tip{active_tip};
    if (advance_chain) {
        BlockValidationState state;
        assert(chainman.ActiveChainstate().InvalidateBlock(state, active_tip));
        assert(state.IsValid());
        benchmark_tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip());
        assert(benchmark_tip == active_tip->pprev);
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) == benchmark_tip->GetBlockHash());
    }
    constexpr NodeId peer_id{std::numeric_limits<NodeId>::max()};
    assert(connman.TestNodes().empty());
    auto peer{std::make_unique<CNode>(
        /*id=*/peer_id,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CService{},
        /*addrNameIn=*/"",
        connection_type,
        /*inbound_onion=*/false,
        /*network_key=*/0)};

    size_t getheaders_count{0};
    connman.SetCaptureMessages(true);
    const auto capture_message_orig{CaptureMessage};
    CaptureMessage = [&](const CAddress&, const std::string& msg_type,
                         std::span<const unsigned char>, bool is_incoming) {
        if (!is_incoming && msg_type == NetMsgType::GETHEADERS) ++getheaders_count;
    };

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

    CNodeStateStats stats;
    assert(node.peerman->GetNodeStateStats(peer_id, stats));
    assert(stats.nSyncHeight == -1);
    assert(stats.nCommonHeight == -1);
    assert(stats.vHeightInFlight.empty());
    assert(stats.their_services == services);
    assert(stats.m_relay_txs == !peer->IsBlockOnlyConn());

    connman.FlushSendBuffer(*peer);
    getheaders_count = 0;

    clock += 20min - 1s;
    if (response_phase == 1) {
        SendTipHeader(connman, *node.peerman, *peer, *active_tip);
        assert(!peer->fDisconnect);
        assert(node.peerman->GetNodeStateStats(peer_id, stats));
        assert(stats.nSyncHeight == active_tip->nHeight);
        assert(stats.vHeightInFlight.empty());
        connman.FlushSendBuffer(*peer);
        getheaders_count = 0;
    }
    assert(node.peerman->SendMessages(*peer));
    assert(!peer->fDisconnect);
    assert(getheaders_count == 0);
    connman.FlushSendBuffer(*peer);

    clock += 1s;
    assert(node.peerman->SendMessages(*peer));
    assert(!peer->fDisconnect);
    assert(getheaders_count == 0);
    connman.FlushSendBuffer(*peer);

    clock += 1s;
    assert(node.peerman->SendMessages(*peer));
    assert(!peer->fDisconnect);
    const bool eviction_candidate{peer->IsOutboundOrBlockRelayConn()};
    assert(getheaders_count == (eviction_candidate && response_phase != 1 ? 1 : 0));

    if (response_phase == 2) {
        SendTipHeader(connman, *node.peerman, *peer, *active_tip);
        assert(!peer->fDisconnect);
        assert(node.peerman->GetNodeStateStats(peer_id, stats));
        assert(stats.nSyncHeight == active_tip->nHeight);
        assert(stats.vHeightInFlight.empty());
    } else if (advance_chain) {
        {
            LOCK(chainman.GetMutex());
            chainman.ActiveChainstate().ResetBlockFailureFlags(active_tip);
            chainman.RecalculateBestHeader();
        }
        BlockValidationState state;
        assert(chainman.ActiveChainstate().ActivateBestChain(state));
        assert(state.IsValid());
        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) == active_tip);
        SendTipHeader(connman, *node.peerman, *peer, *benchmark_tip);
        assert(!peer->fDisconnect);
        assert(node.peerman->GetNodeStateStats(peer_id, stats));
        assert(stats.nSyncHeight == benchmark_tip->nHeight);
        assert(stats.vHeightInFlight.empty());
    }
    connman.FlushSendBuffer(*peer);
    getheaders_count = 0;

    clock += 2min;
    assert(node.peerman->SendMessages(*peer));
    assert(!peer->fDisconnect);
    connman.FlushSendBuffer(*peer);

    clock += 1s;
    assert(node.peerman->SendMessages(*peer));
    assert(peer->fDisconnect == (eviction_candidate && response_phase == 0));

    if (advance_chain) {
        connman.FlushSendBuffer(*peer);
        getheaders_count = 0;

        // Catching up only to the old benchmark starts a fresh full timeout
        // against our advanced tip, followed by the same final-response grace.
        clock += 17min + 59s;
        assert(node.peerman->SendMessages(*peer));
        assert(!peer->fDisconnect);
        assert(getheaders_count == 0);
        connman.FlushSendBuffer(*peer);

        clock += 1s;
        assert(node.peerman->SendMessages(*peer));
        assert(!peer->fDisconnect);
        assert(getheaders_count == (eviction_candidate ? 1 : 0));
        connman.FlushSendBuffer(*peer);

        clock += 2min;
        assert(node.peerman->SendMessages(*peer));
        assert(!peer->fDisconnect);

        clock += 1s;
        assert(node.peerman->SendMessages(*peer));
        assert(peer->fDisconnect == eviction_candidate);
    }

    CaptureMessage = capture_message_orig;
    connman.SetCaptureMessages(false);
    assert(connman.TestNodes().empty());
    node.peerman->FinalizeNode(*peer);
    assert(!node.peerman->GetNodeStateStats(peer_id, stats));
    peer.reset();

    chainman.CheckBlockIndex();
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size()) == block_index_size);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) == active_tip);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) == coins_tip);
    assert(mempool.size() == mempool_size);
    assert(WITH_LOCK(mempool.cs, return mempool.GetSequence()) == mempool_sequence);
}
