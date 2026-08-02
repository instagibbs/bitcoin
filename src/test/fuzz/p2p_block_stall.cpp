// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addrman.h>
#include <chain.h>
#include <kernel/types.h>
#include <net.h>
#include <netmessagemaker.h>
#include <net_processing.h>
#include <protocol.h>
#include <streams.h>
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
#include <validation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;

constexpr size_t BLOCK_DOWNLOAD_WINDOW{1024};
constexpr size_t MAX_BLOCKS_IN_TRANSIT_PER_PEER{16};
constexpr auto BLOCK_STALLING_TIMEOUT_DEFAULT{2s};
constexpr auto BLOCK_STALLING_TIMEOUT_MAX{64s};

enum class BlockConnectedMode : uint8_t {
    NONE,
    ACTIVE,
    HISTORICAL,
    IBD,
};

constexpr std::array CONNECTION_TYPES{
    ConnectionType::INBOUND,
    ConnectionType::OUTBOUND_FULL_RELAY,
    ConnectionType::MANUAL,
    ConnectionType::BLOCK_RELAY,
};

TestingSetup* g_setup;
const std::vector<std::shared_ptr<CBlock>>* g_blocks;
std::vector<const CBlockIndex*> g_block_indexes;

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

CNode& AddPeer(ConnmanTestMsg& connman, PeerManager& peerman, std::vector<CNode*>& nodes,
               NodeId id, ConnectionType connection_type, const CBlockIndex& tip)
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
    nodes.push_back(peer);
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

    ProcessMessage(
        connman,
        *peer,
        NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{CBlock{tip.GetBlockHeader()}})));
    assert(!peer->fDisconnect);

    CNodeStateStats stats;
    assert(peerman.GetNodeStateStats(id, stats));
    assert(stats.nSyncHeight == tip.nHeight);
    assert(stats.vHeightInFlight.empty());
    assert(stats.their_services == services);
    assert(stats.m_relay_txs == !peer->IsBlockOnlyConn());
    connman.FlushSendBuffer(*peer);
    return *peer;
}

CNodeStateStats GetStats(PeerManager& peerman, NodeId id)
{
    CNodeStateStats stats;
    assert(peerman.GetNodeStateStats(id, stats));
    return stats;
}

void AssertInFlight(const CNodeStateStats& stats, size_t first_height, size_t count)
{
    assert(stats.vHeightInFlight.size() == count);
    for (size_t i{0}; i < count; ++i) {
        assert(stats.vHeightInFlight[i] == static_cast<int>(first_height + i));
    }
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();
    auto& chainman{static_cast<TestChainstateManager&>(*g_setup->m_node.chainman)};

    static const auto blocks{CreateBlockChain(BLOCK_DOWNLOAD_WINDOW + 1, chainman.GetParams())};
    g_blocks = &blocks;
    const FakeNodeClock clock{blocks.back()->Time()};

    g_block_indexes.reserve(blocks.size());
    for (const auto& block : blocks) {
        BlockValidationState state;
        assert(chainman.ProcessNewBlockHeaders({{*block}}, /*min_pow_checked=*/true, state));
        assert(state.IsValid());
        const CBlockIndex* index{WITH_LOCK(chainman.GetMutex(), return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
        assert(index);
        g_block_indexes.push_back(index);
    }
    assert(g_block_indexes.back()->nHeight == static_cast<int>(BLOCK_DOWNLOAD_WINDOW + 1));
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header) == g_block_indexes.back());
    chainman.CheckBlockIndex();
}

void FinalizePeers(ConnmanTestMsg& connman, PeerManager& peerman,
                   const std::vector<CNode*>& nodes, std::vector<bool>& finalized)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    assert(nodes.size() == finalized.size());
    for (size_t i{0}; i < nodes.size(); ++i) {
        if (!finalized[i]) {
            peerman.FinalizeNode(*nodes[i]);
            finalized[i] = true;
        }
        CNodeStateStats stats;
        assert(!peerman.GetNodeStateStats(nodes[i]->GetId(), stats));
    }
    connman.ClearTestNodes();
}
} // namespace

FUZZ_TARGET(p2p_block_stall, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    auto& mempool{*node.mempool};
    chainman.ResetIbd();
    FakeNodeClock clock{g_blocks->back()->Time()};

    const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    CBlockIndex* const active_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    const CBlockIndex* const best_header{WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header)};
    const uint256 coins_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock())};
    const size_t mempool_size{mempool.size()};
    const uint64_t mempool_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};
    assert(active_tip);
    assert(best_header == g_block_indexes.back());

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

    const bool test_stalling_window{fuzzed_data_provider.ConsumeBool()};
    const ConnectionType first_connection_type{PickValue(fuzzed_data_provider, CONNECTION_TYPES)};
    const size_t rounds{test_stalling_window ? fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 6) : 1};
    const size_t peer_count{test_stalling_window ? rounds + 1 : fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 4) + 1};
    const BlockConnectedMode block_connected_mode{
        test_stalling_window ?
            static_cast<BlockConnectedMode>(fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 3)) :
            BlockConnectedMode::NONE};

    std::vector<CNode*> peers;
    std::vector<bool> finalized(peer_count, false);
    peers.reserve(peer_count);
    for (size_t i{0}; i < peer_count; ++i) {
        AddPeer(connman, *peerman, peers, static_cast<NodeId>(i),
                i == 0 ? first_connection_type : ConnectionType::OUTBOUND_FULL_RELAY,
                *best_header);
    }

    std::optional<CInv> expected_single_getdata;
    std::vector<CInv> expected_batch_getdata;
    size_t captured_getdata{0};
    const auto capture_message_orig{CaptureMessage};
    connman.SetCaptureMessages(true);
    CaptureMessage = [&](const CAddress&, const std::string& msg_type,
                         std::span<const unsigned char> data, bool is_incoming) {
        if (is_incoming || msg_type != NetMsgType::GETDATA) return;
        std::vector<CInv> invs;
        SpanReader{data} >> invs;
        assert(captured_getdata == 0);
        if (expected_single_getdata) {
            assert(invs.size() == 1);
            assert(invs[0].type == expected_single_getdata->type);
            assert(invs[0].hash == expected_single_getdata->hash);
        } else {
            assert(!expected_batch_getdata.empty());
            assert(invs.size() == expected_batch_getdata.size());
            for (size_t i{0}; i < invs.size(); ++i) {
                assert(invs[i].type == expected_batch_getdata[i].type);
                assert(invs[i].hash == expected_batch_getdata[i].hash);
            }
        }
        ++captured_getdata;
    };

    auto fetch_block = [&](CNode& peer, size_t index) {
        assert(index < BLOCK_DOWNLOAD_WINDOW);
        const CBlockIndex& block_index{*g_block_indexes[index]};
        expected_single_getdata = CInv{MSG_BLOCK | MSG_WITNESS_FLAG, block_index.GetBlockHash()};
        captured_getdata = 0;
        assert(peerman->FetchBlock(peer.GetId(), block_index).has_value());
        assert(captured_getdata == 1);
        expected_single_getdata.reset();
        connman.FlushSendBuffer(peer);
    };

    if (test_stalling_window) {
        auto stalling_timeout{BLOCK_STALLING_TIMEOUT_DEFAULT};
        size_t block_connected_calls{0};
        for (size_t round{0}; round < rounds; ++round) {
            CNode& staller{*peers[round]};
            CNode& waiter{*peers[round + 1]};

            for (size_t i{0}; i < BLOCK_DOWNLOAD_WINDOW; ++i) fetch_block(staller, i);
            AssertInFlight(GetStats(*peerman, staller.GetId()), /*first_height=*/1, BLOCK_DOWNLOAD_WINDOW);
            if (round > 0) {
                assert(GetStats(*peerman, peers[round - 1]->GetId()).vHeightInFlight.empty());
            }

            captured_getdata = 0;
            assert(peerman->SendMessages(waiter));
            assert(captured_getdata == 0);
            assert(!waiter.fDisconnect);
            const auto waiter_stats{GetStats(*peerman, waiter.GetId())};
            assert(waiter_stats.nCommonHeight == active_tip->nHeight);
            assert(waiter_stats.vHeightInFlight.empty());

            clock += stalling_timeout - 1s;
            // Re-evaluating the same blocked window must preserve the original
            // stall start instead of extending the peer's deadline.
            assert(peerman->SendMessages(waiter));
            assert(captured_getdata == 0);
            assert(!waiter.fDisconnect);
            assert(peerman->SendMessages(staller));
            assert(!staller.fDisconnect);
            assert(captured_getdata == 0);

            clock += 1s;
            assert(peerman->SendMessages(staller));
            assert(!staller.fDisconnect);
            assert(captured_getdata == 0);

            clock += 1s;
            assert(peerman->SendMessages(staller));
            assert(staller.fDisconnect);
            assert(captured_getdata == 0);
            stalling_timeout = std::min(2 * stalling_timeout, BLOCK_STALLING_TIMEOUT_MAX);

            if (block_connected_mode != BlockConnectedMode::NONE && round + 1 < rounds) {
                kernel::ChainstateRole role;
                role.historical = block_connected_mode == BlockConnectedMode::HISTORICAL;
                assert(chainman.IsInitialBlockDownload());
                if (block_connected_mode == BlockConnectedMode::ACTIVE) {
                    chainman.JumpOutOfIbd();
                }
                ValidationInterfaceTest::BlockConnected(
                    role, *peerman, g_blocks->front(), g_block_indexes.front());
                ++block_connected_calls;
                if (block_connected_mode == BlockConnectedMode::ACTIVE) {
                    chainman.ResetIbd();
                }
                assert(chainman.IsInitialBlockDownload());
                stalling_timeout = std::max(
                    std::chrono::duration_cast<std::chrono::seconds>(stalling_timeout * 0.85),
                    BLOCK_STALLING_TIMEOUT_DEFAULT);
            }
        }
        assert(block_connected_calls ==
               (block_connected_mode == BlockConnectedMode::NONE ? 0 : rounds - 1));

        CNode& final_staller{*peers[rounds - 1]};
        CNode& final_waiter{*peers[rounds]};
        AssertInFlight(GetStats(*peerman, final_staller.GetId()), /*first_height=*/1, BLOCK_DOWNLOAD_WINDOW);
        peerman->FinalizeNode(final_staller);
        finalized[rounds - 1] = true;

        expected_batch_getdata.clear();
        for (size_t i{0}; i < MAX_BLOCKS_IN_TRANSIT_PER_PEER; ++i) {
            expected_batch_getdata.emplace_back(MSG_BLOCK | MSG_WITNESS_FLAG, g_block_indexes[i]->GetBlockHash());
        }
        captured_getdata = 0;
        assert(peerman->SendMessages(final_waiter));
        assert(!final_waiter.fDisconnect);
        assert(captured_getdata == 1);
        expected_batch_getdata.clear();
        AssertInFlight(GetStats(*peerman, final_waiter.GetId()), /*first_height=*/1, MAX_BLOCKS_IN_TRANSIT_PER_PEER);
    } else {
        const size_t downloading_peers{peer_count - 1};
        CNode& target{*peers[0]};
        for (size_t i{0}; i < MAX_BLOCKS_IN_TRANSIT_PER_PEER; ++i) fetch_block(target, i);
        for (size_t peer_index{1}; peer_index < downloading_peers; ++peer_index) {
            fetch_block(*peers[peer_index], MAX_BLOCKS_IN_TRANSIT_PER_PEER + peer_index - 1);
        }
        AssertInFlight(GetStats(*peerman, target.GetId()), /*first_height=*/1, MAX_BLOCKS_IN_TRANSIT_PER_PEER);

        const auto download_timeout{10min + 5min * (downloading_peers - 1)};
        captured_getdata = 0;
        clock += download_timeout - 1s;
        assert(peerman->SendMessages(target));
        assert(!target.fDisconnect);
        assert(captured_getdata == 0);

        clock += 1s;
        assert(peerman->SendMessages(target));
        assert(!target.fDisconnect);
        assert(captured_getdata == 0);

        clock += 1s;
        assert(peerman->SendMessages(target));
        assert(target.fDisconnect);
        assert(captured_getdata == 0);

        peerman->FinalizeNode(target);
        finalized[0] = true;
        CNode& verifier{*peers.back()};
        expected_batch_getdata.clear();
        for (size_t i{0}; i < MAX_BLOCKS_IN_TRANSIT_PER_PEER; ++i) {
            expected_batch_getdata.emplace_back(MSG_BLOCK | MSG_WITNESS_FLAG, g_block_indexes[i]->GetBlockHash());
        }
        captured_getdata = 0;
        assert(peerman->SendMessages(verifier));
        assert(!verifier.fDisconnect);
        assert(captured_getdata == 1);
        expected_batch_getdata.clear();
        AssertInFlight(GetStats(*peerman, verifier.GetId()), /*first_height=*/1, MAX_BLOCKS_IN_TRANSIT_PER_PEER);
    }

    CaptureMessage = capture_message_orig;
    connman.SetCaptureMessages(false);
    FinalizePeers(connman, *peerman, peers, finalized);
    connman.SetMsgProc(nullptr);
    peerman.reset();

    chainman.CheckBlockIndex();
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size()) == block_index_size);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) == active_tip);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header) == best_header);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) == coins_tip);
    assert(mempool.size() == mempool_size);
    assert(WITH_LOCK(mempool.cs, return mempool.GetSequence()) == mempool_sequence);
}
