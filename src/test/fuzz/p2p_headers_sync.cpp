// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addrman.h>
#include <chain.h>
#include <net.h>
#include <net_processing.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <util/time.h>
#include <validation.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace std::chrono_literals;

constexpr std::array CONNECTION_TYPES{
    ConnectionType::INBOUND,
    ConnectionType::OUTBOUND_FULL_RELAY,
    ConnectionType::MANUAL,
    ConnectionType::BLOCK_RELAY,
};

TestingSetup* g_setup;

CNode& AddPeer(ConnmanTestMsg& connman, PeerManager& peerman, std::vector<CNode*>& nodes,
               NodeId id, ConnectionType connection_type, bool noban)
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
        /*network_key=*/0,
        CNodeOptions{
            .permission_flags = noban ? NetPermissionFlags::NoBan : NetPermissionFlags::None,
        }}};
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

    CNodeStateStats stats;
    assert(peerman.GetNodeStateStats(id, stats));
    assert(stats.nSyncHeight == -1);
    assert(stats.nCommonHeight == -1);
    assert(stats.vHeightInFlight.empty());
    assert(stats.their_services == services);
    assert(stats.m_relay_txs == !peer->IsBlockOnlyConn());
    connman.FlushSendBuffer(*peer);
    return *peer;
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();
}
} // namespace

FUZZ_TARGET(p2p_headers_sync_timeout, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    auto& mempool{*node.mempool};
    chainman.ResetIbd();

    const int scenario{fuzzed_data_provider.ConsumeIntegralInRange(0, 3)};
    const ConnectionType connection_type{PickValue(fuzzed_data_provider, CONNECTION_TYPES)};
    const bool retry_noban_peer{fuzzed_data_provider.ConsumeBool()};
    const bool fresh_header{scenario == 3};
    const bool noban{scenario == 1};
    const bool delayed_alternative{scenario == 2};

    CBlockIndex* const active_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    const CBlockIndex* const best_header{WITH_LOCK(chainman.GetMutex(), return chainman.m_best_header)};
    const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    const uint256 coins_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChainstate().CoinsTip().GetBestBlock())};
    const size_t mempool_size{mempool.size()};
    const uint64_t mempool_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};
    assert(active_tip);
    assert(best_header == active_tip);

    // 600,000 seconds corresponds to exactly 1,000 expected headers and thus
    // exactly one second beyond the fixed 15-minute timeout. The fresh lane
    // remains inside the 24-hour freshness threshold at that boundary.
    constexpr auto stale_header_age{600000s};
    constexpr auto fresh_header_age{23h};
    FakeNodeClock clock{best_header->Time() + (fresh_header ? fresh_header_age : stale_header_age)};

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

    size_t sync_getheaders_count{0};
    size_t chain_challenge_count{0};
    const auto capture_message_orig{CaptureMessage};
    connman.SetCaptureMessages(true);
    CaptureMessage = [&](const CAddress&, const std::string& msg_type,
                         std::span<const unsigned char> data, bool is_incoming) {
        if (is_incoming || msg_type != NetMsgType::GETHEADERS) return;
        CBlockLocator locator;
        uint256 stop_hash;
        SpanReader reader{data};
        reader >> locator >> stop_hash;
        assert(reader.empty());
        assert(stop_hash.IsNull());
        if (locator.vHave.empty()) {
            ++chain_challenge_count;
        } else {
            assert(locator.vHave.size() == 1);
            assert(locator.vHave.front() == active_tip->GetBlockHash());
            ++sync_getheaders_count;
        }
    };

    std::vector<CNode*> peers;
    std::vector<bool> finalized;
    CNode& sync_peer{AddPeer(connman, *peerman, peers, /*id=*/0, connection_type, noban)};
    finalized.push_back(false);
    assert(sync_getheaders_count == 1);
    assert(chain_challenge_count == 0);
    sync_getheaders_count = 0;

    CNode* alternative{nullptr};
    if (!delayed_alternative) {
        alternative = &AddPeer(connman, *peerman, peers, /*id=*/1,
                               ConnectionType::OUTBOUND_FULL_RELAY, /*noban=*/false);
        finalized.push_back(false);
        assert(sync_getheaders_count == (fresh_header ? 1 : 0));
        assert(chain_challenge_count == 0);
        sync_getheaders_count = 0;
    }

    // The stale lane's variable component is exactly one second. The fresh
    // lane has a sub-second component but is disabled by header freshness
    // before it can expire.
    clock += 15min;
    assert(peerman->SendMessages(sync_peer));
    assert(!sync_peer.fDisconnect);
    assert(sync_getheaders_count == 0);
    assert(chain_challenge_count == 0);

    clock += 1s;
    assert(peerman->SendMessages(sync_peer));
    assert(!sync_peer.fDisconnect);
    assert(sync_getheaders_count == 0);
    assert(chain_challenge_count == 0);

    clock += 1s;
    assert(peerman->SendMessages(sync_peer));
    assert(sync_getheaders_count == 0);
    assert(chain_challenge_count == 0);

    if (fresh_header) {
        assert(!sync_peer.fDisconnect);
        // Once freshness disables the timer, merely aging past 24 hours must
        // not resurrect the obsolete deadline.
        clock += 2h;
        assert(peerman->SendMessages(sync_peer));
        assert(!sync_peer.fDisconnect);
        assert(sync_getheaders_count == 0);
        assert(chain_challenge_count == (sync_peer.IsOutboundOrBlockRelayConn() ? 1 : 0));
        chain_challenge_count = 0;
    } else if (delayed_alternative) {
        // A sole sync peer is retained even after expiry.
        assert(!sync_peer.fDisconnect);
        alternative = &AddPeer(connman, *peerman, peers, /*id=*/1,
                               ConnectionType::OUTBOUND_FULL_RELAY, /*noban=*/false);
        finalized.push_back(false);
        assert(sync_getheaders_count == 0);
        assert(chain_challenge_count == 0);

        assert(peerman->SendMessages(sync_peer));
        assert(sync_peer.fDisconnect);
        assert(sync_getheaders_count == 0);
        assert(chain_challenge_count == 0);
        peerman->FinalizeNode(sync_peer);
        finalized[0] = true;

        assert(peerman->SendMessages(*alternative));
        assert(!alternative->fDisconnect);
        assert(sync_getheaders_count == 1);
        assert(chain_challenge_count == 0);
        sync_getheaders_count = 0;
    } else if (noban) {
        assert(!sync_peer.fDisconnect);
        CNode& retry_peer{retry_noban_peer ? sync_peer : *alternative};
        assert(peerman->SendMessages(retry_peer));
        assert(!retry_peer.fDisconnect);
        assert(sync_getheaders_count == 1);
        assert(chain_challenge_count == 0);
        sync_getheaders_count = 0;
    } else {
        assert(sync_peer.fDisconnect);
        peerman->FinalizeNode(sync_peer);
        finalized[0] = true;

        assert(peerman->SendMessages(*alternative));
        assert(!alternative->fDisconnect);
        assert(sync_getheaders_count == 1);
        assert(chain_challenge_count == 0);
        sync_getheaders_count = 0;
    }

    CaptureMessage = capture_message_orig;
    connman.SetCaptureMessages(false);
    assert(peers.size() == finalized.size());
    for (size_t i{0}; i < peers.size(); ++i) {
        if (!finalized[i]) peerman->FinalizeNode(*peers[i]);
        CNodeStateStats stats;
        assert(!peerman->GetNodeStateStats(peers[i]->GetId(), stats));
    }
    connman.ClearTestNodes();
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
