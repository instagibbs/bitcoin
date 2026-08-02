// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addrman.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <kernel/mempool_removal_reason.h>
#include <net.h>
#include <net_processing.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <txmempool.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>

namespace {
using namespace std::chrono_literals;

TestChain100Setup* g_setup;
COutPoint g_funding_outpoint;
CAmount g_funding_value;

struct TxPair {
    CTransactionRef parent;
    CTransactionRef child;
};

void initialize()
{
    static const auto testing_setup{
        MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();

    const CBlock funding{g_setup->CreateAndProcessBlock({}, P2WSH_OP_TRUE)};
    g_funding_outpoint = COutPoint{funding.vtx.at(0)->GetHash(), 0};
    g_funding_value = funding.vtx.at(0)->vout.at(0).nValue;
    g_setup->mineBlocks(100);

    auto& chainman{static_cast<TestChainstateManager&>(*g_setup->m_node.chainman)};
    const Coin coin{WITH_LOCK(
        chainman.GetMutex(),
        return chainman.ActiveChainstate().CoinsTip().AccessCoin(g_funding_outpoint))};
    assert(!coin.IsSpent());
    assert(coin.out.nValue == g_funding_value);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Height()) >=
           COINBASE_MATURITY + 1);
    chainman.CheckBlockIndex();
}

CNode* MakePeer(NodeId id)
{
    in_addr address{};
    address.s_addr = htonl(0x0a000001U + static_cast<uint32_t>(id));
    return new CNode{
        id,
        /*sock=*/nullptr,
        CAddress{CService{address, static_cast<uint16_t>(18444 + id)}, NODE_NETWORK},
        /*nKeyedNetGroupIn=*/static_cast<uint64_t>(id),
        /*nLocalHostNonceIn=*/0,
        CService{},
        /*addrNameIn=*/"",
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false,
        /*network_key=*/static_cast<uint64_t>(id + 1),
        CNodeOptions{.permission_flags = NetPermissionFlags::NoBan},
    };
}

void Handshake(ConnmanTestMsg& connman, PeerManager& peerman, CNode& peer, bool wtxid_relay)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    constexpr ServiceFlags services{NODE_NETWORK | NODE_WITNESS};
    if (!wtxid_relay) {
        connman.Handshake(peer, /*successfully_connected=*/true, services, services,
                          PROTOCOL_VERSION, /*relay_txs=*/true);
    } else {
        connman.Handshake(peer, /*successfully_connected=*/false, services, services,
                          PROTOCOL_VERSION, /*relay_txs=*/true);
        assert(connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::WTXIDRELAY)));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        assert(connman.ReceiveMsgFrom(peer, NetMsg::Make(NetMsgType::VERACK)));
        peer.fPauseSend = false;
        (void)connman.ProcessMessagesOnce(peer);
        assert(peerman.SendMessages(peer));
    }
    assert(peer.fSuccessfullyConnected);
    assert(!peer.fDisconnect);
    connman.FlushSendBuffer(peer);
}

TxPair MakeTxPair(uint8_t scenario, bool version_three, bool invalid_witness)
{
    const bool standalone_parent{scenario == 2 || scenario == 3};
    const bool sponsored_child{scenario != 1};
    const bool invalid_child{scenario == 3 || scenario == 5};
    const CAmount parent_fee{standalone_parent ? 2'000 : 0};
    const CAmount child_fee{sponsored_child ? 4'000 : 0};

    CMutableTransaction parent;
    parent.version = version_three ? 3 : 2;
    parent.nLockTime = scenario;
    parent.vin.emplace_back(g_funding_outpoint);
    parent.vin.front().nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    parent.vin.front().scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
    parent.vout.emplace_back(g_funding_value - parent_fee, P2WSH_OP_TRUE);

    CMutableTransaction child;
    child.version = version_three ? 3 : 2;
    child.nLockTime = scenario;
    child.vin.emplace_back(COutPoint{parent.GetHash(), 0});
    child.vin.front().nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
    child.vin.front().scriptWitness.stack.push_back(
        invalid_witness ? std::vector<uint8_t>{uint8_t{OP_FALSE}} : WITNESS_STACK_ELEM_OP_TRUE);
    const CAmount child_value{
        invalid_child && !invalid_witness ? parent.vout.front().nValue + 1 :
                                            parent.vout.front().nValue - child_fee};
    child.vout.emplace_back(child_value, P2WSH_OP_TRUE);

    return {MakeTransactionRef(std::move(parent)), MakeTransactionRef(std::move(child))};
}

void DrainMessages(ConnmanTestMsg& connman, PeerManager& peerman,
                   const std::array<CNode*, 2>& peers)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    size_t idle_sweeps{0};
    size_t sweeps{0};
    while (idle_sweeps < 2) {
        bool more_work{false};
        for (CNode* peer : peers) {
            peer->fPauseSend = false;
            more_work |= connman.ProcessMessagesOnce(*peer);
            assert(peerman.SendMessages(*peer));
            connman.FlushSendBuffer(*peer);
        }
        idle_sweeps = more_work ? 0 : idle_sweeps + 1;
        assert(++sweeps <= 16);
    }
}

void SendTransaction(ConnmanTestMsg& connman, PeerManager& peerman,
                     const std::array<CNode*, 2>& peers, size_t sender,
                     const CTransactionRef& tx)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    assert(sender < peers.size());
    assert(connman.ReceiveMsgFrom(
        *peers[sender], NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx))));
    DrainMessages(connman, peerman, peers);
}

void SendInventory(ConnmanTestMsg& connman, PeerManager& peerman,
                   const std::array<CNode*, 2>& peers, size_t sender,
                   const CTransactionRef& tx, bool wtxid_relay)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    const CInv inventory{
        wtxid_relay ? MSG_WTX : MSG_TX,
        wtxid_relay ? tx->GetWitnessHash().ToUint256() : tx->GetHash().ToUint256()};
    assert(connman.ReceiveMsgFrom(
        *peers[sender], NetMsg::Make(NetMsgType::INV, std::vector<CInv>{inventory})));
    DrainMessages(connman, peerman, peers);
}

void AssertOrphan(PeerManager& peerman, const CTransactionRef& child, NodeId sender)
{
    const auto orphans{peerman.GetOrphanTransactions()};
    assert(orphans.size() == 1);
    assert(orphans.front().tx->GetWitnessHash() == child->GetWitnessHash());
    assert(orphans.front().announcers == std::set<NodeId>{sender});
}

void AssertOrphan(PeerManager& peerman, const CTransactionRef& child,
                  const std::set<NodeId>& senders)
{
    const auto orphans{peerman.GetOrphanTransactions()};
    assert(orphans.size() == 1);
    assert(orphans.front().tx->GetWitnessHash() == child->GetWitnessHash());
    assert(orphans.front().announcers == senders);
}
} // namespace

FUZZ_TARGET(p2p_orphan_package, .init = ::initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    auto& mempool{*node.mempool};
    assert(mempool.size() == 0);
    chainman.ResetIbd();
    chainman.JumpOutOfIbd();

    const uint8_t scenario{fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 5)};
    const bool duplicate_parent{scenario == 4};
    const bool package_path{scenario != 2 && scenario != 3};
    const bool invalid_child{scenario == 3 || scenario == 5};
    const bool invalid_witness{invalid_child && fuzzed_data_provider.ConsumeBool()};
    const bool version_three{fuzzed_data_provider.ConsumeBool()};
    const bool wtxid_relay{fuzzed_data_provider.ConsumeBool()};
    const size_t child_sender{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1)};
    const size_t parent_sender{
        wtxid_relay && fuzzed_data_provider.ConsumeBool() ? 1 - child_sender : child_sender};
    const TxPair pair{MakeTxPair(scenario, version_three, invalid_witness)};

    const CBlockIndex* const active_tip{
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    const uint256 coins_tip{WITH_LOCK(
        chainman.GetMutex(),
        return chainman.ActiveChainstate().CoinsTip().GetBestBlock())};
    const auto block_index_size{
        WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    assert(active_tip);
    g_setup->m_clock.set(active_tip->Time() + 1s);

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
    std::array<CNode*, 2> peers{MakePeer(/*id=*/0), MakePeer(/*id=*/1)};
    for (CNode* peer : peers) {
        connman.AddTestNode(*peer);
        Handshake(connman, *peerman, *peer, wtxid_relay);
    }

    if (duplicate_parent) {
        SendTransaction(connman, *peerman, peers, parent_sender, pair.parent);
        assert(!mempool.exists(pair.parent->GetHash()));
        assert(peerman->GetOrphanTransactions().empty());
    }

    SendTransaction(connman, *peerman, peers, child_sender, pair.child);
    assert(!mempool.exists(pair.child->GetHash()));
    AssertOrphan(*peerman, pair.child, peers[child_sender]->GetId());
    if (package_path && parent_sender != child_sender) {
        SendInventory(connman, *peerman, peers, parent_sender, pair.child, wtxid_relay);
        assert(!mempool.exists(pair.child->GetHash()));
        AssertOrphan(*peerman, pair.child,
                     {peers[child_sender]->GetId(), peers[parent_sender]->GetId()});
    }

    SendTransaction(connman, *peerman, peers, parent_sender, pair.parent);

    const bool parent_present{mempool.exists(pair.parent->GetHash())};
    const bool child_present{mempool.exists(pair.child->GetHash())};
    const auto orphans{peerman->GetOrphanTransactions()};
    assert(!child_present || parent_present);
    assert(std::ranges::none_of(orphans, [&](const auto& orphan) {
        return mempool.exists(orphan.tx->GetHash());
    }));
    assert(orphans.size() <= 1);
    if (!orphans.empty()) {
        assert(orphans.front().tx->GetWitnessHash() == pair.child->GetWitnessHash());
        assert(!orphans.front().announcers.empty());
    }
    if (scenario == 0 || scenario == 2 || scenario == 4) {
        assert(parent_present);
        assert(child_present);
        assert(orphans.empty());
    } else if (invalid_child) {
        assert(!child_present);
    } else {
        assert(!parent_present);
        assert(!child_present);
    }

    const size_t stable_mempool_size{mempool.size()};
    const size_t stable_orphan_count{orphans.size()};
    DrainMessages(connman, *peerman, peers);
    assert(mempool.size() == stable_mempool_size);
    assert(peerman->GetOrphanTransactions().size() == stable_orphan_count);
    for (CNode* peer : peers) {
        assert(!peer->fDisconnect);
        peerman->FinalizeNode(*peer);
        CNodeStateStats stats;
        assert(!peerman->GetNodeStateStats(peer->GetId(), stats));
    }
    connman.ClearTestNodes();
    connman.SetMsgProc(nullptr);
    peerman.reset();

    WITH_LOCK(mempool.cs, {
        mempool.removeRecursive(*pair.parent, MemPoolRemovalReason::REPLACED);
        mempool.removeRecursive(*pair.child, MemPoolRemovalReason::REPLACED);
    });
    assert(mempool.size() == 0);
    chainman.CheckBlockIndex();
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) ==
           active_tip);
    assert(WITH_LOCK(
               chainman.GetMutex(),
               return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) == coins_tip);
    assert(WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size()) ==
           block_index_size);
    WITH_LOCK(
        chainman.GetMutex(),
        mempool.check(chainman.ActiveChainstate().CoinsTip(), active_tip->nHeight + 1));
    chainman.ResetIbd();
}
