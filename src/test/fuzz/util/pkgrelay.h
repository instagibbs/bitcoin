// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_PKGRELAY_H
#define BITCOIN_TEST_FUZZ_UTIL_PKGRELAY_H

// Harness for the liveness targets of 1-parent-1-child package relay (p2p_pkgrelay_receive.cpp and
// p2p_pkgrelay_send.cpp). They drive a real PeerManager with real P2P messages and real validation.
// Together they check that one honest sender gets a parent and child, or a transaction without
// unconfirmed parents, into its peer's mempool, whatever other peers do.
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

namespace pkgrelay_fuzz {
inline TestChain100Setup* g_setup{nullptr};

/** Coins are P2WSH of {OP_DROP OP_TRUE}, spent with a 64-byte dummy item, so that the witness carries
 * enough weight for stripping it to change the feerate materially, and anyone can spend them. */
inline const CScript WITNESS_SCRIPT_DROP_TRUE{CScript() << OP_DROP << OP_TRUE};
inline const CScript P2WSH_DROP_TRUE{GetScriptForDestination(WitnessV0ScriptHash(WITNESS_SCRIPT_DROP_TRUE))};
inline const std::vector<unsigned char> WITNESS_DUMMY(64, 0);
inline constexpr CAmount COINBASE_VALUE{50 * COIN};
/** Value of a parent's second output, which anyone can spend (as an anchor). */
inline constexpr CAmount ANCHOR_VALUE{1000};

struct Pair {
    CTransactionRef parent;     //!< no unconfirmed parents; output 0 funds the child, output 1 is the anchor
    CTransactionRef child;      //!< spends output 0 of the parent and an output of `funding`
    CTransactionRef fake_child; //!< spends the parent and an unknown outpoint
    CTransactionRef funding;    //!< confirmed transaction funding the child: CONFIRMED_PARENT or a coinbase
    bool parent_pays{false};    //!< whether the parent pays the minimum relay feerate on its own
};
inline std::vector<Pair> PAIRS;
/** Transactions without unconfirmed parents. */
inline std::vector<CTransactionRef> STANDALONE;
/** Confirmed coins of COINBASE_VALUE not spent by any of the above, for adversaries' transactions. */
inline std::vector<COutPoint> SPARE_COINS;
/** Confirmed transaction funding half of the children. */
inline CTransactionRef CONFIRMED_PARENT;

CTransactionRef MakeTx(uint32_t version, const std::vector<COutPoint>& inputs, const std::vector<CAmount>& amounts_out);

/** Fuzz target init: the chain, and the transactions above, checked to be acceptable. */
void Initialize();

CNode* MakePeer(NodeId id, ConnectionType conn_type, NetPermissionFlags permissions);

/** Version handshake with wtxid relay, and package relay if requested, negotiated. */
void Handshake(ConnmanTestMsg& connman, PeerManager& peerman, CNode& peer, bool pkgrelay) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

/** Take everything we sent to this peer, as (message type, payload), and clear the send buffers. */
std::vector<std::pair<std::string, std::vector<unsigned char>>> TakeSentMessages(CNode& node);

template <typename T>
T Parse(const std::vector<unsigned char>& payload)
{
    DataStream stream{payload};
    T ret;
    stream >> ret;
    return ret;
}

/** The transaction stripped of witnesses, inflated, or with a mutated witness: the txid stays. */
CTransactionRef Malleate(FuzzedDataProvider& fdp, const CTransactionRef& tx);

/** A replacement of an adversary's transaction, paying 1000 more. */
CTransactionRef Replacement(const CTransaction& old);

/** A transaction of an adversary's own, added to `own`: spending one of its coins, and optionally an
 * output in `spendable`; or a child of one of its earlier transactions; or a replacement of one
 * (repeated, a chain of replacements). */
CTransactionRef MakeAdversaryTx(FuzzedDataProvider& fdp, const std::vector<std::pair<COutPoint, CAmount>>& spendable, std::vector<CTransactionRef>& own);

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
} // namespace pkgrelay_fuzz

#endif // BITCOIN_TEST_FUZZ_UTIL_PKGRELAY_H
