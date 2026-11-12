// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// pkgrelay_send_liveness: as the sender, every transaction that stays in our mempool reaches one
// package relay peer, on its own or in a package, unless it entered our mempool more than once (no
// transaction is announced to a peer twice).
//
// The peer requests everything we announce (only the child of a package whose parent it has). The
// property is checked once the adversaries stop, and while they keep acting: then within a few
// rounds of messages, for a peer with the NoBan permission (no randomized inventory delay).
// Adversaries may submit the honest pairs and transactions (as our wallet would) and their own
// transactions: children of the honest parents through an output anyone can spend, conflicting
// children, grandchildren, and chains of replacements of these. They may also request from us.
// Transactions may leave our mempool, and blocks may confirm any (see ConfirmInBlock).

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util/pkgrelay.h>

using namespace pkgrelay_fuzz;

FUZZ_TARGET(pkgrelay_send_liveness, .init = Initialize)
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
                        // As a node would, it requests only the child of a package whose parent it has.
                        std::vector<PkgInv> pkgs;
                        std::vector<CInv> children;
                        for (const auto& pkg : Parse<std::vector<PkgInv>>(payload)) {
                            if (received.contains(pkg.parent)) {
                                children.emplace_back(MSG_WTX, pkg.child.ToUint256());
                            } else {
                                pkgs.push_back(pkg);
                            }
                        }
                        if (!pkgs.empty()) request(NetMsg::Make(NetMsgType::GETPKG, pkgs));
                        if (!children.empty()) request(NetMsg::Make(NetMsgType::GETDATA, children));
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
