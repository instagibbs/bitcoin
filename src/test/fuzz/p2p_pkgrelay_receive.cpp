// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// pkgrelay_receive_liveness: one honest peer gets its transactions into our mempool whatever other
// peers do.
//
// The honest peer relays packages and holds independent items, each acceptable to our mempool:
// parent and child pairs (the parent has no unconfirmed parents; either may or may not pay for
// itself) and transactions without unconfirmed parents. It announces them as the protocol
// prescribes and answers every request, possibly only after up to three adversary moves, so that
// our mempool can change in between. The child of a parent that pays for itself may be replaced on
// its side; it then answers for the pair with pkgnotfound and announces the parent on its own,
// which becomes the item. Likewise with the child once a block confirms the parent.
//
// Adversaries may announce, request and deliver the honest transactions and packages as is,
// stripped of witnesses, malleated, reversed or mixed; deliver fake children of the parents and
// witnessless copies of the children's confirmed funding; fill the orphanage; send notfound and
// pkgnotfound; stall; disconnect and reconnect; and spend what the honest transactions spend and
// the parents' outputs (replacement cycling is out of scope). Transactions may leave our mempool,
// except accepted honest ones, and blocks may confirm any (see ConfirmInBlock).
//
// Property: every item ends up in our mempool or confirmed, by txid, within a bounded time if the
// honest peer is outbound, unless a transaction conflicting with it did.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util/pkgrelay.h>

using namespace pkgrelay_fuzz;

FUZZ_TARGET(pkgrelay_receive_liveness, .init = Initialize)
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
    // The honest sender answers a getpkg as its mempool is when the request arrives.
    auto answer_getpkg = [&](const std::vector<PkgInv>& requests) {
        std::vector<PkgInv> not_found;
        std::vector<CInv> fallback;
        for (const auto& pkg : requests) {
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
    };
    auto answer_getdata = [&](const std::vector<CInv>& requests) {
        std::vector<CInv> not_found;
        for (const auto& inv : requests) {
            if (!inv.IsGenTxMsg()) continue;
            if (const auto tx{honest_tx(inv.hash)}) {
                net.Receive(*honest, NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx)));
            } else {
                not_found.push_back(inv);
            }
        }
        if (!not_found.empty()) net.Receive(*honest, NetMsg::Make(NetMsgType::NOTFOUND, not_found));
    };
    // Requests that reach the honest sender only after some of the adversaries' moves (during the
    // adversarial prefix only), with the number of moves they have waited.
    bool defer_requests{true};
    std::vector<std::pair<std::vector<PkgInv>, int>> deferred_getpkg;
    std::vector<std::pair<std::vector<CInv>, int>> deferred_getdata;
    auto answer_deferred = [&](auto& deferred, auto answer) {
        std::erase_if(deferred, [&](auto& entry) {
            if (defer_requests && ++entry.second < 3 && fdp.ConsumeBool()) return false;
            answer(entry.first);
            return true;
        });
    };
    auto process = [&]() EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        answer_deferred(deferred_getpkg, answer_getpkg);
        answer_deferred(deferred_getdata, answer_getdata);
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
                        auto requests{Parse<std::vector<CInv>>(payload)};
                        if (defer_requests && fdp.ConsumeBool()) {
                            deferred_getdata.emplace_back(std::move(requests), 0);
                        } else {
                            answer_getdata(requests);
                            more = true;
                        }
                    } else if (type == NetMsgType::GETPKG) {
                        auto requests{Parse<std::vector<PkgInv>>(payload)};
                        if (defer_requests && fdp.ConsumeBool()) {
                            deferred_getpkg.emplace_back(std::move(requests), 0);
                        } else {
                            answer_getpkg(requests);
                            more = true;
                        }
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
    defer_requests = false;
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
