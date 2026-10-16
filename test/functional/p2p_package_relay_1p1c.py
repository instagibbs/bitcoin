#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test 1-parent-1-child package relay (pkginv, getpkg, pkgtxns, pkgnotfound).

Property: one honest peer gets a parent and child, or a transaction with no unconfirmed parents,
into the node's mempool whatever other peers do, without relying on the orphanage.

Parents pay no fee unless they need to stand alone, so the node accepts them only with their child.
node0 is the recipient and node1 the sender; node2 runs without package relay. They are only
connected for test_end_to_end.
"""

from decimal import Decimal
import random
import time

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.mempool_util import (
    DEFAULT_MIN_RELAY_TX_FEE,
    create_large_orphan,
    tx_in_orphanage,
)
from test_framework.messages import (
    CInv,
    COIN,
    CBlockHeader,
    HeaderAndShortIDs,
    MSG_CMPCT_BLOCK,
    MAX_BIP125_RBF_SEQUENCE,
    MSG_WTX,
    PKGRELAY_1P1C_FEATURE,
    PkgInv,
    msg_cmpctblock,
    msg_feefilter,
    msg_getpkg,
    msg_headers,
    msg_inv,
    msg_pkginv,
    msg_pkgnotfound,
    msg_pkgtxns,
    msg_sendcmpct,
    msg_tx,
    tx_from_hex,
)
from test_framework.p2p import (
    GETDATA_TX_INTERVAL,
    NONPREF_PEER_TX_DELAY,
    OVERLOADED_PEER_TX_DELAY,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.wallet import MiniWallet

# Delay large enough for any inventory trickle to fire under mocktime.
TRICKLE_BUMP = 60
MAX_PKGINV_SZ = 1000
MAX_GETPKG_SZ = 100
MAX_PEER_TX_ANNOUNCEMENTS = 5000
MAX_PEER_TX_REQUEST_IN_FLIGHT = 100


class PkgPeer(P2PInterface):
    """Records package relay messages and transaction announcements, and never requests anything
    on its own."""
    def __init__(self, pkgrelay=True, wtxidrelay=True):
        super().__init__(wtxidrelay=wtxidrelay, pkgrelay=pkgrelay)
        self.features_received = []
        self.getpkg_received = []
        self.pkginv_received = []
        self.pkgtxns_received = []
        self.pkgnotfound_received = []
        self.inv_received = []
        self.getdata_received = []

    def on_feature(self, message):
        self.features_received.append(message.feature_id)

    def on_getpkg(self, message):
        self.getpkg_received.extend(message.pkgs)

    def on_pkginv(self, message):
        self.pkginv_received.extend(message.pkgs)

    def on_pkgtxns(self, message):
        self.pkgtxns_received.append(PkgInv(message.parent.wtxid_int, message.child.wtxid_int))

    def on_pkgnotfound(self, message):
        self.pkgnotfound_received.extend(message.pkgs)

    def on_inv(self, message):
        self.inv_received.extend(i.hash for i in message.inv)

    def on_getdata(self, message):
        self.getdata_received.extend(i.hash for i in message.inv)

    def got(self, attr, item):
        return item in getattr(self, attr)


def pkg_of(parent, child):
    return PkgInv(parent["tx"].wtxid_int, child["tx"].wtxid_int)


def sync_fully(peer):
    """Return once the node has sent peer everything it sends in reply to peer's messages so far,
    or because of a clock bump before them."""
    # The node can send more after the first pong in the same pass; the second pong follows it.
    peer.sync_with_ping()
    peer.sync_with_ping()


def sat_per_kvb(fee, vsize):
    return int(fee * COIN * 1000 / vsize)


class PackageRelay1p1cTest(BitcoinTestFramework):
    def set_test_params(self):
        # Use the cached chain: its coinbases were connected before the nodes started, so they are not
        # in the recently confirmed filter (see test_per_tx_filters_poisoned).
        self.num_nodes = 4
        # node3 has a small send buffer, so that serving packages exercises its backpressure.
        self.extra_args = [[], [], ["-pkgrelay=0"], ["-maxsendbuffer=50"]]

    def setup_network(self):
        self.setup_nodes()

    def low_fee_parent(self, fee_rate=Decimal(0)):
        """A parent spending a confirmed coin, by default with no fee."""
        self.sequence -= 1
        return self.wallet.create_self_transfer(fee_rate=fee_rate, sequence=self.sequence, confirmed_only=True)

    def child_of(self, parent, extra_utxos=(), fee=10000):
        return self.wallet.create_self_transfer_multi(utxos_to_spend=[parent["new_utxo"], *extra_utxos], fee_per_output=fee)

    def freeze_time(self, node):
        # Never move a node's clock back: its inventory send schedules are relative to it.
        node.setmocktime(max(node.mocktime or 0, int(time.time())))

    def cleanup(self):
        for node in self.nodes:
            node.disconnect_p2ps()

    def relay_pair(self, peer, node, pkg, parent, child, *, delay=NONPREF_PEER_TX_DELAY):
        """Announce the pair from peer, answer the request and check that both are accepted."""
        peer.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(delay)
        peer.wait_until(lambda: peer.got("getpkg_received", pkg))
        peer.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        mempool = node.getrawmempool()
        assert parent["txid"] in mempool
        assert child["txid"] in mempool

    def test_negotiation(self):
        self.log.info("Package relay is offered to transaction relay peers, and used only with wtxidrelay")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)

        legacy = node.add_p2p_connection(PkgPeer(pkgrelay=False))
        assert_equal(legacy.features_received, [PKGRELAY_1P1C_FEATURE])
        no_wtxid = node.add_p2p_connection(PkgPeer(wtxidrelay=False))
        block_relay = node.add_outbound_p2p_connection(PkgPeer(), p2p_idx=0, connection_type="block-relay-only")
        assert_equal(block_relay.features_received, [])
        for peer in [no_wtxid, block_relay]:
            peer.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        for peer in [no_wtxid, block_relay]:
            sync_fully(peer)
            assert_equal(peer.getpkg_received, [])

        self.log.info("A package from a block-relay-only peer disconnects it")
        block_relay.send_without_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        block_relay.wait_for_disconnect()
        assert child["txid"] not in node.getrawmempool()
        self.cleanup()

        self.log.info("A node with -pkgrelay=0 neither offers nor uses package relay")
        node = self.nodes[2]
        self.freeze_time(node)
        peer = node.add_p2p_connection(PkgPeer())
        assert_equal(peer.features_received, [])
        peer.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(peer)
        assert_equal(peer.getpkg_received, [])
        self.cleanup()

    def test_oversized_messages(self):
        self.log.info("A pkginv with more than MAX_PKGINV_SZ entries, or a getpkg with more than MAX_GETPKG_SZ, disconnects the peer")
        node = self.nodes[0]
        pkgs = [PkgInv(i, i + 1) for i in range(1, MAX_PKGINV_SZ + 2)]
        for msg in [msg_pkginv(pkgs), msg_getpkg(pkgs[:MAX_GETPKG_SZ + 1])]:
            peer = node.add_p2p_connection(PkgPeer())
            peer.send_without_ping(msg)
            peer.wait_for_disconnect()
        self.cleanup()

    def test_basic(self):
        self.log.info("A parent without fee and its child are relayed together, without the orphanage")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)

        legacy = node.add_p2p_connection(PkgPeer(pkgrelay=False))
        peer = node.add_p2p_connection(PkgPeer())

        self.log.info("A peer that did not negotiate package relay is ignored")
        legacy.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(legacy)
        assert not legacy.got("getpkg_received", pkg)

        self.relay_pair(peer, node, pkg, parent, child)
        assert not tx_in_orphanage(node, child["tx"])

        self.log.info("Also a TRUC parent without fee")
        parent = self.wallet.create_self_transfer(fee_rate=0, version=3, confirmed_only=True)
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"], version=3)
        self.relay_pair(peer, node, pkg_of(parent, child), parent, child)
        assert_equal(peer.getdata_received, [])
        self.cleanup()

    def test_parent_in_mempool(self):
        self.log.info("Both transactions are requested when only the child is missing")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.wallet.send_self_transfer(from_node=node, fee_rate=Decimal("0.0005"), confirmed_only=True)
        child = self.child_of(parent)
        peer = node.add_p2p_connection(PkgPeer())
        self.relay_pair(peer, node, pkg_of(parent, child), parent, child)
        self.cleanup()

    def test_outbound_preferred(self):
        self.log.info("An outbound announcer is requested at once, ahead of an earlier inbound one")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)

        inbound = node.add_p2p_connection(PkgPeer())
        inbound.send_and_ping(msg_pkginv([pkg]))
        outbound = node.add_outbound_p2p_connection(PkgPeer(), p2p_idx=1)
        outbound.send_and_ping(msg_pkginv([pkg]))
        outbound.wait_until(lambda: outbound.got("getpkg_received", pkg))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(inbound)
        assert not inbound.got("getpkg_received", pkg)
        outbound.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        assert child["txid"] in node.getrawmempool()
        self.cleanup()

    def test_orphanage_flooded(self):
        self.log.info("The pair gets through while other peers flood the orphanage")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)

        for _ in range(3):
            attacker = node.add_p2p_connection(P2PInterface())
            for _ in range(10):
                attacker.send_without_ping(msg_tx(create_large_orphan()))
            attacker.sync_with_ping()
        assert_greater_than(len(node.getorphantxs()), 0)

        peer = node.add_p2p_connection(PkgPeer())
        self.relay_pair(peer, node, pkg_of(parent, child), parent, child)
        assert not tx_in_orphanage(node, child["tx"])
        self.cleanup()

    def test_stalling_announcer(self):
        self.log.info("An announcer that never answers delays the honest announcer by one request interval")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)

        attacker = node.add_p2p_connection(PkgPeer())
        honest = node.add_p2p_connection(PkgPeer())
        attacker.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        attacker.wait_until(lambda: attacker.got("getpkg_received", pkg))

        honest.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(honest)
        assert not honest.got("getpkg_received", pkg)

        self.log.info("A response that is not the requested package does not complete the request")
        attacker.send_and_ping(msg_pkgtxns(child["tx"], parent["tx"]))
        assert child["txid"] not in node.getrawmempool()
        sync_fully(honest)
        assert not honest.got("getpkg_received", pkg)

        node.bumpmocktime(GETDATA_TX_INTERVAL)
        honest.wait_until(lambda: honest.got("getpkg_received", pkg))
        honest.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        assert child["txid"] in node.getrawmempool()
        self.cleanup()

    def test_notfound(self):
        self.log.info("pkgnotfound moves the request on to the next announcer at once")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)

        attacker = node.add_p2p_connection(PkgPeer())
        honest = node.add_p2p_connection(PkgPeer())
        attacker.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        attacker.wait_until(lambda: attacker.got("getpkg_received", pkg))
        honest.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)

        attacker.send_and_ping(msg_pkgnotfound([pkg]))
        honest.wait_until(lambda: honest.got("getpkg_received", pkg))
        honest.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        assert child["txid"] in node.getrawmempool()

        self.log.info("So does the announcer disconnecting")
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        attacker = node.add_p2p_connection(PkgPeer())
        attacker.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        attacker.wait_until(lambda: attacker.got("getpkg_received", pkg))
        honest.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        attacker.peer_disconnect()
        attacker.wait_for_disconnect()
        honest.wait_until(lambda: honest.got("getpkg_received", pkg))
        honest.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        assert child["txid"] in node.getrawmempool()
        self.cleanup()

    def test_bad_packages(self):
        self.log.info("A package with a malleated parent does not keep out the package with the real one")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        malleated = tx_from_hex(parent["hex"])
        malleated.wit.vtxinwit[0].scriptWitness.stack.insert(0, b"\x01")
        assert_equal(malleated.txid_hex, parent["txid"])
        bad = PkgInv(malleated.wtxid_int, child["tx"].wtxid_int)

        attacker = node.add_p2p_connection(PkgPeer())
        attacker.send_and_ping(msg_pkginv([bad]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        attacker.wait_until(lambda: attacker.got("getpkg_received", bad))
        attacker.send_and_ping(msg_pkgtxns(malleated, child["tx"]))
        assert child["txid"] not in node.getrawmempool()

        # Only the package id is remembered as rejected, not the child.
        legacy = node.add_p2p_connection(PkgPeer(pkgrelay=False))
        legacy.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child["tx"].wtxid_int)]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        legacy.wait_until(lambda: legacy.got("getdata_received", child["tx"].wtxid_int))

        peer = node.add_p2p_connection(PkgPeer())
        self.relay_pair(peer, node, pkg_of(parent, child), parent, child)

        self.log.info("A package whose child does not spend its parent is not accepted, even in part")
        first = self.wallet.create_self_transfer(fee_rate=Decimal("0.0005"), confirmed_only=True)
        second = self.wallet.create_self_transfer(fee_rate=Decimal("0.0005"), confirmed_only=True)
        unrelated = pkg_of(first, second)
        peer.send_and_ping(msg_pkginv([unrelated]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_until(lambda: peer.got("getpkg_received", unrelated))
        peer.send_and_ping(msg_pkgtxns(first["tx"], second["tx"]))
        mempool = node.getrawmempool()
        assert first["txid"] not in mempool
        assert second["txid"] not in mempool
        self.cleanup()

    def test_child_rejected(self):
        self.log.info("A parent that pays for itself is accepted from a package whose child is rejected")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0.0005"), confirmed_only=True)
        coin = self.wallet.get_utxo(confirmed_only=True)
        child = self.child_of(parent, extra_utxos=[coin])
        pkg = pkg_of(parent, child)
        # A conflict the child does not pay enough to replace.
        node.sendrawtransaction(self.wallet.create_self_transfer(utxo_to_spend=coin, fee=Decimal("0.001"))["hex"])

        peer = node.add_p2p_connection(PkgPeer())
        peer.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_until(lambda: peer.got("getpkg_received", pkg))
        peer.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        mempool = node.getrawmempool()
        assert parent["txid"] in mempool
        assert child["txid"] not in mempool

        self.log.info("The package is not requested again")
        other = node.add_p2p_connection(PkgPeer())
        other.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(other)
        assert not other.got("getpkg_received", pkg)
        self.cleanup()

    def test_per_tx_filters_poisoned(self):
        self.log.info("Poisoning the per-transaction reject filters does not block the pair")
        node = self.nodes[0]
        self.freeze_time(node)

        # A coinbase from the cached chain funds the child. Its copy without the witness reserved
        # value has the coinbase's txid as wtxid, and is rejected as a loose coinbase, which adds
        # that txid to the reject filter. A child arriving as an orphan is then dropped as having a
        # rejected parent, and its wtxid is rejected too.
        cb_utxo = next(u for u in self.wallet.get_utxos(mark_as_spent=False) if u["coinbase"])
        self.wallet.get_utxo(txid=cb_utxo["txid"], vout=cb_utxo["vout"])
        coinbase = tx_from_hex(node.getrawtransaction(cb_utxo["txid"], False, node.getblockhash(cb_utxo["height"])))
        assert coinbase.wtxid_hex != coinbase.txid_hex
        coinbase.wit.vtxinwit = []

        parent = self.low_fee_parent()
        child = self.child_of(parent, extra_utxos=[cb_utxo])

        attacker = node.add_p2p_connection(P2PInterface())
        attacker.send_and_ping(msg_tx(coinbase))
        attacker.send_and_ping(msg_tx(child["tx"]))
        assert not tx_in_orphanage(node, child["tx"])

        legacy = node.add_p2p_connection(PkgPeer(pkgrelay=False))
        legacy.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child["tx"].wtxid_int)]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(legacy)
        assert_equal(legacy.getdata_received, [])

        peer = node.add_p2p_connection(PkgPeer())
        self.relay_pair(peer, node, pkg_of(parent, child), parent, child)
        self.cleanup()

    def test_announcement_limits(self):
        self.log.info("A peer with MAX_PEER_TX_REQUEST_IN_FLIGHT packages requested has new requests delayed")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        junk = [PkgInv(random.getrandbits(256), random.getrandbits(256)) for _ in range(MAX_PEER_TX_REQUEST_IN_FLIGHT + MAX_PEER_TX_ANNOUNCEMENTS)]

        busy = node.add_p2p_connection(PkgPeer())
        busy.send_and_ping(msg_pkginv(junk[:MAX_PEER_TX_REQUEST_IN_FLIGHT]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        busy.wait_until(lambda: len(busy.getpkg_received) == MAX_PEER_TX_REQUEST_IN_FLIGHT)
        busy.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(busy)
        assert not busy.got("getpkg_received", pkg)
        node.bumpmocktime(OVERLOADED_PEER_TX_DELAY)
        busy.wait_until(lambda: busy.got("getpkg_received", pkg))

        self.log.info("A peer with MAX_PEER_TX_ANNOUNCEMENTS packages announced has more ignored, unlike other peers")
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        flooder = node.add_p2p_connection(PkgPeer())
        flood = junk[MAX_PEER_TX_REQUEST_IN_FLIGHT:]
        for i in range(0, len(flood), MAX_PKGINV_SZ):
            flooder.send_without_ping(msg_pkginv(flood[i:i + MAX_PKGINV_SZ]))
        flooder.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        flooder.wait_until(lambda: len(flooder.getpkg_received) == MAX_PEER_TX_ANNOUNCEMENTS)
        sync_fully(flooder)
        assert not flooder.got("getpkg_received", pkg)
        assert_equal(flooder.message_count["getpkg"], MAX_PEER_TX_ANNOUNCEMENTS // MAX_GETPKG_SZ)
        honest = node.add_p2p_connection(PkgPeer())
        self.relay_pair(honest, node, pkg, parent, child)
        self.cleanup()

    def test_package_rbf(self):
        self.log.info("A package replaces a conflicting package that pays less")
        node = self.nodes[0]
        self.freeze_time(node)
        coin = self.wallet.get_utxo(confirmed_only=True)

        def pair(fee):
            self.sequence -= 1
            parent = self.wallet.create_self_transfer(utxo_to_spend=coin, fee_rate=0, sequence=self.sequence)
            return parent, self.child_of(parent, fee=fee)
        low, high, middle = pair(10000), pair(30000), pair(20000)
        peer = node.add_p2p_connection(PkgPeer())
        self.relay_pair(peer, node, pkg_of(*low), *low)
        self.relay_pair(peer, node, pkg_of(*high), *high)
        mempool = node.getrawmempool()
        assert low[0]["txid"] not in mempool
        assert low[1]["txid"] not in mempool

        self.log.info("But not one that pays more")
        peer.send_and_ping(msg_pkginv([pkg_of(*middle)]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_until(lambda: peer.got("getpkg_received", pkg_of(*middle)))
        peer.send_and_ping(msg_pkgtxns(middle[0]["tx"], middle[1]["tx"]))
        mempool = node.getrawmempool()
        assert middle[1]["txid"] not in mempool
        assert high[1]["txid"] in mempool
        self.cleanup()

    def test_rejected_and_confirmed(self):
        self.log.info("A package whose child was not accepted is not requested again before the next block")
        node = self.nodes[0]
        self.freeze_time(node)
        parent = self.low_fee_parent()
        poor_child = self.child_of(parent, fee=0)
        rejected = pkg_of(parent, poor_child)
        first = node.add_p2p_connection(PkgPeer())
        second = node.add_p2p_connection(PkgPeer())
        first.send_and_ping(msg_pkginv([rejected]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        first.wait_until(lambda: first.got("getpkg_received", rejected))
        first.send_and_ping(msg_pkgtxns(parent["tx"], poor_child["tx"]))
        assert parent["txid"] not in node.getrawmempool()
        second.send_and_ping(msg_pkginv([rejected]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(second)
        assert not second.got("getpkg_received", rejected)

        self.log.info("Nor is a package whose child is in the mempool, or was confirmed")
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        self.relay_pair(first, node, pkg, parent, child)
        second.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        sync_fully(second)
        assert not second.got("getpkg_received", pkg)

        self.generateblock(node, output="raw(51)", transactions=[parent["hex"], child["hex"]], sync_fun=self.no_op)
        second.send_and_ping(msg_pkginv([pkg, rejected]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        second.wait_until(lambda: second.got("getpkg_received", rejected))
        assert not second.got("getpkg_received", pkg)
        self.cleanup()

    def test_end_to_end(self):
        self.log.info("A node relays a pair to a peer whose mempool would reject the parent alone")
        node0, node1, node2 = self.nodes[:3]
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        for node in self.nodes:
            self.freeze_time(node)
        observer = node0.add_p2p_connection(PkgPeer())
        self.connect_nodes(1, 0)
        self.connect_nodes(0, 2)
        self.sync_blocks(self.nodes[:3])
        node1.submitpackage([parent["hex"], child["hex"]])

        def arrived():
            for node in self.nodes:
                node.bumpmocktime(1)
            return child["txid"] in node2.getrawmempool()
        self.wait_until(arrived)
        assert parent["txid"] in node0.getrawmempool()
        assert not tx_in_orphanage(node0, child["tx"])
        from_node1 = next(p for p in node0.getpeerinfo() if p["inbound"] and "Satoshi" in p["subver"])
        assert_greater_than(from_node1["bytesrecv_per_msg"].get("pkgtxns", 0), 0)

        self.log.info("It relays the pair on as a pair to package relay peers, and one by one to others")

        def announced():
            node0.bumpmocktime(1)
            return observer.got("pkginv_received", pkg)
        self.wait_until(announced)
        assert parent["txid"] in node2.getrawmempool()
        received = node2.getpeerinfo()[0]["bytesrecv_per_msg"]
        assert "pkginv" not in received
        assert "pkgtxns" not in received
        self.disconnect_nodes(1, 0)
        self.disconnect_nodes(0, 2)
        self.cleanup()

    def announce_from_node1(self, package, *, alone=(), feefilter=0):
        """Submit package and then each of alone to node1 with its inventory trickle held back, then
        let it announce them."""
        node = self.nodes[1]
        self.freeze_time(node)
        peer = node.add_p2p_connection(PkgPeer())
        legacy = node.add_p2p_connection(PkgPeer(pkgrelay=False))
        if feefilter:
            peer.send_and_ping(msg_feefilter(feefilter))
        node.bumpmocktime(TRICKLE_BUMP)
        peer.sync_with_ping()
        legacy.sync_with_ping()
        if package:
            node.submitpackage([tx["hex"] for tx in package])
        for tx in alone:
            node.sendrawtransaction(tx["hex"])
        node.bumpmocktime(TRICKLE_BUMP)
        return peer, legacy

    def test_sender_pairs(self):
        self.log.info("A sender announces a parent and child as a pair instead of one by one")
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        peer, legacy = self.announce_from_node1([parent, child])

        peer.wait_until(lambda: peer.got("pkginv_received", pkg))
        legacy.wait_until(lambda: legacy.got("inv_received", child["tx"].wtxid_int))
        assert legacy.got("inv_received", parent["tx"].wtxid_int)
        sync_fully(peer)
        assert_equal(peer.inv_received, [])

        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgtxns_received", pkg)

        self.log.info("A child that pays for itself is paired with its parent too")
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0.0005"), confirmed_only=True)
        child = self.child_of(parent, fee=1000)
        assert_greater_than(parent["fee"] / parent["tx"].get_vsize(), child["fee"] / child["tx"].get_vsize())
        pkg = pkg_of(parent, child)
        peer, _ = self.announce_from_node1([parent, child])
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))
        sync_fully(peer)
        assert_equal(peer.inv_received, [])
        self.cleanup()

    def test_sender_not_paired(self):
        self.log.info("Other topologies are announced one by one: a child of two parents, a grandchild")
        fee_rate = Decimal("0.0005")
        parents = [self.wallet.create_self_transfer(fee_rate=fee_rate, confirmed_only=True) for _ in range(2)]
        two_parent_child = self.wallet.create_self_transfer_multi(utxos_to_spend=[p["new_utxo"] for p in parents])
        parent = self.wallet.create_self_transfer(fee_rate=fee_rate, confirmed_only=True)
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"], fee_rate=fee_rate)
        grandchild = self.wallet.create_self_transfer(utxo_to_spend=child["new_utxo"], fee_rate=fee_rate)
        alone = [*parents, two_parent_child, grandchild]
        peer, _ = self.announce_from_node1([], alone=[*parents, two_parent_child, parent, child, grandchild])

        peer.wait_until(lambda: peer.got("pkginv_received", pkg_of(parent, child)))
        peer.wait_until(lambda: all(peer.got("inv_received", tx["tx"].wtxid_int) for tx in alone))
        sync_fully(peer)
        assert_equal(len(peer.pkginv_received), 1)
        assert_equal(sorted(peer.inv_received), sorted(tx["tx"].wtxid_int for tx in alone))
        self.cleanup()

    def test_sender_feefilter(self):
        self.log.info("A pair is announced to a peer whose feefilter its chunk pays")

        def pair():
            parent = self.low_fee_parent()
            child = self.child_of(parent)
            chunk_rate = sat_per_kvb(child["fee"], parent["tx"].get_vsize() + child["tx"].get_vsize())
            child_rate = sat_per_kvb(child["fee"], child["tx"].get_vsize())
            # Something the peer is announced at the same trickle in any case.
            marker = self.wallet.create_self_transfer(fee_rate=Decimal("0.01"), confirmed_only=True)
            return parent, child, chunk_rate, child_rate, marker

        parent, child, chunk_rate, _, marker = pair()
        peer, _ = self.announce_from_node1([parent, child], alone=[marker], feefilter=chunk_rate // 2)
        peer.wait_until(lambda: peer.got("pkginv_received", pkg_of(parent, child)))
        peer.wait_until(lambda: peer.got("inv_received", marker["tx"].wtxid_int))
        sync_fully(peer)
        assert_equal(peer.inv_received, [marker["tx"].wtxid_int])

        self.log.info("If only the child pays it, the child is announced alone")
        parent, child, chunk_rate, child_rate, marker = pair()
        peer, _ = self.announce_from_node1([parent, child], alone=[marker], feefilter=(chunk_rate + child_rate) // 2)
        peer.wait_until(lambda: peer.got("inv_received", marker["tx"].wtxid_int))
        sync_fully(peer)
        assert_equal(sorted(peer.inv_received), sorted([marker["tx"].wtxid_int, child["tx"].wtxid_int]))
        assert_equal(peer.pkginv_received, [])

        self.log.info("If neither does, neither is announced")
        parent, child, _, child_rate, marker = pair()
        peer, _ = self.announce_from_node1([parent, child], alone=[marker], feefilter=child_rate * 2)
        peer.wait_until(lambda: peer.got("inv_received", marker["tx"].wtxid_int))
        sync_fully(peer)
        assert_equal(peer.inv_received, [marker["tx"].wtxid_int])
        assert_equal(peer.pkginv_received, [])
        self.cleanup()

    def test_sender_serving(self):
        self.log.info("Serving a package marks its transactions as broadcast")
        node = self.nodes[1]
        parent = self.low_fee_parent(fee_rate=Decimal(DEFAULT_MIN_RELAY_TX_FEE) / COIN)
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        peer, legacy = self.announce_from_node1([], alone=[parent, child])
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))
        assert all(node.getmempoolentry(tx["txid"])["unbroadcast"] for tx in [parent, child])
        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgtxns_received", pkg)
        assert not any(node.getmempoolentry(tx["txid"])["unbroadcast"] for tx in [parent, child])

        self.log.info("A package that was not announced to the peer is neither served nor announced in parts")
        stranger = node.add_p2p_connection(PkgPeer())
        stranger.send_and_ping(msg_getpkg([pkg]))
        assert stranger.got("pkgnotfound_received", pkg)
        assert_equal(stranger.pkgtxns_received, [])
        marker = self.wallet.create_self_transfer(fee_rate=Decimal("0.01"), confirmed_only=True)
        node.sendrawtransaction(marker["hex"])
        node.bumpmocktime(TRICKLE_BUMP)
        stranger.wait_until(lambda: stranger.got("inv_received", marker["tx"].wtxid_int))
        sync_fully(stranger)
        assert_equal(stranger.inv_received, [marker["tx"].wtxid_int])
        assert_equal(stranger.pkginv_received, [])

        self.log.info("A peer that did not negotiate package relay gets no reply to getpkg")
        legacy.send_without_ping(msg_getpkg([pkg]))
        sync_fully(legacy)
        assert_equal(legacy.pkgtxns_received, [])
        assert_equal(legacy.pkgnotfound_received, [])
        self.cleanup()

    def test_sender_fallback_parent(self):
        self.log.info("If the child is replaced before the request, the sender announces the parent alone")
        node = self.nodes[1]
        # The parent has to stay in the sender's mempool without its child.
        parent = self.low_fee_parent(fee_rate=Decimal(DEFAULT_MIN_RELAY_TX_FEE) / COIN)
        other_utxo = self.wallet.get_utxo(confirmed_only=True)
        child = self.child_of(parent, extra_utxos=[other_utxo])
        pkg = pkg_of(parent, child)
        peer, _ = self.announce_from_node1([parent, child])
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))

        replacement = self.wallet.create_self_transfer(utxo_to_spend=other_utxo, fee=Decimal("0.001"))
        node.sendrawtransaction(replacement["hex"])
        assert child["txid"] not in node.getrawmempool()

        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgnotfound_received", pkg)
        node.bumpmocktime(TRICKLE_BUMP)
        peer.wait_until(lambda: peer.got("inv_received", parent["tx"].wtxid_int))
        self.cleanup()

        self.log.info("Also if another child of the parent replaced the child, with which it is paired again")
        parent = self.low_fee_parent(fee_rate=Decimal(DEFAULT_MIN_RELAY_TX_FEE) / COIN)
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        peer, _ = self.announce_from_node1([parent, child])
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))

        replacement = self.child_of(parent, fee=30000)
        node.sendrawtransaction(replacement["hex"])
        assert child["txid"] not in node.getrawmempool()

        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgnotfound_received", pkg)
        node.bumpmocktime(TRICKLE_BUMP)
        peer.wait_until(lambda: peer.got("pkginv_received", pkg_of(parent, replacement)))
        peer.wait_until(lambda: peer.got("inv_received", parent["tx"].wtxid_int))
        self.cleanup()

        self.log.info("The parent is left out if it does not pay the peer's feefilter")
        parent = self.low_fee_parent(fee_rate=Decimal(DEFAULT_MIN_RELAY_TX_FEE) / COIN)
        other_utxo = self.wallet.get_utxo(confirmed_only=True)
        child = self.child_of(parent, extra_utxos=[other_utxo])
        pkg = pkg_of(parent, child)
        peer, _ = self.announce_from_node1([parent, child], feefilter=10 * DEFAULT_MIN_RELAY_TX_FEE)
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))

        replacement = self.wallet.create_self_transfer(utxo_to_spend=other_utxo, fee=Decimal("0.001"))
        node.sendrawtransaction(replacement["hex"])
        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgnotfound_received", pkg)
        node.bumpmocktime(TRICKLE_BUMP)
        peer.wait_until(lambda: peer.got("inv_received", replacement["tx"].wtxid_int))
        sync_fully(peer)
        assert not peer.got("inv_received", parent["tx"].wtxid_int)
        self.cleanup()

    def test_sender_fallback_child(self):
        self.log.info("If a block confirms the parent alone, the sender announces the child alone")
        node = self.nodes[1]
        parent = self.low_fee_parent()
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        peer, _ = self.announce_from_node1([parent, child])
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))

        self.generateblock(node, output="raw(51)", transactions=[parent["hex"]], sync_fun=self.no_op)
        # Push the parent out of the most recent block, from which it could still be served.
        self.generateblock(node, output="raw(51)", transactions=[], sync_fun=self.no_op)
        assert child["txid"] in node.getrawmempool()

        peer.send_and_ping(msg_getpkg([pkg]))
        assert peer.got("pkgnotfound_received", pkg)
        node.bumpmocktime(TRICKLE_BUMP)
        peer.wait_until(lambda: peer.got("inv_received", child["tx"].wtxid_int))
        self.cleanup()

    def test_sender_serving_backpressure(self):
        self.log.info("Packages are served as the send buffer drains, before any later message is processed")
        node = self.nodes[3]
        self.freeze_time(node)
        # Each pkgtxns is larger than node3's send buffer.
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0.0001"), target_vsize=60_000, confirmed_only=True)
        child = self.child_of(parent)
        pkg = pkg_of(parent, child)
        peer = node.add_p2p_connection(PkgPeer())
        for tx in [parent, child]:
            node.sendrawtransaction(tx["hex"])
        node.bumpmocktime(TRICKLE_BUMP)
        peer.wait_until(lambda: peer.got("pkginv_received", pkg))
        peer.send_without_ping(msg_getpkg([pkg] * MAX_GETPKG_SZ))
        # The ping is processed only once every queued request has been served.
        peer.sync_with_ping()
        assert_equal(peer.pkgtxns_received, [pkg] * MAX_GETPKG_SZ)
        self.cleanup()

    def test_rejected_package_in_compact_block(self):
        self.log.info("The transactions of a rejected package are kept for compact block reconstruction")
        node = self.nodes[0]
        self.freeze_time(node)
        # A recent tip, so that the node reconstructs the compact block rather than leaving it to block download.
        self.generate(node, 1, sync_fun=self.no_op)
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0.0005"), confirmed_only=True)
        coin = self.wallet.get_utxo(confirmed_only=True)
        child = self.child_of(parent, extra_utxos=[coin])
        pkg = pkg_of(parent, child)
        # A conflict the child does not pay enough to replace.
        node.sendrawtransaction(self.wallet.create_self_transfer(utxo_to_spend=coin, fee=Decimal("0.001"))["hex"])
        peer = node.add_p2p_connection(PkgPeer())
        peer.send_and_ping(msg_pkginv([pkg]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer.wait_until(lambda: peer.got("getpkg_received", pkg))
        peer.send_and_ping(msg_pkgtxns(parent["tx"], child["tx"]))
        assert parent["txid"] in node.getrawmempool()
        assert child["txid"] not in node.getrawmempool()

        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1),
                             ntime=node.getblockheader(tip)["time"] + 1, txlist=[parent["tx"], child["tx"]])
        add_witness_commitment(block)
        block.solve()
        cmpct = HeaderAndShortIDs()
        cmpct.initialize_from_block(block, use_witness=True)
        # Announce the block, so that the node asks for it as a compact block.
        peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer.send_and_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_until(lambda: "getdata" in peer.last_message and
                        [(i.type, i.hash) for i in peer.last_message["getdata"].inv] == [(MSG_CMPCT_BLOCK, block.hash_int)])
        peer.send_and_ping(msg_cmpctblock(cmpct.to_p2p()))
        assert_equal(node.getbestblockhash(), block.hash_hex)
        assert_equal(peer.message_count["getblocktxn"], 0)
        self.cleanup()

    def run_test(self):
        self.sequence = MAX_BIP125_RBF_SEQUENCE
        self.wallet = MiniWallet(self.nodes[0])
        # The cached chain leaves the wallet too few mature coins, so split one.
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        split = self.wallet.create_self_transfer_multi(num_outputs=50)
        self.generateblock(self.nodes[0], output="raw(51)", transactions=[split["hex"]])
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(0, 3)
        self.wallet.rescan_utxos()

        self.test_negotiation()
        self.test_oversized_messages()
        self.test_basic()
        self.test_parent_in_mempool()
        self.test_outbound_preferred()
        self.test_orphanage_flooded()
        self.test_stalling_announcer()
        self.test_notfound()
        self.test_bad_packages()
        self.test_child_rejected()
        self.test_per_tx_filters_poisoned()
        self.test_announcement_limits()
        self.test_package_rbf()
        # Mines on node0, which test_end_to_end then syncs to the other nodes.
        self.test_rejected_and_confirmed()
        self.test_end_to_end()
        self.test_sender_pairs()
        self.test_sender_not_paired()
        self.test_sender_feefilter()
        self.test_sender_serving()
        self.test_sender_fallback_parent()
        self.test_sender_serving_backpressure()
        # Mines on node1 only.
        self.test_sender_fallback_child()
        # Mines on node0 only, so it runs last.
        self.test_rejected_package_in_compact_block()


if __name__ == '__main__':
    PackageRelay1p1cTest(__file__).main()
