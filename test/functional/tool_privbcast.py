#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-privbcast, the bounded private transaction broadcast tool.

The tool reaches the network only through a Tor SOCKS5 listener. Here that listener is the
test framework's SOCKS5 server: RESOLVE queries for the test seed names are answered from a
fixed script, and CONNECT requests are redirected to Python P2P listeners with chosen
behaviours, or to a bitcoind. Every wire-visible parameter is a constant in the tool;
regtest-only flags supply the seeds, the bundled onions and a time divisor.
"""
import base64
import hashlib
import json
from decimal import Decimal
import os
import platform
import signal
import subprocess
import threading
import time

from test_framework.crypto.ellswift import xswiftec
from test_framework.crypto.secp256k1 import FE
from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_WITNESS_TX,
    MSG_WTX,
    NODE_WITNESS,
    msg_getdata,
    msg_inv,
    msg_notfound,
    msg_ping,
    msg_pong,
    msg_sendtxrcncl,
    msg_tx,
    msg_wtxidrelay,
    tx_from_hex,
)
from test_framework.netutil import format_addr_port
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
    start_p2p_listener,
)
from test_framework.socks5 import (
    Command,
    start_socks5_server,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    p2p_port,
)
from test_framework.v2_p2p import EncryptedP2PState
from test_framework.wallet import MiniWallet

# Timing in this file is real. The tool is a separate process, and nothing outside it can move its
# clock, so the regtest -timedivisor scales every plan duration instead and the margins below are
# sized for the slowest CI host, not for precision: this file checks the process end to end. The
# node's jobs run on setmocktime in p2p_private_broadcast.py.

# The Parameters of doc/design/private-broadcast-tool.md. The tool has no knobs, so the checks below
# hardcode what they test against.
TIME_DIVISOR = 10  # scaled budgets (4.5 s handshake, 7.5 s request window, 1 s PONG) comfortably cover a real bitcoind recipient
PRIVATE_VERSION = 70017
PRIVATE_USER_AGENT = "/pynode:0.0.1/"
REGTEST_PORT = 18444
SLOTS = 6
OPPORTUNITIES_PER_SLOT = 4
DISCOVERY_WINDOW_S = 18
START_GRACE_S = 5
HANDSHAKE_TIMEOUT_S = 45
REQUEST_WINDOW_S = 75
PONG_WAIT_S = 10
BACKUP_MIN_S, BACKUP_MAX_S = 50, 60
MID_MIN_S, MID_MAX_S = 35, 180
LATE_MIN_S, LATE_MAX_S = 185, 240
PRIMARY_SEPARATION_S = 5
PARENT_HOLD_S = 30
MAX_RECV_BYTES = 128 * 1024
MAX_STANDARD_TX_WEIGHT = 400_000
MAX_STDIN_BYTES = 8_004_096
# A package recipient asks for the child this long after the INV: past the point where the parent hold
# would still fit before the request window's last PONG_WAIT, and before that point itself.
LATE_CHILD_REQUEST_S = (REQUEST_WINDOW_S - PONG_WAIT_S - PARENT_HOLD_S / 2) / TIME_DIVISOR


def ellswift_x(encoding):
    """The x coordinate a BIP324 public key encoding stands for: every encoding of one key gives the same."""
    return xswiftec(FE(int.from_bytes(encoding[:32], "big")), FE(int.from_bytes(encoding[32:], "big"))).to_bytes()


def make_onion(seed: int) -> str:
    """A syntactically valid v3 onion address derived from a one-byte seed."""
    pubkey = bytes([seed]) * 32
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + checksum + b"\x03").decode().lower() + ".onion"


class Recipient(P2PInterface):
    """An honest recipient: negotiates wtxid relay (BIP339), as P2PInterface does by default,
    requests the announced transaction by wtxid and answers PING."""

    def __init__(self):
        super().__init__()
        self.txs_received = []
        self.getdatas_sent = 0
        self.invs_received = 0
        self.ping_nonces = []
        self.notfound = []

    def request(self, hashes, inv_type=MSG_WTX):
        want = msg_getdata()
        for h in hashes:
            want.inv.append(CInv(inv_type, h))
        self.getdatas_sent += 1
        self.send_without_ping(want)

    def on_inv(self, message):
        self.invs_received += 1
        self.request([i.hash for i in message.inv if i.type == MSG_WTX])

    def on_tx(self, message):
        self.txs_received.append(message.tx)

    def on_ping(self, message):
        self.ping_nonces.append(message.nonce)
        super().on_ping(message)

    def on_notfound(self, message):
        self.notfound.extend(i.hash for i in message.vec)


class SilentRecipient(Recipient):
    """Handshakes, then never requests: what an honest peer that already has X looks like."""

    def on_inv(self, message):
        self.invs_received += 1


class NoRelayRecipient(Recipient):
    """Announces relay=false in its VERSION; the tool must not announce to it."""

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.relay = 0


class NoPongRecipient(Recipient):
    """Requests and receives X but never answers the PING."""

    def on_ping(self, message):
        self.ping_nonces.append(message.nonce)


class NoWtxidRecipient(Recipient):
    """Does not send WTXIDRELAY: the tool must leave it before announcing anything."""

    def __init__(self):
        super().__init__()
        self.wtxidrelay = False


class LateWtxidRecipient(NoWtxidRecipient):
    """Sends WTXIDRELAY only after its VERACK, too late for BIP339: the tool must leave it unannounced."""

    def on_version(self, message):
        super().on_version(message)
        self.send_without_ping(msg_wtxidrelay())


class WrongNoncePongRecipient(Recipient):
    """Requests and receives X, then answers the PING with another nonce, which answers nothing."""

    def on_ping(self, message):
        self.ping_nonces.append(message.nonce)
        self.send_without_ping(msg_pong(message.nonce ^ 1))


class EarlyRequestRecipient(Recipient):
    """Asks for X by wtxid right after its VERSION, before any announcement, and never again: the early
    request must be ignored, not remembered."""

    def __init__(self, wtxid):
        super().__init__()
        self.wtxid = wtxid

    def on_version(self, message):
        self.send_version()
        self.request([self.wtxid])
        super().on_version(message)

    def on_inv(self, message):
        self.invs_received += 1


class PingingRecipient(Recipient):
    """Sends a PING of its own after its VERACK: the tool answers nothing its profile does not send."""

    def on_version(self, message):
        super().on_version(message)
        self.send_without_ping(msg_ping(nonce=1))


class ProbingRecipient(Recipient):
    """Sends requests the profile does not allow, repeats the request after the transfer, and
    sends a late SENDTXRCNCL. None of it may be answered or change the tool's behaviour."""

    def on_inv(self, message):
        hashes = [i.hash for i in message.inv if i.type == MSG_WTX]
        self.request(hashes, inv_type=MSG_WITNESS_TX)  # the txid-relay form: not what a wtxid-relay peer is asked
        self.request(hashes)  # the one request that is answered

    def on_tx(self, message):
        super().on_tx(message)
        self.request([message.tx.wtxid_int])
        self.request([message.tx.wtxid_int])
        self.send_without_ping(msg_sendtxrcncl())


class WrongFormRecipient(Recipient):
    """Asks for the announced transaction only in forms E5 does not answer: by its wtxid as MSG_WITNESS_TX
    and as MSG_TX, twice in one request, and as MSG_WTX naming another hash. It must never be served."""

    def on_inv(self, message):
        self.invs_received += 1
        hashes = [i.hash for i in message.inv if i.type == MSG_WTX]
        self.request(hashes, inv_type=MSG_WITNESS_TX)
        self.request(hashes, inv_type=MSG_TX)
        self.request(hashes * 2)
        self.request([h ^ 1 for h in hashes])


class OldVersionRecipient(Recipient):
    """Announces protocol 70015, below the 70016 that BIP339 needs: the tool must leave it unannounced."""

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nVersion = 70015


class NoWitnessRecipient(Recipient):
    """Does not offer NODE_WITNESS: the tool must leave it unannounced."""

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services & ~NODE_WITNESS)


class FloodingRecipient(Recipient):
    """Floods the connection with announcements once the handshake is done, well past the receive cap."""
    MESSAGES = 10  # about 36 kB each

    def on_verack(self, message):
        super().on_verack(message)
        junk = msg_inv([CInv(MSG_TX, i) for i in range(1, 1001)])
        for _ in range(self.MESSAGES):
            self.send_without_ping(junk)


class PackageRecipient(Recipient):
    """A recipient in package mode that knows the parent's and child's ids."""

    def __init__(self, parent_txid, parent_wtxid, child_txid, child_wtxid):
        super().__init__()
        self.parent_txid, self.parent_wtxid = parent_txid, parent_wtxid
        self.child_txid, self.child_wtxid = child_txid, child_wtxid


class BatchedParentRecipient(PackageRecipient):
    """Resolves the child as a node lacking its parent does when the child's other inputs are confirmed
    coins it no longer remembers: it asks for every one of them by txid, ours last, in GETDATAs of up
    to 1000 entries, for as many inputs as a child of maximum standard weight can have. The request
    names the child's txid too, which the tool must neither serve nor call not found."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = [0x1000 + i for i in range(MAX_STANDARD_TX_WEIGHT // (4 * 41) - 2)]

    def on_tx(self, message):
        super().on_tx(message)
        if len(self.txs_received) == 1:
            wanted = [CInv(MSG_WITNESS_TX, h) for h in self.unknown + [self.child_txid, self.parent_txid]]
            for i in range(0, len(wanted), 1000):
                self.send_without_ping(msg_getdata(wanted[i:i + 1000]))


class BothNamedRecipient(PackageRecipient):
    """Asks for the child and the parent in one request before anything was served, which the tool must
    ignore outright, then for the child alone, then for the parent. Once it has the parent it asks for
    it again, with a transaction the tool does not have: after the parent phase nothing more is served
    and no NOTFOUND is sent."""

    def on_inv(self, message):
        self.invs_received += 1
        self.send_without_ping(msg_getdata([CInv(MSG_WTX, self.child_wtxid), CInv(MSG_WITNESS_TX, self.parent_txid)]))
        self.send_without_ping(msg_getdata([CInv(MSG_WTX, self.child_wtxid)]))

    def on_tx(self, message):
        super().on_tx(message)
        if len(self.txs_received) == 1:
            self.send_without_ping(msg_getdata([CInv(MSG_WITNESS_TX, self.parent_txid)]))
        elif len(self.txs_received) == 2:
            self.send_without_ping(msg_getdata([CInv(MSG_WITNESS_TX, self.parent_txid), CInv(MSG_WITNESS_TX, 0x2000)]))


class ParentWrongFormRecipient(PackageRecipient):
    """After the child, asks for the parent only in forms F2 does not answer: as MSG_TX by txid and as
    MSG_WTX by wtxid. It is never sent the parent, and gets no NOTFOUND: both name the job's own parent."""

    def on_tx(self, message):
        super().on_tx(message)
        self.send_without_ping(msg_getdata([CInv(MSG_TX, self.parent_txid)]))
        self.send_without_ping(msg_getdata([CInv(MSG_WTX, self.parent_wtxid)]))


class LateChildRecipient(PackageRecipient):
    """Asks for the child late in the request window and never for the parent."""

    def on_inv(self, message):
        self.invs_received += 1
        threading.Timer(LATE_CHILD_REQUEST_S, self.request, args=([self.child_wtxid],)).start()


class RecordingV2State(EncryptedP2PState):
    """Keeps the initiator's ellswift key, so that a test can check each attempt used its own."""

    peer_ellswift = None

    def complete_handshake(self, response):
        start = response.tell()
        theirs = self.received_prefix + response.read(64 - len(self.received_prefix))
        response.seek(start)
        if len(theirs) == 64:
            self.peer_ellswift = theirs
        return super().complete_handshake(response)


class ChildOnlyPeer(P2PInterface):
    """Delivers a child to the node and answers the node's request for its parent with NOTFOUND,
    so the node keeps the child as an orphan and turns to the next announcer for the parent."""

    def on_getdata(self, message):
        self.send_without_ping(msg_notfound(vec=message.inv))


class ToolPrivbcast(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The tool speaks v2 (BIP324) and never falls back to v1, so a node that
        # receives the transaction as an exit-path recipient must accept v2 (the mainnet default).
        self.extra_args = [["-v2transport=1"]]

    def add_options(self, parser):
        parser.add_argument("--package", action="store_true", help="test one-parent-one-child package mode (the extension) only")

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_privbcast()

    def setup_network(self):
        self.setup_nodes()

    # ---- SOCKS5 fixture -------------------------------------------------------------------

    def start_proxy(self, resolve_script, behaviours, node_endpoints=(), connect_delay=0, resolve_delay=0, proxy_authenticates=True, tor=True):
        """resolve_script: seed name -> list of answers, cycled per query.
        behaviours: endpoint address string -> (listener class, supports_v2).
        node_endpoints: endpoint address strings redirected to nodes[0].
        connect_delay: seconds the proxy stalls before answering any CONNECT (Tor building a circuit).
        resolve_delay: seconds the proxy stalls before answering any RESOLVE (a slow resolver).
        proxy_authenticates: if False the proxy offers only unauthenticated SOCKS, which the tool must refuse.
        tor: if False the proxy is an ordinary SOCKS5 proxy: no RESOLVE, no .onion."""
        self.listeners = {}
        self.listeners_lock = threading.Lock()
        self.connects = {}
        self.resolve_counts = {}

        def resolve_factory(name):
            with self.listeners_lock:
                n = self.resolve_counts.get(name, 0)
                self.resolve_counts[name] = n + 1
            answers = resolve_script.get(name)
            if not answers:
                return None
            return answers[n % len(answers)]

        def destinations_factory(requested_to_addr, requested_to_port, proxy_client):
            with self.listeners_lock:
                self.connects[requested_to_addr] = self.connects.get(requested_to_addr, 0) + 1
                if requested_to_addr in node_endpoints:
                    return {"actual_to_addr": "127.0.0.1", "actual_to_port": p2p_port(0)}
                if requested_to_addr not in behaviours:
                    self.log.debug(f"unexpected connect to {format_addr_port(requested_to_addr, requested_to_port)}")
                    return None
                if requested_to_addr not in self.listeners:
                    cls, v2 = behaviours[requested_to_addr]
                    listener = cls()
                    listener.peer_connect_helper(dstaddr="0.0.0.0", dstport=0, net=self.chain, timeout_factor=self.options.timeout_factor)
                    listener.peer_connect_send_version(services=P2P_SERVICES)
                    if v2:
                        listener.v2_state = RecordingV2State(initiating=False, net=self.chain)
                    else:
                        # A v1-only peer closes on the v2 handshake bytes; mark it so the framework does
                        # not log that expected close as an error. The tool never comes back over v1.
                        listener.reconnect = True
                    addr, port = start_p2p_listener(self.network_thread, listener)
                    self.listeners[requested_to_addr] = (listener, addr, port)
                _, addr, port = self.listeners[requested_to_addr]
                return {"actual_to_addr": addr, "actual_to_port": port}

        self.socks5_server = start_socks5_server(destinations_factory, resolve_factory, connect_reply_delay=connect_delay,
                                                 resolve_reply_delay=resolve_delay,
                                                 auth=proxy_authenticates, unauth=True, tor=tor)

    def stop_proxy(self):
        self.socks5_server.stop()

    def drain_socks_commands(self):
        commands = []
        while not self.socks5_server.queue.empty():
            item = self.socks5_server.queue.get()
            if isinstance(item, Exception):
                raise item
            commands.append(item)
        return commands

    # ---- tool invocation -------------------------------------------------------------------

    def tool_argv(self, *extra, chain="-regtest"):
        argv = self.get_binaries().privbcast_argv() + [chain, f"-tor=127.0.0.1:{self.socks5_server.conf.addr[1]}"]
        return argv + list(extra)

    def run_tool(self, *extra, stdin="", expected_rc=0, chain="-regtest", timeout=240):
        argv = self.tool_argv(*extra, chain=chain)
        self.log.debug(f"running {argv}")
        timeout *= self.options.timeout_factor
        try:
            proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"{argv} did not exit within {timeout} s")
        for line in proc.stderr.splitlines():
            self.log.debug(f"tool stderr: {line}")
        if expected_rc is not None:
            assert_equal(proc.returncode, expected_rc)
        return proc

    def run_send(self, tx_hex, *extra, expected_rc=0, time_divisor=TIME_DIVISOR):
        proc = self.run_tool(f"-timedivisor={time_divisor}", *extra, "send", stdin=tx_hex, expected_rc=expected_rc)
        return json.loads(proc.stdout), proc

    def start_send(self, tx_hex, *extra, time_divisor=TIME_DIVISOR):
        """Start a send job in the background (transaction from a file, so the process owns no pipe)."""
        path = os.path.join(self.options.tmpdir, f"send_{len(os.listdir(self.options.tmpdir))}.hex")
        with open(path, "w", encoding="utf8") as f:
            f.write(tx_hex)
        # Its own process group on Windows, so that interrupt() can target it alone with Ctrl-Break.
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0
        with open(path, encoding="utf8") as stdin:
            return subprocess.Popen(self.tool_argv(f"-timedivisor={time_divisor}", *extra, "send"),
                                    stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    creationflags=creationflags)

    def finish_send(self, proc):
        """Wait for a background send job; returns (returncode, report)."""
        out, err = proc.communicate(timeout=60 * self.options.timeout_factor)
        for line in err.splitlines():
            self.log.debug(f"tool stderr: {line}")
        return proc.returncode, json.loads(out)

    @staticmethod
    def interrupt(proc):
        """Interrupt a background job as a user would: SIGINT, or on Windows Ctrl-Break, which the tool handles the same way."""
        proc.send_signal(signal.CTRL_BREAK_EVENT if platform.system() == "Windows" else signal.SIGINT)

    @staticmethod
    def attempts(report):
        for s in report["slots"]:
            for a in s["attempts"]:
                yield s, a

    def attempts_to(self, report, endpoint):
        return [a for _, a in self.attempts(report) if a["endpoint"].startswith(endpoint)]

    # ---- tests -----------------------------------------------------------------------------

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 120)  # >100 for COINBASE_MATURITY, plus a margin of spendable UTXOs for every scenario
        if self.options.package:
            self.test_package_requests()
            self.test_package_node_recipient()
            self.test_package_existing_orphan()
            return
        self.test_argument_errors()
        self.test_bounded_job()
        self.test_concurrent_invocations()
        self.test_interrupt_mid_delivery()
        self.test_stalled_stderr()
        self.test_stalled_proxy()
        self.test_socks_auth_required()
        self.test_not_tor_proxy()
        self.test_unsuitable_peers()
        self.test_peer_deviations()
        self.test_assignment()
        self.test_slow_resolve()
        self.test_interrupt_blocked_resolve()
        self.test_node_recipient()
        self.test_discover()

    def test_argument_errors(self):
        self.log.info("Argument and input errors: exit status 1, found before any network activity")
        # Messages are for people and are not checked. Each case is built so that only one check can
        # fail, and a job that ran anyway would query a seed through the proxy at once: a.seed. on
        # regtest, the chain's own seeds elsewhere.
        self.start_proxy({"a.seed.": ["9.0.2.1"]}, {})
        timeout = 20 * self.options.timeout_factor

        def refused(*args, stdin, chain="-regtest"):
            try:
                rc = subprocess.run(self.tool_argv(*args, chain=chain), input=stdin, capture_output=True,
                                    text=True, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = None
            assert_equal(self.drain_socks_commands(), [])
            assert_equal(rc, 1)

        tx_hex = self.wallet.create_self_transfer()["hex"]
        refused("-seed=a.seed.", "send", stdin="zz")
        refused("-seed=a.seed.", "send", stdin="")
        # Two transactions must be a parent and its child; the same one twice is refused too.
        other_hex = self.wallet.create_self_transfer()["hex"]
        refused("-seed=a.seed.", "send", stdin=f"{tx_hex}\n{other_hex}")
        refused("-seed=a.seed.", "send", stdin=f"{tx_hex} {tx_hex}")
        # Regtest-only flags are refused elsewhere.
        refused("-seed=a.seed.", "send", stdin=tx_hex, chain="-signet")
        refused(f"-fixedseed={make_onion(3)}:{REGTEST_PORT}", "send", stdin=tx_hex, chain="-signet")
        refused(f"-timedivisor={TIME_DIVISOR}", "send", stdin=tx_hex, chain="-chain=main")
        # No command, or an unknown one, is an error.
        refused("-seed=a.seed.", stdin=tx_hex)
        refused("-seed=a.seed.", "frobnicate", stdin=tx_hex)
        # stdin is read up to its bound and no further: input still open past the bound is refused
        # without waiting for its end.
        proc = subprocess.Popen(self.tool_argv("-seed=a.seed.", "send"), stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def feed():
            try:
                proc.stdin.write((tx_hex + " " * MAX_STDIN_BYTES).encode())
                proc.stdin.flush()
            except OSError:
                pass  # the tool stopped reading
        writer = threading.Thread(target=feed)
        writer.start()
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            rc = None
        writer.join()
        try:
            proc.stdin.close()
        except OSError:
            pass
        assert_equal(self.drain_socks_commands(), [])
        assert_equal(rc, 1)
        # A remote SOCKS listener is refused.
        argv = self.get_binaries().privbcast_argv() + ["-regtest", "-tor=10.1.2.3:9050", "send"]
        try:
            proc = subprocess.run(argv, input=tx_hex, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AssertionError("a remote -tor must be refused before any network activity")
        assert_equal(proc.returncode, 1)
        # No arguments at all prints the usage.
        proc = subprocess.run(self.get_binaries().privbcast_argv(), capture_output=True, text=True, timeout=3 * timeout)
        assert_equal(proc.returncode, 1)
        assert proc.stdout
        self.stop_proxy()

    def test_bounded_job(self):
        self.log.info("A complete job against scripted recipients")
        # Half the usual pace: discovery opens twelve SOCKS streams at once, and a loaded CI host
        # (Windows) has been slow enough at TIME_DIVISOR to cost a query. This section counts every
        # query.
        divisor = 5
        # Every candidate of a seed shares one behaviour, and the four exit-path primaries cover
        # all three seeds whatever the tie order, so each behaviour is exercised on every run
        # rather than only when the shuffle happens to pick it.
        resolve_script = {
            "a.seed.": ["8.0.0.1", "8.0.0.2", "8.0.0.3", "8.0.0.1"],  # last answer repeats within the seed
            "b.seed.": ["8.0.1.1", "8.0.1.2", "8.0.1.3", "8.0.1.1"],
            "c.seed.": ["8.0.2.1", "8.0.2.2", "8.0.2.3", "8.0.2.1"],
        }
        seed_behaviour = {"a.seed.": NoPongRecipient, "b.seed.": NoRelayRecipient, "c.seed.": SilentRecipient}
        behaviours = {ip: (seed_behaviour[seed], True) for seed, ips in resolve_script.items() for ip in ips}
        # Two onions, one per onion slot: an honest but v1-only recipient (the tool never falls
        # back to v1, so it is never served) and a probing v2 recipient.
        v1_onion, probing_onion = make_onion(1), make_onion(2)
        behaviours[v1_onion] = (Recipient, False)
        behaviours[probing_onion] = (ProbingRecipient, True)
        self.start_proxy(resolve_script, behaviours)
        # The node is not among these recipients, so nothing about the job may touch its state.
        node = self.nodes[0]
        peers_before = len(node.getpeerinfo())
        banned_before = node.listbanned()
        mempool_before = node.getrawmempool()
        tx = self.wallet.create_self_transfer()
        report, proc = self.run_send(tx["hex"], "-seed=a.seed.", "-seed=b.seed.", "-seed=c.seed.",
                                     f"-fixedseed={v1_onion}:{REGTEST_PORT}", f"-fixedseed={probing_onion}:{REGTEST_PORT}",
                                     time_divisor=divisor)
        self.log.debug(json.dumps(report, indent=1))
        assert_equal(report["txid"], tx["txid"])
        assert_equal(report["wtxid"], tx["wtxid"])
        assert_equal(report["summary"]["interrupted"], False)
        # The report counts from job start: no field is named for a time and no number is an epoch
        # timestamp (a peer's protocol version is the peer's to choose). Progress went to stderr.
        def check_relative(value):
            if isinstance(value, dict):
                for key, v in value.items():
                    assert not key.startswith("time"), key
                    if key != "peer_version":
                        check_relative(v)
            elif isinstance(value, list):
                for v in value:
                    check_relative(v)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                assert value < 10**9, value
        check_relative(report)
        assert proc.stderr  # progress lines
        assert_equal(report["summary"]["slots_completed"], SLOTS)
        assert_greater_than_or_equal(SLOTS * OPPORTUNITIES_PER_SLOT, report["summary"]["connections"])

        # Discovery: four queries per seed, each on its own stream, and every candidate got the
        # chain port. The tool's accounting and the proxy's view must agree, on any host. A host
        # that stalls at job start skips queries rather than running them late, and one that
        # answers a SOCKS stage too slowly costs the query; both are the tool doing its job, so
        # the counts are asserted as invariants, not as the twelve answers a fast host gets.
        commands = self.drain_socks_commands()
        resolves = [c for c in commands if c.cmd == Command.RESOLVE]
        disc = report["discovery"]
        seeds = {s["name"]: s for s in disc["seeds"]}
        assert_equal(set(seeds), set(resolve_script))
        for name, st in seeds.items():
            assert_equal(st["queries"] + st["skipped"], 4)
            assert_greater_than_or_equal(st["queries"], self.resolve_counts.get(name, 0))  # a query sent may still not reach RESOLVE
            assert_greater_than_or_equal(self.resolve_counts.get(name, 0), st["answers"])
            assert_equal(st["kept"], min(st["accepted"], 3))
        assert_equal(len(resolves), sum(self.resolve_counts.values()))
        assert_equal(sum(st["answers"] for st in seeds.values()), disc["duplicates"] + disc["rejected"] + sum(st["accepted"] for st in seeds.values()))
        assert_equal(disc["rejected"], 0)
        assert_equal(disc["exit_path_candidates"], sum(st["kept"] for st in seeds.values()))
        assert_greater_than(disc["exit_path_candidates"], 0)
        assert_equal(disc["onion_candidates"], 2)
        # Stream isolation: every SOCKS stream authenticated with its own credentials.
        creds = [(c.username, c.password) for c in commands]
        assert all(u and p for u, p in creds)
        assert_equal(len(set(creds)), len(creds))
        for _, a in self.attempts(report):
            assert a["endpoint"].endswith(f":{REGTEST_PORT}")
            # The peer's protocol version and user agent, as it sent them.
            if a["peer_version"] is not None:
                assert_equal((a["peer_version"], a["peer_user_agent"]), (P2P_VERSION, P2P_SUBVERSION))

        # What follows assumes the host kept up: every query reached the proxy and no opportunity
        # was missed. A CI host that stalled reports otherwise; the tool's answer to a stall (skip
        # the query, miss the opportunity) is covered above, and the outcome shape is then not
        # applicable rather than wrong.
        missed = sum(s["missed_opportunities"] for s in report["slots"])
        skipped = sum(st["skipped"] for st in seeds.values())
        stalled = missed > 0 or skipped > 0 or len(resolves) < 12
        if stalled:
            self.log.warning(f"host stalled during the job (missed={missed}, skipped={skipped}, resolves={len(resolves)}): outcome checks not applicable")
        else:
            assert_greater_than_or_equal(report["summary"]["pongs"], 1)  # the probing onion pongs; the v1-only one is never served
            assert_greater_than(report["summary"]["announcements_written"], 0)
            # Exit-path outcomes follow the seed's behaviour; every seed was drawn at least once.
            def seed_of(ip):
                return next(seed for seed, ips in resolve_script.items() if ip in ips)

            seeds_attempted = set()
            for _, a in self.attempts(report):
                if a["source"] != "dns_seed":
                    continue
                seed = seed_of(a["endpoint"].rsplit(":", 1)[0])
                assert_equal(a["provenance"], seed)
                seeds_attempted.add(seed)
                if seed == "a.seed.":  # requests and receives X, never answers the PING
                    assert_equal(a["outcome"], "tx_written_no_pong")
                    assert a["tx_written_ms"] is not None
                    assert a["ping_written_ms"] is not None
                    assert a["pong_ms"] is None
                    # Ended when the PONG wait ran out.
                    assert -5 <= a["ended_ms"] - a["ping_written_ms"] - PONG_WAIT_S * 1000 / divisor <= 1000, a
                elif seed == "b.seed.":  # relay=false: refused before any announcement
                    assert_equal(a["outcome"], "not_announced")
                    assert a["inv_handed_ms"] is None
                    assert_equal(self.listeners[a["endpoint"].rsplit(":", 1)[0]][0].invs_received, 0)
                else:  # handshakes, never requests
                    assert_equal(a["outcome"], "announced_not_requested")
                    assert_equal(a["peer_user_agent"], P2P_SUBVERSION)
                    assert a["inv_written_ms"] is not None
                    assert a["getdata_ms"] is None
                    # Ended when the request window ran out.
                    assert -5 <= a["ended_ms"] - a["inv_handed_ms"] - REQUEST_WINDOW_S * 1000 / divisor <= 1000, a
            assert_equal(seeds_attempted, set(resolve_script))
            # Two onions: each onion slot's first attempt is one of them (R5a, R5c).
            for s in report["slots"]:
                if s["class"] == "onion":
                    assert_equal(s["attempts"][0]["source"], "bundled")
            # A refused primary is replaced at the slot's next opportunity by a candidate from another seed.
            replaced = [s for s in report["slots"]
                        if s["class"] == "exit_path" and s["attempts"] and s["attempts"][0]["provenance"] == "b.seed."]
            assert_greater_than(len(replaced), 0)
            for s in replaced:
                assert_greater_than_or_equal(len(s["attempts"]), 2)
                assert s["attempts"][1]["provenance"] != s["attempts"][0]["provenance"]
                assert s["attempts"][1]["inv_handed_ms"] is not None
            # The v1-only onion closes the v2 attempt without a byte. That is a plain transport
            # failure: the tool never falls back to v1, so the endpoint is never served.
            v1_attempts = self.attempts_to(report, v1_onion)
            assert_equal([a["outcome"] for a in v1_attempts], ["not_announced"])
            assert_equal(v1_attempts[0]["bytes_recv"], 0)
            assert_equal(len(self.listeners[v1_onion][0].txs_received), 0)
            # The probing onion: its txid-form request, repeats and late SENDTXRCNCL change nothing.
            probing = self.attempts_to(report, probing_onion)
            assert_equal(len(probing), 1)
            assert_equal(probing[0]["outcome"], "pong_received")
            assert_equal(probing[0]["extra_requests"], 3)  # txid-form request before, two repeats after
            assert_equal(len(self.listeners[probing_onion][0].txs_received), 1)  # served exactly once

        # Each endpoint is connected exactly once for the whole job.
        for endpoint, n in self.connects.items():
            assert_equal(n, 1)

        # An announcement ends its slot: no attempt follows one whose INV the transport took.
        for s in report["slots"]:
            for prev in s["attempts"][:-1]:
                assert prev["inv_handed_ms"] is None, s

        # Every recipient got at most one INV, naming the transaction's wtxid alone, and only messages
        # the profile sends.
        for listener, _, _ in self.listeners.values():
            assert_greater_than_or_equal(1, listener.invs_received)
            inv = listener.last_message.get("inv")
            if inv is not None:
                assert_equal([(i.type, i.hash) for i in inv.inv], [(MSG_WTX, int(tx["wtxid"], 16))])
            assert set(listener.last_message) <= {"version", "wtxidrelay", "verack", "inv", "tx", "ping"}, listener.last_message

        # Nothing is shared between attempts but the transaction and the profile: each recipient saw
        # its own BIP324 key and VERSION nonce, and each PING carried its own nonce.
        keys, version_nonces, ping_nonces = [], [], []
        for listener, _, _ in self.listeners.values():
            state = getattr(listener, "v2_state", None)
            if state is not None and state.peer_ellswift is not None:
                keys.append(ellswift_x(state.peer_ellswift))
            if "version" in listener.last_message:
                version_nonces.append(listener.last_message["version"].nNonce)
            ping_nonces.extend(listener.ping_nonces)
        assert_greater_than(len(keys), 1)
        for values in (keys, version_nonces, ping_nonces):
            assert_equal(len(set(values)), len(values))

        # The report names what was dialled and carries no transaction bytes.
        assert tx["hex"] not in json.dumps(report)

        # The VERSION every recipient saw is the fixed profile.
        for endpoint, (listener, _, _) in self.listeners.items():
            v = listener.last_message.get("version")
            if v is None:
                continue
            assert_equal(v.nVersion, PRIVATE_VERSION)
            assert_equal(v.nServices, NODE_WITNESS)
            assert_equal(v.strSubVer, PRIVATE_USER_AGENT)
            assert_equal(v.relay, 0)
            assert_equal(v.nStartingHeight, 0)
            assert_equal(v.nTime, 0)
            assert_equal((v.addrFrom.ip, v.addrFrom.port, v.addrFrom.nServices), ("0.0.0.0", 0, NODE_WITNESS))
            assert_equal((v.addrTo.ip, v.addrTo.port, v.addrTo.nServices), ("0.0.0.0", 0, 0))
            if not isinstance(listener, NoRelayRecipient):  # refused at its VERSION, before any reply
                assert "wtxidrelay" in listener.last_message  # BIP339 offered to every 70016+ peer

        # The schedule is drawn at job start: the prompt slots' primaries open together at delivery
        # start, every other primary at its own pre-drawn time, and each backup a pre-drawn 50-60 s
        # after the previous scheduled opportunity. Each attempt sits on a scheduled opportunity,
        # started within the scaled grace of it and ended by its deadline.
        delivery_ms = DISCOVERY_WINDOW_S * 1000 / divisor
        grace_ms = START_GRACE_S * 1000 / divisor
        attempt_max_ms = (HANDSHAKE_TIMEOUT_S + REQUEST_WINDOW_S + PONG_WAIT_S) * 1000 / divisor
        backup_min_ms = BACKUP_MIN_S * 1000 / divisor
        backup_max_ms = BACKUP_MAX_S * 1000 / divisor
        late_primaries = []
        for s in report["slots"]:
            sched = s["scheduled_ms"]
            assert_equal(len(sched), OPPORTUNITIES_PER_SLOT)
            if s["stratum"] == "prompt":
                assert abs(sched[0] - delivery_ms) <= 1, sched
            else:
                lo, hi = (MID_MIN_S, MID_MAX_S) if s["stratum"] == "mid" else (LATE_MIN_S, LATE_MAX_S)
                assert delivery_ms + lo * 1000 / divisor - 1 <= sched[0] <= delivery_ms + hi * 1000 / divisor + 1, sched
            if s["stratum"] == "late":
                late_primaries.append(sched[0])
            for k in range(1, len(sched)):
                assert backup_min_ms - 1 <= sched[k] - sched[k - 1] <= backup_max_ms + 1, sched
            for a in s["attempts"]:
                assert a["scheduled_start_ms"] in sched, a
                assert 0 <= a["started_ms"] - a["scheduled_start_ms"] <= grace_ms, a
                assert a["ended_ms"] <= a["scheduled_start_ms"] + attempt_max_ms + 200, a
            # A slot never has two connections alive at once, and dials no opportunity twice: each
            # attempt starts after the previous one ended, at a later opportunity.
            for prev, nxt in zip(s["attempts"], s["attempts"][1:]):
                assert_greater_than_or_equal(nxt["started_ms"], prev["ended_ms"])
                assert_greater_than(sched.index(nxt["scheduled_start_ms"]), sched.index(prev["scheduled_start_ms"]))
        assert_equal(len(late_primaries), 2)
        assert_greater_than_or_equal(abs(late_primaries[1] - late_primaries[0]), PRIMARY_SEPARATION_S * 1000 / divisor - 1)
        # The tool shares nothing with the node: as a bystander it never received the
        # transaction, opened no peer to the node, and changed no bans. (Address-manager
        # background churn is not a tool effect and is not asserted here.)
        assert tx["txid"] not in node.getrawmempool()
        assert_equal(node.getrawmempool(), mempool_before)
        assert_equal(len(node.getpeerinfo()), peers_before)
        assert_equal(node.listbanned(), banned_before)
        self.stop_proxy()

    def test_concurrent_invocations(self):
        self.log.info("Two send jobs run at once through one proxy, each its own broadcast")
        # The tool keeps no state between jobs and locks nothing, so two invocations sharing one
        # Tor proxy each complete independently. Distinct seeds and recipients let the run assert
        # that neither job saw the other's peer.
        addr1, addr2 = "8.5.0.1", "8.5.0.2"
        self.start_proxy({"a.seed.": [addr1], "b.seed.": [addr2]},
                         {addr1: (Recipient, True), addr2: (Recipient, True)})
        node = self.nodes[0]
        peers_before = len(node.getpeerinfo())
        tx1 = self.wallet.create_self_transfer()
        tx2 = self.wallet.create_self_transfer()
        assert tx1["txid"] != tx2["txid"]
        proc1 = self.start_send(tx1["hex"], "-seed=a.seed.")
        proc2 = self.start_send(tx2["hex"], "-seed=b.seed.")  # both processes now live at once
        rc1, report1 = self.finish_send(proc1)
        rc2, report2 = self.finish_send(proc2)
        for rc, report, tx, mine, other in ((rc1, report1, tx1, addr1, addr2), (rc2, report2, tx2, addr2, addr1)):
            assert_equal(rc, 0)
            assert_equal(report["txid"], tx["txid"])  # each job broadcast its own transaction
            assert_greater_than_or_equal(report["summary"]["pongs"], 1)
            assert_greater_than(report["summary"]["announcements_written"], 0)
            served = self.attempts_to(report, mine)
            assert_greater_than(len(served), 0)
            assert any(a["outcome"] == "pong_received" for a in served)
            assert_equal(self.attempts_to(report, other), [])  # never touched the other job's recipient
        assert_equal(len(node.getpeerinfo()), peers_before)  # neither job made the node a recipient
        # Nothing is shared between the two jobs: every proxy stream had its own credentials, each
        # recipient saw its own BIP324 key and VERSION nonce, and each job drew its own schedule.
        creds = [(c.username, c.password) for c in self.drain_socks_commands()]
        assert_equal(len(set(creds)), len(creds))
        l1, l2 = self.listeners[addr1][0], self.listeners[addr2][0]
        assert ellswift_x(l1.v2_state.peer_ellswift) != ellswift_x(l2.v2_state.peer_ellswift)
        assert l1.last_message["version"].nNonce != l2.last_message["version"].nNonce
        assert [s["scheduled_ms"] for s in report1["slots"]] != [s["scheduled_ms"] for s in report2["slots"]]
        self.stop_proxy()

    def test_socks_auth_required(self):
        self.log.info("A proxy offering no authentication: the tool resolves nothing and sends nothing")
        onion = make_onion(9)
        self.start_proxy({"a.seed.": ["9.0.0.1"]}, {onion: (Recipient, True)}, proxy_authenticates=False)
        # The greeting is answered with no-auth, which the tool refuses: no RESOLVE, no CONNECT.
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=a.seed.", f"-fixedseed={onion}:{REGTEST_PORT}", expected_rc=2)
        assert_equal(report["summary"]["announcements_written"], 0)
        for _, a in self.attempts(report):
            assert_equal(a["outcome"], "not_announced")
        assert_equal(self.connects, {})
        assert_equal(self.resolve_counts, {})  # the proxy never reached the RESOLVE stage
        assert_equal(self.drain_socks_commands(), [])
        self.stop_proxy()

    def test_not_tor_proxy(self):
        self.log.info("An authenticating proxy that is not Tor: no exit-path candidates, no onion reached, nothing sent")
        onion = make_onion(10)
        self.start_proxy({"a.seed.": ["9.0.1.1"]}, {onion: (Recipient, True)}, tor=False)
        # Every RESOLVE is refused as an unsupported command, so the only CONNECTs are to the onion, and
        # each fails at the proxy; nothing is announced.
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=a.seed.", f"-fixedseed={onion}:{REGTEST_PORT}", expected_rc=2)
        assert_equal(report["summary"]["announcements_written"], 0)
        assert_equal(report["discovery"]["exit_path_candidates"], 0)
        for _, a in self.attempts(report):
            assert_equal(a["outcome"], "not_announced")
        commands = self.drain_socks_commands()
        assert_equal(len([c for c in commands if c.cmd == Command.RESOLVE]), 4)
        connects = [c for c in commands if c.cmd == Command.CONNECT]
        assert connects
        assert all(c.addr.decode() == onion for c in connects)
        assert_equal(self.connects, {})  # no connection got past the proxy
        self.stop_proxy()

    def test_slow_resolve(self):
        self.log.info("A resolver that answers after the discovery window: no candidates, discovery still ends on time")
        window_s = DISCOVERY_WINDOW_S / TIME_DIVISOR
        self.start_proxy({"a.seed.": ["9.1.0.1"]}, {}, resolve_delay=window_s * 2)
        started = time.monotonic()
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "-seed=a.seed.", "-noprogress", "discover")
        elapsed = time.monotonic() - started
        out = json.loads(proc.stdout)
        assert_equal(out["seeds"][0]["queries"], 4)  # all four started at once
        assert_equal(out["seeds"][0]["kept"], 0)      # every answer arrived after the window
        # discover returns at the window, not after the resolver's much longer stall.
        assert_greater_than(window_s * 2, elapsed)
        assert_equal(self.connects, {})
        self.stop_proxy()

        self.log.info("With the same resolver a send job still starts delivery at the window")
        onions = [make_onion(12), make_onion(13)]
        self.start_proxy({"a.seed.": ["9.1.0.1"]}, {o: (Recipient, True) for o in onions}, resolve_delay=window_s * 2)
        tx = self.wallet.create_self_transfer()
        proc = self.start_send(tx["hex"], "-seed=a.seed.", *[f"-fixedseed={o}:{REGTEST_PORT}" for o in onions])
        self.wait_until(lambda: any(o in self.listeners and self.listeners[o][0].txs_received for o in onions))
        self.interrupt(proc)
        _, report = self.finish_send(proc)
        assert_equal(report["discovery"]["exit_path_candidates"], 0)
        prompt_onion = next(s for s in report["slots"] if s["class"] == "onion" and s["stratum"] == "prompt")
        assert_equal(prompt_onion["missed_opportunities"], 0)
        started_ms = prompt_onion["attempts"][0]["started_ms"]
        assert 0 <= started_ms - DISCOVERY_WINDOW_S * 1000 / TIME_DIVISOR <= START_GRACE_S * 1000 / TIME_DIVISOR, started_ms
        self.stop_proxy()

    def test_interrupt_blocked_resolve(self):
        self.log.info("SIGINT while workers are blocked in RESOLVE ends the job promptly")
        self.start_proxy({"a.seed.": ["9.2.0.1"]}, {}, resolve_delay=10)
        # Unscaled, so that the exchange's own timeouts are seconds away: only abandoning it ends the
        # job this soon.
        tx = self.wallet.create_self_transfer()
        proc = self.start_send(tx["hex"], "-seed=a.seed.", time_divisor=1)
        # Wait until a RESOLVE has reached the proxy and is stalling, so a query is genuinely blocked.
        self.wait_until(lambda: self.resolve_counts.get("a.seed.", 0) >= 1)
        self.interrupt(proc)
        interrupted = time.monotonic()
        rc, report = self.finish_send(proc)
        # The blocked exchanges were abandoned, not waited out.
        assert_greater_than(3 * self.options.timeout_factor, time.monotonic() - interrupted)
        assert_equal(rc, 2)
        assert_equal(report["summary"]["interrupted"], True)
        assert_equal(report["summary"]["connections"], 0)
        assert_equal(report["summary"]["slots_completed"], 0)
        assert_equal(self.connects, {})
        self.stop_proxy()

    def test_node_recipient(self):
        self.log.info("A bitcoind as the only recipient receives the transaction and nothing else changes")
        node = self.nodes[0]
        node_addr = "3.3.3.3"
        self.start_proxy({"c.seed.": [node_addr]}, {}, node_endpoints=(node_addr,))
        banned_before = node.listbanned()
        tx = self.wallet.create_self_transfer()
        assert tx["txid"] not in node.getrawmempool()
        report, _ = self.run_send(tx["hex"], "-seed=c.seed.")
        self.log.debug(json.dumps(report, indent=1))
        # Selecting the user's own node makes it an ordinary first-hop relayer: it receives the
        # transaction over v2 and accepts it. Its peer/address state changing is the expected
        # public-network consequence of self-connection, not the tool touching node state.
        atts = self.attempts_to(report, node_addr)
        assert_greater_than(len(atts), 0)
        assert any(a["outcome"] == "pong_received" for a in atts)
        assert_greater_than(report["summary"]["announcements_written"], 0)
        self.wait_until(lambda: tx["txid"] in node.getrawmempool())  # node accepts and relays it
        # No recipient misbehaved, so nothing gets banned.
        assert_equal(node.listbanned(), banned_before)
        self.stop_proxy()


    def test_package_node_recipient(self):
        self.log.info("A child with a low-fee parent: the node asks for the parent after the child and accepts both")
        node = self.nodes[0]
        node_addr = "3.3.3.4"
        self.start_proxy({"c.seed.": [node_addr]}, {}, node_endpoints=(node_addr,))
        # A zero-fee parent: below any relay floor on its own; the child pays for both.
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0"))
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
        alone = node.testmempoolaccept([parent["hex"]])[0]
        assert_equal(alone["allowed"], False)
        assert "min relay fee not met" in alone["reject-reason"]
        # testmempoolaccept does not apply the child's fee to the parent (no package feerates in test
        # accepts), so it cannot vouch for this package; the P2P 1p1c path below is the real check.
        # Child first on stdin: the tool orders the two by who spends whom. The node asks for the parent
        # 4 s after the child arrives (non-preferred plus txid-relay delay: the tool is a wtxid-relay
        # peer), which the parent hold must outlast; at TIME_DIVISOR the hold would be only 3 s.
        report, _ = self.run_send(child["hex"] + "\n" + parent["hex"], "-seed=c.seed.", time_divisor=5)
        self.log.debug(json.dumps(report, indent=1))
        assert_equal(report["txid"], child["txid"])
        assert_equal(report["parent_txid"], parent["txid"])
        served = [a for _, a in self.attempts(report) if a["parent_tx_written_ms"] is not None]
        assert_greater_than(len(served), 0)
        for a in served:
            assert a["getdata_ms"] is not None and a["tx_written_ms"] is not None
            assert_greater_than_or_equal(a["parent_getdata_ms"], a["getdata_ms"])  # asked for only after the child was requested
            assert_equal(a["outcome"], "pong_received")
        assert_greater_than(report["summary"]["parents_served"], 0)
        self.wait_until(lambda: child["txid"] in node.getrawmempool() and parent["txid"] in node.getrawmempool())
        self.stop_proxy()

    def test_package_existing_orphan(self):
        self.log.info("A node that already holds the child as an orphan asks the tool only for the parent")
        node = self.nodes[0]
        node_addr = "3.3.3.5"
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0"))
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
        # Another peer delivers the child first; the node orphans it and that peer cannot supply the parent.
        other = node.add_p2p_connection(ChildOnlyPeer())
        other.send_without_ping(msg_tx(tx_from_hex(child["hex"])))
        self.wait_until(lambda: child["txid"] in node.getorphantxs())
        other.wait_until(lambda: "notfound" in other.last_message or "getdata" in other.last_message)
        self.start_proxy({"e.seed.": [node_addr]}, {}, node_endpoints=(node_addr,))
        # Only a wtxid announcement adds the tool as an announcer of the existing orphan (BIP339). The
        # node then asks for the parent, never the child, 4 s later; see test_package_node_recipient.
        report, _ = self.run_send(child["hex"] + "\n" + parent["hex"], "-seed=e.seed.", time_divisor=5)
        self.log.debug(json.dumps(report, indent=1))
        served = [a for _, a in self.attempts(report) if a["parent_tx_written_ms"] is not None]
        assert_greater_than(len(served), 0)
        for a in served:
            assert a["getdata_ms"] is None and a["tx_written_ms"] is None  # the child was never asked for
            assert_greater_than_or_equal(a["parent_getdata_ms"], a["inv_handed_ms"])
            assert_equal(a["outcome"], "pong_received")
        self.wait_until(lambda: child["txid"] in node.getrawmempool() and parent["txid"] in node.getrawmempool())
        self.stop_proxy()
        node.disconnect_p2ps()

    def test_unsuitable_peers(self):
        self.log.info("Peers below protocol 70016, without NODE_WITNESS or without WTXIDRELAY are left unannounced; "
                      "requests in the wrong form go unanswered; a flooding peer is cut at the receive cap")
        old, no_witness, no_wtxid, flooder, wrong_form = "9.3.0.1", "9.3.0.2", "9.3.0.3", "9.3.0.4", "9.3.0.5"
        self.start_proxy({"v.seed.": [old, no_witness], "w.seed.": [no_wtxid, flooder], "x.seed.": [wrong_form]},
                         {old: (OldVersionRecipient, True), no_witness: (NoWitnessRecipient, True),
                          no_wtxid: (NoWtxidRecipient, True), flooder: (FloodingRecipient, True),
                          wrong_form: (WrongFormRecipient, True)})
        tx = self.wallet.create_self_transfer()
        # Whether the flooder was sent the INV before the cap cut it is a race, and with it the exit status.
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "-seed=v.seed.", "-seed=w.seed.", "-seed=x.seed.", "send", stdin=tx["hex"], expected_rc=None)
        report = json.loads(proc.stdout)
        self.log.debug(json.dumps(report, indent=1))
        for endpoint in (old, no_witness, no_wtxid):
            assert_equal([a["outcome"] for a in self.attempts_to(report, endpoint)], ["not_announced"])
            listener = self.listeners[endpoint][0]
            assert_equal(listener.invs_received, 0)
            assert not listener.txs_received
        assert_equal(self.attempts_to(report, old)[0]["peer_version"], 70015)
        asked = self.attempts_to(report, wrong_form)
        assert_equal([a["outcome"] for a in asked], ["announced_not_requested"])
        listener = self.listeners[wrong_form][0]
        assert_equal(listener.getdatas_sent, 4)
        assert not listener.txs_received
        flooded = self.attempts_to(report, flooder)
        assert_equal(len(flooded), 1)
        a = flooded[0]
        assert a["outcome"] in ("not_announced", "post_announcement_failure"), a
        # Past the cap, then cut: well short of the announcements it was sent, and early.
        assert_greater_than_or_equal(a["bytes_recv"], MAX_RECV_BYTES)
        assert_greater_than(FloodingRecipient.MESSAGES * 36_000, a["bytes_recv"])
        assert_greater_than(HANDSHAKE_TIMEOUT_S * 1000 / TIME_DIVISOR, a["ended_ms"] - a["scheduled_start_ms"])
        self.stop_proxy()

    def test_peer_deviations(self):
        self.log.info("A PONG with another nonce, WTXIDRELAY after VERACK, a request before the announcement, a PING from the peer")
        tx = self.wallet.create_self_transfer()
        wrong_nonce, late_wtxid, early, pinging = "9.3.1.1", "9.3.1.2", "9.3.1.3", "9.3.1.4"
        wtxid = int(tx["wtxid"], 16)
        self.start_proxy({"y.seed.": [wrong_nonce, late_wtxid], "z.seed.": [early, pinging]},
                         {wrong_nonce: (WrongNoncePongRecipient, True), late_wtxid: (LateWtxidRecipient, True),
                          early: (lambda: EarlyRequestRecipient(wtxid), True), pinging: (PingingRecipient, True)})
        report, _ = self.run_send(tx["hex"], "-seed=y.seed.", "-seed=z.seed.")
        self.log.debug(json.dumps(report, indent=1))
        # A PONG without the PING's nonce answers nothing: the attempt ends when the wait runs out.
        a = self.attempts_to(report, wrong_nonce)
        assert_equal([x["outcome"] for x in a], ["tx_written_no_pong"])
        assert -5 <= a[0]["ended_ms"] - a[0]["ping_written_ms"] - PONG_WAIT_S * 1000 / TIME_DIVISOR <= 1000, a[0]
        # WTXIDRELAY after VERACK is too late.
        assert_equal([x["outcome"] for x in self.attempts_to(report, late_wtxid)], ["not_announced"])
        assert_equal(self.listeners[late_wtxid][0].invs_received, 0)
        # A request before the announcement point is ignored, not remembered.
        assert_equal([x["outcome"] for x in self.attempts_to(report, early)], ["announced_not_requested"])
        assert_equal(self.listeners[early][0].invs_received, 1)
        assert_equal(self.listeners[early][0].txs_received, [])
        # The peer's own PING gets no PONG, and the attempt goes on as with any other peer.
        assert_equal([x["outcome"] for x in self.attempts_to(report, pinging)], ["pong_received"])
        assert "pong" not in self.listeners[pinging][0].last_message
        self.stop_proxy()

    def test_package_requests(self):
        self.log.info("Package mode against scripted recipients: batched, both-named, wrong-form and unasked parent requests, and a late child request")
        parent = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
        ids = dict(parent_txid=int(parent["txid"], 16), parent_wtxid=int(parent["wtxid"], 16),
                   child_txid=int(child["txid"], 16), child_wtxid=int(child["wtxid"], 16))
        batched, both, unasked, wrong_form, late = "9.6.0.1", "9.6.0.2", "9.6.0.3", "9.6.1.1", "9.6.1.2"
        self.start_proxy({"p.seed.": [batched, both, unasked], "q.seed.": [wrong_form, late]},
                         {batched: (lambda: BatchedParentRecipient(**ids), True),
                          both: (lambda: BothNamedRecipient(**ids), True),
                          unasked: (Recipient, True),
                          wrong_form: (lambda: ParentWrongFormRecipient(**ids), True),
                          late: (lambda: LateChildRecipient(**ids), True)})
        report, _ = self.run_send(child["hex"] + "\n" + parent["hex"], "-seed=p.seed.", "-seed=q.seed.")
        self.log.debug(json.dumps(report, indent=1))
        # Each was announced the child alone, by wtxid, once; the parent is never announced.
        for endpoint in (batched, both, unasked, wrong_form, late):
            listener = self.listeners[endpoint][0]
            assert_equal(listener.invs_received, 1)
            assert_equal([(i.type, i.hash) for i in listener.last_message["inv"].inv], [(MSG_WTX, ids["child_wtxid"])])
            assert set(listener.last_message) <= {"version", "wtxidrelay", "verack", "inv", "tx", "ping", "notfound"}, listener.last_message
            assert_equal([a["outcome"] for a in self.attempts_to(report, endpoint)], ["pong_received"])
        # The batched request: the parent served once, NOTFOUND for exactly the entries that are not ours,
        # and a request larger than a 64 KiB cap would have allowed.
        listener = self.listeners[batched][0]
        assert_equal([t.txid_hex for t in listener.txs_received], [child["txid"], parent["txid"]])
        assert_equal(sorted(listener.notfound), listener.unknown)
        a = self.attempts_to(report, batched)[0]
        assert a["parent_tx_written_ms"] is not None
        assert_greater_than(a["bytes_recv"], 64 * 1024)
        # Both named before the child was served: ignored outright, no NOTFOUND; then served in turn.
        listener = self.listeners[both][0]
        assert_equal([t.txid_hex for t in listener.txs_received], [child["txid"], parent["txid"]])
        assert_equal(listener.notfound, [])
        assert_greater_than_or_equal(self.attempts_to(report, both)[0]["extra_requests"], 1)
        # Never asked for the parent: the PING waited out the hold, then went.
        listener = self.listeners[unasked][0]
        assert_equal([t.txid_hex for t in listener.txs_received], [child["txid"]])
        a = self.attempts_to(report, unasked)[0]
        assert a["parent_hold_expired_ms"] is not None and a["parent_getdata_ms"] is None
        assert_greater_than_or_equal(a["ping_written_ms"] - a["tx_written_ms"], PARENT_HOLD_S * 1000 / TIME_DIVISOR - 100)
        assert_greater_than_or_equal(PARENT_HOLD_S * 1000 / TIME_DIVISOR + 1000, a["ping_written_ms"] - a["tx_written_ms"])
        # Asked for the parent only in forms F2 does not serve: never sent it, and no NOTFOUND, since
        # both name the job's own parent. The PING waited out the hold.
        listener = self.listeners[wrong_form][0]
        assert_equal([t.txid_hex for t in listener.txs_received], [child["txid"]])
        assert_equal(listener.notfound, [])
        a = self.attempts_to(report, wrong_form)[0]
        assert a["parent_getdata_ms"] is None and a["parent_hold_expired_ms"] is not None
        # Asked for the child late: the hold was cut so that the PING went out PONG_WAIT before the
        # request window ends.
        a = self.attempts_to(report, late)[0]
        cut_ms = (REQUEST_WINDOW_S - PONG_WAIT_S) * 1000 / TIME_DIVISOR
        assert -5 <= a["ping_written_ms"] - a["inv_handed_ms"] - cut_ms <= 1000, a
        assert_greater_than(PARENT_HOLD_S * 1000 / TIME_DIVISOR, a["ping_written_ms"] - a["tx_written_ms"])
        self.stop_proxy()

    def test_assignment(self):
        self.log.info("Assignment: seeds spread over slots; onion slots take onions")
        # No endpoint is reachable, so every assigned opportunity is dialled and fails before announcing.
        # Four seeds of three and ten onions, of which eight are kept: every exit-path slot's opportunities
        # come from distinct seeds, the four first attempts from four seeds, and the onion slots dial
        # the eight kept onions, each once.
        tx = self.wallet.create_self_transfer()
        seeds = {f"q{n}.seed.": [f"9.8.{n}.{i}" for i in range(1, 4)] for n in range(1, 5)}
        onions = [make_onion(20 + i) for i in range(10)]
        self.start_proxy(seeds, {})
        report, _ = self.run_send(tx["hex"], *[f"-seed={name}" for name in seeds],
                                  *[f"-fixedseed={o}:{REGTEST_PORT}" for o in onions], expected_rc=2)
        self.log.debug(json.dumps(report, indent=1))
        kept = {st["name"]: st["kept"] for st in report["discovery"]["seeds"]}
        if kept != {name: 3 for name in seeds}:
            self.log.warning(f"host lost discovery answers ({kept}): spread checks not applicable")
        else:
            first = []
            for s in report["slots"]:
                if s["class"] != "exit_path":
                    continue
                provenance = [a["provenance"] for a in s["attempts"]]
                assert_equal(len(set(provenance)), len(provenance))
                first.append(provenance[0])
            assert_equal(len(set(first)), 4)
        for s in report["slots"]:
            for a in s["attempts"]:
                assert_equal(a["source"], "bundled" if s["class"] == "onion" else "dns_seed")
        assert_equal(report["discovery"]["onion_candidates"], 8)
        onion_endpoints = [a["endpoint"] for s, a in self.attempts(report) if s["class"] == "onion"]
        assert_equal(len(set(onion_endpoints)), 8)
        assert_equal(len(onion_endpoints), 8)
        self.stop_proxy()

    def test_discover(self):
        self.log.info("discover resolves through the proxy and opens no connection")
        # Seed a answers IPv4, IPv6 and a private address, which is rejected (the fourth query repeats
        # the first answer: a duplicate); seed b answers four distinct addresses, of which three are
        # kept; seeds c and d both answer one address, which counts once; seed z's queries all fail.
        # Half the usual pace, as in test_bounded_job: every query is counted.
        self.start_proxy({"a.seed.": ["1.1.1.1", "2606:4700:4700::1111", "10.0.0.1"],
                          "b.seed.": ["2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4"],
                          "c.seed.": ["4.4.4.1"], "d.seed.": ["4.4.4.1"]}, {"1.1.1.1": (Recipient, True)})
        proc = self.run_tool("-timedivisor=5", "-seed=a.seed.", "-seed=b.seed.", "-seed=c.seed.", "-seed=d.seed.", "-seed=z.seed.",
                             "-noprogress", "discover")
        out = json.loads(proc.stdout)
        seeds = {s["name"]: s for s in out["seeds"]}
        assert_equal(seeds["a.seed."]["queries"], 4)
        assert_equal(seeds["a.seed."]["answers"], 4)
        assert_equal(seeds["a.seed."]["kept"], 2)
        assert_equal(sorted(seeds["a.seed."]["candidates"]), [f"1.1.1.1:{REGTEST_PORT}", f"[2606:4700:4700::1111]:{REGTEST_PORT}"])
        assert_equal((seeds["b.seed."]["answers"], seeds["b.seed."]["accepted"], seeds["b.seed."]["kept"]), (4, 4, 3))
        b_kept = seeds["b.seed."]["candidates"]
        assert_equal(len(set(b_kept)), 3)
        assert set(b_kept) <= {f"2.2.2.{i}:{REGTEST_PORT}" for i in range(1, 5)}, b_kept
        assert_equal(seeds["z.seed."]["queries"], 4)
        assert_equal(seeds["z.seed."]["answers"], 0)
        assert_equal(seeds["z.seed."]["kept"], 0)
        c, d = seeds["c.seed."], seeds["d.seed."]
        assert_equal(sorted([c["accepted"], d["accepted"]]), [0, 1])
        assert_equal(c["candidates"] + d["candidates"], [f"4.4.4.1:{REGTEST_PORT}"])
        assert_equal(out["duplicates"], 1 + 7)  # a.seed.'s repeat, and all but one answer of 4.4.4.1
        assert_equal(out["rejected"], 1)
        commands = self.drain_socks_commands()
        assert_equal([c.cmd for c in commands], [Command.RESOLVE] * 20)
        assert_equal(self.connects, {})
        self.stop_proxy()

    def test_stalled_proxy(self):
        self.log.info("A proxy that stalls every CONNECT: attempts fail within the handshake budget, later opportunities start on time")
        # Half the usual pace, since nine proxy handlers stall at once. The stall ends inside the scaled
        # handshake budget (45 s / 5 = 9 s) with a failure, and a slot's next opportunity is at least 10 s
        # later, so a backup still starts on time.
        # Three seeds of three (discovery keeps at most three candidates per seed): with no onions known the
        # onion slots fall back to exit-path peers, so nine candidates make six primaries and three backups.
        # The fixed-seed list holds only an IPv4 and an IPv6 entry, which give no candidate.
        divisor = 5
        script = {"s.seed.": ["8.1.0.1", "8.1.0.2", "8.1.0.3"], "t.seed.": ["8.1.1.1", "8.1.1.2", "8.1.1.3"],
                  "u.seed.": ["8.1.2.1", "8.1.2.2", "8.1.2.3"]}
        self.start_proxy(script, {}, connect_delay=8.0)
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=s.seed.", "-seed=t.seed.", "-seed=u.seed.",
                                  f"-fixedseed=9.9.9.9:{REGTEST_PORT}", f"-fixedseed=[2606:4700::6810:1]:{REGTEST_PORT}",
                                  expected_rc=2, time_divisor=divisor)
        self.log.debug(json.dumps(report, indent=1))
        assert_equal(report["summary"]["interrupted"], False)
        assert_equal(report["summary"]["slots_completed"], SLOTS)
        assert_equal(report["summary"]["announcements_written"], 0)
        # Every attempt went to a seed's answer; the fixed seeds gave no candidate.
        assert_equal(report["discovery"]["onion_candidates"], 0)
        assert {a["endpoint"] for _, a in self.attempts(report)} <= {f"{ip}:{REGTEST_PORT}" for ips in script.values() for ip in ips}
        # Six primaries and three backups, all stalled and all on time; the rest is empty.
        assert_equal(report["summary"]["connections"], 9)
        handshake_ms = HANDSHAKE_TIMEOUT_S * 1000 / divisor
        grace_ms = START_GRACE_S * 1000 / divisor
        for s in report["slots"]:
            assert_equal(s["missed_opportunities"], 0)
            for a in s["attempts"]:
                assert_equal(a["outcome"], "not_announced")
                assert 0 <= a["started_ms"] - a["scheduled_start_ms"] <= grace_ms, a
                # Failed within the handshake budget, so the slot's next opportunity is not held up.
                assert a["ended_ms"] - a["scheduled_start_ms"] <= handshake_ms + 200, a
        # Scarce candidates go to first attempts: every slot dialled its first opportunity, and the three
        # left over went to second ones, of exit-path slots, which draw before the onion slots fall back.
        for s in report["slots"]:
            assert_equal(s["attempts"][0]["scheduled_start_ms"], s["scheduled_ms"][0])
            for a in s["attempts"][1:]:
                assert_equal(a["scheduled_start_ms"], s["scheduled_ms"][1])
                assert_equal(s["class"], "exit_path")
        # A stalled primary's backup was tried, at its own scheduled time.
        assert any(len(s["attempts"]) >= 2 for s in report["slots"])
        # The job ends by its scheduled end: nothing stretched.
        assert report["summary"]["duration_ms"] <= max(s["scheduled_end_ms"] for s in report["slots"]) + 1500
        self.stop_proxy()

    def test_stalled_stderr(self):
        self.log.info("A full stderr pipe nobody drains: progress lines are dropped, the schedule is not held up")
        try:
            import fcntl
        except ImportError:
            self.log.info("skipped: no fcntl on this platform")
            return
        if not hasattr(fcntl, "F_SETPIPE_SZ"):
            self.log.info("skipped: no F_SETPIPE_SZ on this platform")
            return
        self.start_proxy({"a.seed.": ["8.3.0.1"]}, {"8.3.0.1": (Recipient, True)})
        proc = r_fd = w_fd = None
        try:
            tx = self.wallet.create_self_transfer()
            r_fd, w_fd = os.pipe()
            # The smallest pipe the kernel allows, filled to capacity before the tool starts: every
            # write the tool attempts finds it full, and nobody reads until the job is over. A write
            # that waited for room would hold its slot for the whole job.
            capacity = fcntl.fcntl(w_fd, fcntl.F_SETPIPE_SZ, 4096)
            os.set_blocking(w_fd, False)
            filled = 0
            while True:
                try:
                    filled += os.write(w_fd, b"x" * (capacity - filled or 1))
                except BlockingIOError:
                    break
            os.set_blocking(w_fd, True)  # the tool inherits an ordinary blocking descriptor
            assert_greater_than(filled, 0)
            started = time.monotonic()
            proc = subprocess.Popen(self.tool_argv(f"-timedivisor={TIME_DIVISOR}", "-seed=a.seed.", "-debug=1", "send"),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=w_fd, text=True)
            os.close(w_fd)
            w_fd = None
            out, _ = proc.communicate(input=tx["hex"], timeout=120 * self.options.timeout_factor)
            elapsed = time.monotonic() - started
            assert_equal(proc.returncode, 0)
            report = json.loads(out)
            assert_greater_than(report["summary"]["pongs"], 0)
            assert_equal(report["summary"]["slots_completed"], SLOTS)
            # Ended by its scheduled bound plus report time, not when someone read stderr.
            bound_s = (DISCOVERY_WINDOW_S + LATE_MAX_S + (OPPORTUNITIES_PER_SLOT - 1) * BACKUP_MAX_S
                       + HANDSHAKE_TIMEOUT_S + REQUEST_WINDOW_S + PONG_WAIT_S) / TIME_DIVISOR
            assert_greater_than(bound_s + 10, elapsed)
            # The pipe holds exactly the filler: not one line waited for room, none got through.
            os.set_blocking(r_fd, False)
            got = b""
            while True:
                try:
                    chunk = os.read(r_fd, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                got += chunk
            assert_equal(len(got), filled)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()  # a tool that waited for room is still blocked in its first write
                proc.communicate()
            for fd in (w_fd, r_fd):
                if fd is not None:
                    os.close(fd)
            self.stop_proxy()

    def test_interrupt_mid_delivery(self):
        self.log.info("SIGINT after the recipient received our INV: exit status 0, and the report says interrupted")
        self.start_proxy({"a.seed.": ["8.2.0.1"]}, {"8.2.0.1": (Recipient, True)})
        tx = self.wallet.create_self_transfer()
        proc = self.start_send(tx["hex"], "-seed=a.seed.")
        # Cancel once the recipient has seen our INV: it was fully written by then.
        self.wait_until(lambda: "8.2.0.1" in self.listeners and self.listeners["8.2.0.1"][0].invs_received >= 1)
        self.interrupt(proc)
        interrupted = time.monotonic()
        rc, report = self.finish_send(proc)
        assert_greater_than(3 * self.options.timeout_factor, time.monotonic() - interrupted)
        assert_equal(report["summary"]["interrupted"], True)
        assert_greater_than(SLOTS, report["summary"]["slots_completed"])
        assert_greater_than(report["summary"]["announcements_written"], 0)
        assert_equal(rc, 0)
        self.stop_proxy()


if __name__ == "__main__":
    ToolPrivbcast(__file__).main()
