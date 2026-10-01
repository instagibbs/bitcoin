# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared code for the bitcoin-privbcast functional tests (tool_privbcast*.py).

The tool reaches the network only through a Tor SOCKS5 listener. Here that listener is the
test framework's SOCKS5 server: RESOLVE queries for the test seed names are answered from a
fixed script, and CONNECT requests are redirected to Python P2P listeners with chosen
behaviours, or to a bitcoind. Every wire-visible parameter is a constant in the tool;
regtest-only flags supply the seeds, the bundled onions and a time divisor.
"""


import base64
import hashlib
import json
import os
import platform
import signal
import subprocess
import threading

from test_framework.messages import (
    CInv,
    MSG_WTX,
    msg_getdata,
)
from test_framework.netutil import format_addr_port
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    start_p2p_listener,
)
from test_framework.socks5 import (
    start_socks5_server,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
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


MAX_RECV_BYTES = 128 * 1024


MAX_STDIN_BYTES = 8_004_096


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


class PrivbcastToolTest(BitcoinTestFramework):
    """Runs bitcoin-privbcast through the framework's SOCKS5 server, against scripted recipients."""
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The tool speaks v2 (BIP324) and never falls back to v1, so a node that
        # receives the transaction as an exit-path recipient must accept v2 (the mainnet default).
        self.extra_args = [["-v2transport=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_privbcast()

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        raise NotImplementedError

    def setup_wallet(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 120)  # >100 for COINBASE_MATURITY, plus a margin of spendable UTXOs for every scenario

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
