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
import os
import signal
import subprocess
import threading
import time

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_WITNESS_TX,
    NODE_WITNESS,
    msg_getdata,
    msg_sendtxrcncl,
)
from test_framework.netutil import format_addr_port
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
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

# Mirrors the constants in src/privbcast/{job,session,discovery}.h. The tool has no knobs, so the
# checks below hardcode what they test against.
TIME_DIVISOR = 10  # scaled budgets (4.5 s handshake, 7.5 s request window, 1 s PONG) comfortably cover a real bitcoind recipient
PRIVATE_VERSION = 70016
PRIVATE_USER_AGENT = "/pynode:0.0.1/"
REGTEST_PORT = 18444
SLOTS = 6
OPPORTUNITIES_PER_SLOT = 4
DISCOVERY_WINDOW_S = 18
START_GRACE_S = 5
HANDSHAKE_TIMEOUT_S = 45
HANDSHAKE_RESERVE_S = 10
REQUEST_WINDOW_S = 75
PONG_WAIT_S = 10
BACKUP_MIN_S, BACKUP_MAX_S = 50, 60
MID_MIN_S, MID_MAX_S = 35, 180
LATE_MIN_S, LATE_MAX_S = 185, 240
PRIMARY_SEPARATION_S = 5


def make_onion(seed: int) -> str:
    """A syntactically valid v3 onion address derived from a one-byte seed."""
    pubkey = bytes([seed]) * 32
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + checksum + b"\x03").decode().lower() + ".onion"


class Recipient(P2PInterface):
    """An honest recipient: requests the announced transaction the BIP144 way and answers PING."""

    def __init__(self):
        super().__init__()
        self.txs_received = []
        self.getdatas_sent = 0
        self.invs_received = 0

    def request(self, hashes, inv_type=MSG_WITNESS_TX):
        want = msg_getdata()
        for h in hashes:
            want.inv.append(CInv(inv_type, h))
        self.getdatas_sent += 1
        self.send_without_ping(want)

    def on_inv(self, message):
        self.invs_received += 1
        self.request([i.hash for i in message.inv if i.type == MSG_TX])

    def on_tx(self, message):
        self.txs_received.append(message.tx)


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
        pass


class ProbingRecipient(Recipient):
    """Sends requests the profile does not allow, repeats the request after the transfer, and
    sends a late SENDTXRCNCL. None of it may be answered or change the tool's behaviour."""

    def on_inv(self, message):
        hashes = [i.hash for i in message.inv if i.type == MSG_TX]
        self.request(hashes, inv_type=MSG_TX)  # plain MSG_TX: not what a NODE_WITNESS peer is asked
        self.request(hashes)  # the one request that is answered

    def on_tx(self, message):
        super().on_tx(message)
        self.request([message.tx.txid_int])
        self.request([message.tx.txid_int])
        self.send_without_ping(msg_sendtxrcncl())


class ToolPrivbcast(BitcoinTestFramework):
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

    # ---- SOCKS5 fixture -------------------------------------------------------------------

    def start_proxy(self, resolve_script, behaviours, node_endpoints=(), connect_delay=0, resolve_delay=0, proxy_authenticates=True):
        """resolve_script: seed name -> list of answers, cycled per query.
        behaviours: endpoint address string -> (listener class, supports_v2).
        node_endpoints: endpoint address strings redirected to nodes[0].
        connect_delay: seconds the proxy stalls before answering any CONNECT (Tor building a circuit).
        resolve_delay: seconds the proxy stalls before answering any RESOLVE (a slow resolver).
        proxy_authenticates: if False the proxy offers only unauthenticated SOCKS, which the tool must refuse."""
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
                        listener.v2_state = EncryptedP2PState(initiating=False, net=self.chain)
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
                                                 auth=proxy_authenticates, unauth=True)

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
        proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
        for line in proc.stderr.splitlines():
            self.log.debug(f"tool stderr: {line}")
        assert_equal(proc.returncode, expected_rc)
        return proc

    def run_send(self, tx_hex, *extra, expected_rc=0):
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", *extra, "send", stdin=tx_hex, expected_rc=expected_rc)
        return json.loads(proc.stdout), proc

    def start_send(self, tx_hex, *extra):
        """Start a send job in the background (transaction from a file, so the process owns no pipe)."""
        path = os.path.join(self.options.tmpdir, f"send_{len(os.listdir(self.options.tmpdir))}.hex")
        with open(path, "w", encoding="utf8") as f:
            f.write(tx_hex)
        with open(path, encoding="utf8") as stdin:
            return subprocess.Popen(self.tool_argv(f"-timedivisor={TIME_DIVISOR}", *extra, "send"),
                                    stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish_send(self, proc):
        """Wait for a background send job; returns (returncode, report)."""
        out, err = proc.communicate(timeout=60)
        for line in err.splitlines():
            self.log.debug(f"tool stderr: {line}")
        return proc.returncode, json.loads(out)

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
        self.generate(self.wallet, 110)  # >100 for COINBASE_MATURITY, plus several spendable UTXOs
        self.test_argument_errors()
        self.test_bounded_job()
        self.test_interrupt()
        self.test_interrupt_mid_delivery()
        self.test_stalled_stderr()
        self.test_stalled_proxy()
        self.test_socks_auth_required()
        self.test_slow_resolve()
        self.test_interrupt_blocked_resolve()
        self.test_node_recipient()
        self.test_discover()

    def test_argument_errors(self):
        self.log.info("Argument and input errors")
        self.start_proxy({}, {})
        tx_hex = self.wallet.create_self_transfer()["hex"]
        proc = self.run_tool("send", stdin="zz", expected_rc=1)
        assert "decode failed" in proc.stderr
        proc = self.run_tool("send", stdin="", expected_rc=1)
        assert "no transaction" in proc.stderr
        # Regtest-only flags are refused elsewhere, before any network activity.
        proc = self.run_tool("-seed=a.seed.", "send", stdin=tx_hex, expected_rc=1, chain="-signet")
        assert "only accepted on regtest" in proc.stderr
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "send", stdin=tx_hex, expected_rc=1, chain="-chain=main")
        assert "only accepted on regtest" in proc.stderr
        # A remote SOCKS listener is refused.
        argv = self.get_binaries().privbcast_argv() + ["-regtest", "-tor=10.1.2.3:9050", "send"]
        proc = subprocess.run(argv, input=tx_hex, capture_output=True, text=True, timeout=60)
        assert_equal(proc.returncode, 1)
        assert "loopback" in proc.stderr
        # No command, or an unknown one.
        proc = self.run_tool(stdin=tx_hex, expected_rc=1)
        proc = self.run_tool("frobnicate", stdin=tx_hex, expected_rc=1)
        assert_equal(self.drain_socks_commands(), [])
        self.stop_proxy()

    def test_bounded_job(self):
        self.log.info("A complete job against scripted recipients")
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
                                     f"-fixedseed={v1_onion}:{REGTEST_PORT}", f"-fixedseed={probing_onion}:{REGTEST_PORT}")
        self.log.debug(json.dumps(report, indent=1))
        assert_equal(report["txid"], tx["txid"])
        assert_equal(report["wtxid"], tx["wtxid"])
        assert_equal(report["summary"]["interrupted"], False)
        assert_equal(report["summary"]["slots_completed"], SLOTS)
        assert_greater_than_or_equal(report["summary"]["pongs"], 1)  # the probing onion pongs; the v1-only one is never served
        assert_greater_than(report["summary"]["announcements_written"], 0)
        assert_greater_than_or_equal(SLOTS * OPPORTUNITIES_PER_SLOT, report["summary"]["connections"])

        # Discovery: four queries per seed, each on its own stream; repeats are counted, and every
        # candidate got the chain port.
        commands = self.drain_socks_commands()
        resolves = [c for c in commands if c.cmd == Command.RESOLVE]
        assert_equal(len(resolves), 12)
        assert_equal(self.resolve_counts, {"a.seed.": 4, "b.seed.": 4, "c.seed.": 4})
        disc = report["discovery"]
        assert_equal({s["name"]: s["queries"] for s in disc["seeds"]}, {"a.seed.": 4, "b.seed.": 4, "c.seed.": 4})
        assert_equal(disc["duplicates"], 3)
        assert_equal(disc["rejected"], 0)
        assert_equal(disc["exit_path_candidates"], 9)
        assert_equal(disc["onion_candidates"], 2)
        # Stream isolation: every SOCKS stream authenticated with its own credentials.
        creds = [(c.username, c.password) for c in commands]
        assert all(u and p for u, p in creds)
        assert_equal(len(set(creds)), len(creds))
        for _, a in self.attempts(report):
            assert a["endpoint"].endswith(f":{REGTEST_PORT}")

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
            elif seed == "b.seed.":  # relay=false: refused before any announcement
                assert_equal(a["outcome"], "not_announced")
                assert_equal(a["reason"], "relay=false")
                assert a["inv_handed_ms"] is None
            else:  # handshakes, never requests
                assert_equal(a["outcome"], "announced_not_requested")
                assert a["inv_written_ms"] is not None
                assert a["getdata_ms"] is None
        assert_equal(seeds_attempted, set(resolve_script))
        # A refused primary is replaced at the slot's next opportunity by a candidate from another seed.
        replaced = [s for s in report["slots"]
                    if s["class"] == "exit_path" and s["attempts"] and s["attempts"][0]["reason"] == "relay=false"]
        assert_greater_than(len(replaced), 0)
        for s in replaced:
            assert_greater_than_or_equal(len(s["attempts"]), 2)
            assert s["attempts"][1]["provenance"] != s["attempts"][0]["provenance"]
            assert s["attempts"][1]["inv_handed_ms"] is not None
        # The v1-only onion closes the v2 attempt without a byte. That is a plain transport
        # failure: the tool never falls back to v1, so the endpoint is never served.
        v1_attempts = self.attempts_to(report, v1_onion)
        assert_equal([(a["outcome"], a["reason"]) for a in v1_attempts], [("not_announced", "peer closed")])
        assert_equal(v1_attempts[0]["bytes_recv"], 0)
        assert_equal(len(self.listeners[v1_onion][0].txs_received), 0)
        # The probing onion: its plain MSG_TX request, repeats and late SENDTXRCNCL change nothing.
        probing = self.attempts_to(report, probing_onion)
        assert_equal(len(probing), 1)
        assert_equal(probing[0]["outcome"], "pong_received")
        assert_equal(probing[0]["extra_requests"], 3)  # plain MSG_TX before, two repeats after
        assert_equal(len(self.listeners[probing_onion][0].txs_received), 1)  # served exactly once

        # Each endpoint is connected exactly once for the whole job.
        for endpoint, n in self.connects.items():
            assert_equal(n, 1)

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
            assert_equal(v.addrFrom.nServices, NODE_WITNESS)

        # The schedule is drawn at job start: the prompt slots' primaries open together at delivery
        # start, every other primary at its own pre-drawn time, and each backup a pre-drawn 50-60 s
        # after the previous scheduled opportunity. Each attempt sits on a scheduled opportunity,
        # started within the scaled grace of it and ended by its deadline.
        delivery_ms = DISCOVERY_WINDOW_S * 1000 / TIME_DIVISOR
        grace_ms = START_GRACE_S * 1000 / TIME_DIVISOR
        attempt_max_ms = (HANDSHAKE_TIMEOUT_S + REQUEST_WINDOW_S + PONG_WAIT_S) * 1000 / TIME_DIVISOR
        backup_min_ms = BACKUP_MIN_S * 1000 / TIME_DIVISOR
        backup_max_ms = BACKUP_MAX_S * 1000 / TIME_DIVISOR
        late_primaries = []
        for s in report["slots"]:
            sched = s["scheduled_ms"]
            assert_equal(len(sched), OPPORTUNITIES_PER_SLOT)
            if s["stratum"] == "prompt":
                assert abs(sched[0] - delivery_ms) <= 1, sched
            else:
                lo, hi = (MID_MIN_S, MID_MAX_S) if s["stratum"] == "mid" else (LATE_MIN_S, LATE_MAX_S)
                assert delivery_ms + lo * 1000 / TIME_DIVISOR - 1 <= sched[0] <= delivery_ms + hi * 1000 / TIME_DIVISOR + 1, sched
            if s["stratum"] == "late":
                late_primaries.append(sched[0])
            for k in range(1, len(sched)):
                assert backup_min_ms - 1 <= sched[k] - sched[k - 1] <= backup_max_ms + 1, sched
            for a in s["attempts"]:
                assert a["scheduled_start_ms"] in sched, a
                assert 0 <= a["started_ms"] - a["scheduled_start_ms"] <= grace_ms, a
                assert a["ended_ms"] <= a["scheduled_start_ms"] + attempt_max_ms + 200, a
            # A slot never has two connections alive at once: each attempt starts after the previous one ended.
            for prev, nxt in zip(s["attempts"], s["attempts"][1:]):
                assert_greater_than_or_equal(nxt["started_ms"], prev["ended_ms"])
        assert_equal(len(late_primaries), 2)
        assert_greater_than_or_equal(abs(late_primaries[1] - late_primaries[0]), PRIMARY_SEPARATION_S * 1000 / TIME_DIVISOR - 1)
        # The tool shares nothing with the node: as a bystander it never received the
        # transaction, opened no peer to the node, and changed no bans. (Address-manager
        # background churn is not a tool effect and is not asserted here.)
        assert tx["txid"] not in node.getrawmempool()
        assert_equal(node.getrawmempool(), mempool_before)
        assert_equal(len(node.getpeerinfo()), peers_before)
        assert_equal(node.listbanned(), banned_before)
        self.stop_proxy()

    def test_interrupt(self):
        self.log.info("SIGINT during discovery ends the job promptly with exit status 2 and a report")
        self.start_proxy({"a.seed.": ["8.0.0.1"]}, {"8.0.0.1": (Recipient, True)})
        node = self.nodes[0]
        mempool_before = node.getrawmempool()
        tx = self.wallet.create_self_transfer()
        started = time.monotonic()
        proc = self.start_send(tx["hex"], "-seed=a.seed.")
        self.wait_until(lambda: self.resolve_counts.get("a.seed.", 0) >= 1)  # discovery is under way
        proc.send_signal(signal.SIGINT)
        rc, report = self.finish_send(proc)
        elapsed = time.monotonic() - started
        assert_equal(rc, 2)
        assert_equal(report["summary"]["interrupted"], True)
        assert_equal(report["summary"]["connections"], 0)
        assert_equal(report["summary"]["announcements_written"], 0)
        assert_equal(report["summary"]["slots_completed"], 0)
        assert_greater_than(DISCOVERY_WINDOW_S / TIME_DIVISOR + 10, elapsed)
        assert_equal(self.connects, {})
        assert_equal(node.getrawmempool(), mempool_before)
        self.stop_proxy()

    def test_socks_auth_required(self):
        self.log.info("A proxy offering no authentication: the tool resolves nothing and sends nothing")
        onion = make_onion(9)
        self.start_proxy({"a.seed.": ["9.0.0.1"]}, {onion: (Recipient, True)}, proxy_authenticates=False)
        # discover: the greeting is answered with no-auth, which the tool refuses, so no RESOLVE runs.
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "-seed=a.seed.", "-noprogress", "discover")
        out = json.loads(proc.stdout)
        assert_equal(out["seeds"][0]["queries"], 4)
        assert_equal(out["seeds"][0]["kept"], 0)
        assert_equal(self.resolve_counts, {})  # the proxy never reached the RESOLVE stage
        assert_equal(self.drain_socks_commands(), [])
        # send: no exit or onion connection is made either, and the job ends with nothing announced.
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=a.seed.", f"-fixedseed={onion}:{REGTEST_PORT}", expected_rc=2)
        assert_equal(report["summary"]["announcements_written"], 0)
        for _, a in self.attempts(report):
            assert_equal(a["outcome"], "not_announced")
            assert_equal(a["reason"], "socks connect failed")
        assert_equal(self.connects, {})
        assert_equal(self.drain_socks_commands(), [])
        self.stop_proxy()

    def test_slow_resolve(self):
        self.log.info("A resolver that answers after the query deadline: no candidates, discovery still ends on time")
        query_deadline_s = 15 / TIME_DIVISOR  # disc::QUERY_DEADLINE scaled
        self.start_proxy({"a.seed.": ["9.1.0.1"]}, {}, resolve_delay=query_deadline_s * 2)
        started = time.monotonic()
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "-seed=a.seed.", "-noprogress", "discover")
        elapsed = time.monotonic() - started
        out = json.loads(proc.stdout)
        assert_equal(out["seeds"][0]["queries"], 4)  # all four started at once
        assert_equal(out["seeds"][0]["kept"], 0)      # every answer arrived after the deadline
        # discover returns at the window (18 s scaled), not after the resolver's much longer stall.
        assert_greater_than(query_deadline_s * 2, elapsed)
        assert_equal(self.connects, {})
        self.stop_proxy()

    def test_interrupt_blocked_resolve(self):
        self.log.info("SIGINT while workers are blocked in RESOLVE ends the job promptly")
        self.start_proxy({"a.seed.": ["9.2.0.1"]}, {}, resolve_delay=60)  # never answers within the job
        tx = self.wallet.create_self_transfer()
        started = time.monotonic()
        proc = self.start_send(tx["hex"], "-seed=a.seed.")
        # Wait until a RESOLVE has reached the proxy and is stalling, so a worker is genuinely blocked.
        self.wait_until(lambda: self.resolve_counts.get("a.seed.", 0) >= 1)
        proc.send_signal(signal.SIGINT)
        rc, report = self.finish_send(proc)
        elapsed = time.monotonic() - started
        assert_equal(rc, 2)
        assert_equal(report["summary"]["interrupted"], True)
        assert_equal(report["summary"]["connections"], 0)
        # Far below the full schedule (~50 s scaled): the blocked workers were released at once.
        assert_greater_than(20, elapsed)
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

    def test_discover(self):
        self.log.info("discover resolves through the proxy and opens no connection")
        # Seed a answers IPv4 and IPv6 (repeats are duplicates); seed z's queries all fail.
        self.start_proxy({"a.seed.": ["1.1.1.1", "2606:4700:4700::1111"]}, {"1.1.1.1": (Recipient, True)})
        proc = self.run_tool(f"-timedivisor={TIME_DIVISOR}", "-seed=a.seed.", "-seed=z.seed.", "-noprogress", "discover")
        out = json.loads(proc.stdout)
        seeds = {s["name"]: s for s in out["seeds"]}
        assert_equal(seeds["a.seed."]["queries"], 4)
        assert_equal(seeds["a.seed."]["answers"], 4)
        assert_equal(seeds["a.seed."]["kept"], 2)
        assert_equal(sorted(seeds["a.seed."]["candidates"]), [f"1.1.1.1:{REGTEST_PORT}", f"[2606:4700:4700::1111]:{REGTEST_PORT}"])
        assert_equal(seeds["z.seed."]["queries"], 4)
        assert_equal(seeds["z.seed."]["answers"], 0)
        assert_equal(seeds["z.seed."]["kept"], 0)
        assert_equal(out["duplicates"], 2)
        assert_equal(out["rejected"], 0)
        commands = self.drain_socks_commands()
        assert_equal([c.cmd for c in commands], [Command.RESOLVE] * 8)
        assert_equal(self.connects, {})
        self.stop_proxy()

    def test_stalled_proxy(self):
        self.log.info("A proxy that never answers CONNECT: attempts fail on the SOCKS timeout, later opportunities start on time")
        # Longer than the scaled SOCKS exchange budget ((45 - 10) s / TIME_DIVISOR = 3.5 s), shorter than
        # the 5 s minimum between a slot's opportunities, so a backup would still start on time.
        # Three seeds of three (discovery keeps at most three candidates per seed): with no onions known the
        # onion slots fall back to exit-path peers, so nine candidates make six primaries and three backups.
        self.start_proxy({"s.seed.": ["8.1.0.1", "8.1.0.2", "8.1.0.3"], "t.seed.": ["8.1.1.1", "8.1.1.2", "8.1.1.3"],
                          "u.seed.": ["8.1.2.1", "8.1.2.2", "8.1.2.3"]}, {}, connect_delay=4.0)
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=s.seed.", "-seed=t.seed.", "-seed=u.seed.", expected_rc=2)
        self.log.debug(json.dumps(report, indent=1))
        assert_equal(report["summary"]["interrupted"], False)
        assert_equal(report["summary"]["slots_completed"], SLOTS)
        assert_equal(report["summary"]["announcements_written"], 0)
        # Six primaries and three backups, all stalled and all on time; the rest is empty.
        assert_equal(report["summary"]["connections"], 9)
        socks_budget_ms = (HANDSHAKE_TIMEOUT_S - HANDSHAKE_RESERVE_S) * 1000 / TIME_DIVISOR
        grace_ms = START_GRACE_S * 1000 / TIME_DIVISOR
        for s in report["slots"]:
            assert_equal(s["missed_opportunities"], 0)
            for a in s["attempts"]:
                assert_equal(a["outcome"], "not_announced")
                assert_equal(a["reason"], "socks connect failed")
                assert 0 <= a["started_ms"] - a["scheduled_start_ms"] <= grace_ms, a
                # Gave up at the SOCKS exchange deadline, not at the proxy's pace.
                assert a["ended_ms"] - a["scheduled_start_ms"] <= socks_budget_ms + 200, a
                assert a["ended_ms"] - a["scheduled_start_ms"] >= socks_budget_ms - 200, a
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
            out, _ = proc.communicate(input=tx["hex"], timeout=120)
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
        proc.send_signal(signal.SIGINT)
        rc, report = self.finish_send(proc)
        assert_equal(report["summary"]["interrupted"], True)
        assert_greater_than(SLOTS, report["summary"]["slots_completed"])
        assert_greater_than(report["summary"]["announcements_written"], 0)
        assert_equal(rc, 0)
        self.stop_proxy()


if __name__ == "__main__":
    ToolPrivbcast(__file__).main()
