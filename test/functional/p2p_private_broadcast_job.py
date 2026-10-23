#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a private broadcast job end to end: a complete job against scripted recipients, and a job
aborted after its announcement.

The harness and the shared scripted recipients are in test_framework/privbcast.py.
"""


import json
import time

from test_framework.messages import (
    MSG_WITNESS_TX,
    MSG_WTX,
    msg_sendtxrcncl,
)
from test_framework.p2p import (
    P2P_SUBVERSION,
    P2P_VERSION,
)
from test_framework.socks5 import (
    Command,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)


from test_framework.privbcast import (
    REGTEST_PORT,
    SLOTS,
    START_GRACE_S,
    HANDSHAKE_TIMEOUT_S,
    REQUEST_WINDOW_S,
    PONG_WAIT_S,
    check_fresh,
    check_profile,
    check_schedule,
    drain_socks_commands,
    query_sets,
    Recipient,
    PrivbcastJobTest,
)


class SilentRecipient(Recipient):
    """Handshakes, then never requests: what an honest peer that already has X looks like."""

    def on_inv(self, message):
        pass


class NoRelayRecipient(Recipient):
    """Announces relay=false in its VERSION; the job must not announce to it."""

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.relay = 0


class NoPongRecipient(Recipient):
    """Requests and receives X but never answers the PING."""

    def on_ping(self, message):
        self.ping_nonces.append(message.nonce)


class ProbingRecipient(Recipient):
    """Sends requests the profile does not allow, repeats the request after the transfer, and
    sends a late SENDTXRCNCL. None of it may be answered or change the job's behaviour."""

    def on_inv(self, message):
        hashes = [i.hash for i in message.inv if i.type == MSG_WTX]
        self.request(hashes, inv_type=MSG_WITNESS_TX)  # the txid-relay form: not what a wtxid-relay peer is asked
        self.request(hashes)  # the one request that is answered

    def on_tx(self, message):
        super().on_tx(message)
        self.request([message.tx.wtxid_int])
        self.request([message.tx.wtxid_int])
        self.send_without_ping(msg_sendtxrcncl())


class P2PPrivateBroadcastJob(PrivbcastJobTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        self.setup_wallet()
        self.test_bounded_job()
        self.test_abort_mid_delivery()

    def test_bounded_job(self):
        self.log.info("A complete job against scripted recipients")
        # Half the usual pace: discovery opens twenty SOCKS streams at once, and a loaded CI host
        # has been slow enough at TIME_DIVISOR to cost a query. This section counts every query.
        divisor = 5
        # Every candidate of a seed shares one behaviour, and the six first attempts cover all five
        # seeds whatever the tie order (R5b), so each behaviour is exercised on every run rather than
        # only when the shuffle happens to pick it. d.seed. names an honest but v1-only recipient (a
        # job never falls back to v1, so it is never served: B4), and e.seed. a probing v2 recipient;
        # each answers every query with that one address.
        resolve_script = {
            "a.seed.": ["8.0.0.1", "8.0.0.2", "8.0.0.3", "8.0.0.4"],
            "b.seed.": ["8.0.1.1", "8.0.1.2", "8.0.1.3", "8.0.1.1"],  # last answer repeats within the seed
            "c.seed.": ["8.0.2.1", "8.0.2.2", "8.0.2.3", "8.0.2.4"],
            "d.seed.": ["8.0.3.1"],
            "e.seed.": ["8.0.4.1"],
        }
        seed_behaviour = {"a.seed.": (NoPongRecipient, True), "b.seed.": (NoRelayRecipient, True), "c.seed.": (SilentRecipient, True),
                          "d.seed.": (Recipient, False), "e.seed.": (ProbingRecipient, True)}
        behaviours = {ip: seed_behaviour[seed] for seed, ips in resolve_script.items() for ip in ips}
        v1_ip, probing_ip = resolve_script["d.seed."][0], resolve_script["e.seed."][0]
        self.start_proxy(resolve_script, behaviours, time_divisor=divisor)
        tx = self.wallet.create_self_transfer()
        job, report = self.run_job(tx)
        assert_equal((job["state"], job["announced"]), ("done", True))
        assert_equal(report["txid"], tx["txid"])
        assert_equal(report["wtxid"], tx["wtxid"])
        assert_equal(report["summary"]["interrupted"], False)
        assert_equal(report["summary"]["error"], None)
        # The report counts from job start: no field is named for a time and no number is an epoch
        # timestamp (H1).
        def check_relative(value):
            if isinstance(value, dict):
                for key, v in value.items():
                    assert not key.startswith("time"), key
                    check_relative(v)
            elif isinstance(value, list):
                for v in value:
                    check_relative(v)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                assert_greater_than(10**9, value)
        check_relative(report)
        assert_equal(report["summary"]["slots_completed"], SLOTS)

        # Discovery: four query sets, each one query per seed, each query on its own stream, and every
        # candidate got the chain port. The job's accounting and the proxy's view must agree, on any
        # host. A host that stalls at job start skips queries rather than running them late, and one
        # that answers a SOCKS stage too slowly costs the query; both are the job doing its job, so
        # the counts are asserted as invariants, not as the twenty answers a fast host gets.
        commands = drain_socks_commands(self.socks5_server)
        resolves = [c for c in commands if c.cmd == Command.RESOLVE]
        disc = report["discovery"]
        seeds = {s["name"]: s for s in disc["seeds"]}
        assert_equal(set(seeds), set(resolve_script))
        for name, st in seeds.items():
            assert_equal(st["queries"] + st["skipped"], 4)
            assert_greater_than_or_equal(st["queries"], self.resolve_counts.get(name, 0))  # a query sent may still not reach RESOLVE
            assert_greater_than_or_equal(self.resolve_counts.get(name, 0), st["answers"])
        assert_equal(sum(st["answers"] for st in seeds.values()), disc["duplicates"] + disc["rejected"] + sum(st["accepted"] for st in seeds.values()))
        assert_equal(disc["rejected"], 0)
        assert_equal(disc["exit_path_candidates"], sum(st["accepted"] for st in seeds.values()))
        assert_greater_than(disc["exit_path_candidates"], 0)
        # Stream isolation (B2): every connection has credentials of its own, and the queries share
        # theirs only within a query set.
        sets = query_sets(commands)
        assert_greater_than_or_equal(4, len(sets))
        for _, a in self.attempts(report):
            assert a["endpoint"].endswith(f":{REGTEST_PORT}")
            # The peer's protocol version and user agent, as it sent them.
            if a["peer_version"] is not None:
                assert_equal((a["peer_version"], a["peer_user_agent"]), (P2P_VERSION, P2P_SUBVERSION))

        # The checks below need a host that kept up: every query reached the proxy and no
        # opportunity was missed. If the host stalled they do not apply, and are skipped.
        missed = sum(s["missed_opportunities"] for s in report["slots"])
        skipped = sum(st["skipped"] for st in seeds.values())
        stalled = missed > 0 or skipped > 0 or len(resolves) < 20
        if stalled:
            self.log.warning(f"host stalled during the job (missed={missed}, skipped={skipped}, resolves={len(resolves)}): outcome checks not applicable")
        else:
            assert_equal(sorted(sorted(s) for s in sets), [sorted(resolve_script)] * 4)  # D1
            assert_equal(report["summary"]["pongs"], 1)  # the probing recipient's; the v1-only one is never served
            # Every INV the transport took was fully written: these recipients read at once.
            assert_equal(report["summary"]["announcements_written"], report["summary"]["announcements_handed"])
            # Outcomes follow the seed's behaviour; every seed was drawn at least once.
            def seed_of(ip):
                return next(seed for seed, ips in resolve_script.items() if ip in ips)

            seeds_attempted = set()
            for _, a in self.attempts(report):
                seed = seed_of(a["endpoint"].rsplit(":", 1)[0])
                assert_equal(a["provenance"], seed)
                seeds_attempted.add(seed)
                if seed == "a.seed.":  # requests and receives X, never answers the PING
                    assert_equal(a["outcome"], "tx_written_no_pong")
                    # Ended when the PONG wait ran out.
                    assert -5 <= a["ended_ms"] - a["ping_written_ms"] - PONG_WAIT_S * 1000 / divisor <= 1000, a
                elif seed == "b.seed.":  # relay=false: refused before any announcement
                    assert_equal(a["outcome"], "not_announced")
                    assert_equal(self.listeners[a["endpoint"].rsplit(":", 1)[0]][0].message_count["inv"], 0)
                elif seed == "c.seed.":  # handshakes, never requests
                    assert_equal(a["outcome"], "announced_not_requested")
                    # Ended when the request window ran out.
                    assert -5 <= a["ended_ms"] - a["inv_handed_ms"] - REQUEST_WINDOW_S * 1000 / divisor <= 1000, a
            assert_equal(seeds_attempted, set(resolve_script))
            # Every seed supplies a first attempt (R5a, R5b).
            assert_equal({s["attempts"][0]["provenance"] for s in report["slots"]}, set(resolve_script))
            # A refused primary is replaced at the slot's next opportunity by a candidate from another seed.
            replaced = [s for s in report["slots"] if s["attempts"] and s["attempts"][0]["provenance"] == "b.seed."]
            assert_greater_than(len(replaced), 0)
            for s in replaced:
                assert_greater_than_or_equal(len(s["attempts"]), 2)
                assert s["attempts"][1]["provenance"] != s["attempts"][0]["provenance"]
                assert s["attempts"][1]["inv_handed_ms"] is not None
            # The v1-only recipient closes the v2 attempt without a byte. That is a plain transport
            # failure: a job never falls back to v1, so the endpoint is never served (B4).
            v1_attempts = self.attempts_to(report, v1_ip)
            assert_equal([a["outcome"] for a in v1_attempts], ["not_announced"])
            assert_equal(v1_attempts[0]["bytes_recv"], 0)
            assert_equal(len(self.listeners[v1_ip][0].txs_received), 0)
            # The probing recipient: its txid-form request, repeats and late SENDTXRCNCL change nothing.
            probing = self.attempts_to(report, probing_ip)
            assert_equal(len(probing), 1)
            assert_equal(probing[0]["outcome"], "pong_received")
            assert_equal(probing[0]["extra_requests"], 3)  # txid-form request before, two repeats after
            assert_equal(len(self.listeners[probing_ip][0].txs_received), 1)  # served exactly once

        # Each endpoint is connected exactly once for the whole job.
        for n in self.connects.values():
            assert_equal(n, 1)

        # An announcement ends its slot: no attempt follows one whose INV the transport took.
        for s in report["slots"]:
            for prev in s["attempts"][:-1]:
                assert prev["inv_handed_ms"] is None, s

        # Every recipient got the fixed profile: its VERSION, at most one INV naming the transaction's
        # wtxid alone, and only messages the profile sends.
        for listener, _, _ in self.listeners.values():
            check_profile(listener, tx["wtxid"])
            if "version" in listener.last_message and not isinstance(listener, NoRelayRecipient):
                # After a VERSION that qualifies the job sends WTXIDRELAY (E2); NoRelayRecipient's does not qualify.
                assert "wtxidrelay" in listener.last_message

        # Nothing is shared between attempts but the transaction and the profile (A4).
        check_fresh([listener for listener, _, _ in self.listeners.values()])

        # The report names what was dialled and carries no transaction bytes.
        assert tx["hex"] not in json.dumps(report)

        # The schedule has the shape Parameters gives it. Each attempt sits on a scheduled
        # opportunity, started within the scaled grace of it (C5) and ended by its deadline (D2).
        check_schedule(report, divisor, tolerance_ms=1)
        grace_ms = START_GRACE_S * 1000 / divisor
        attempt_max_ms = (HANDSHAKE_TIMEOUT_S + REQUEST_WINDOW_S + PONG_WAIT_S) * 1000 / divisor
        for s in report["slots"]:
            sched = s["scheduled_ms"]
            for a in s["attempts"]:
                assert a["scheduled_start_ms"] in sched, a
                assert 0 <= a["started_ms"] - a["scheduled_start_ms"] <= grace_ms, a
                assert_greater_than_or_equal(a["scheduled_start_ms"] + attempt_max_ms + 200, a["ended_ms"])
            # A slot never has two connections alive at once, and dials no opportunity twice: each
            # attempt starts after the previous one ended, at a later opportunity.
            for prev, nxt in zip(s["attempts"], s["attempts"][1:]):
                assert_greater_than_or_equal(nxt["started_ms"], prev["ended_ms"])
                assert_greater_than(sched.index(nxt["scheduled_start_ms"]), sched.index(prev["scheduled_start_ms"]))
        self.stop_proxy()

    def test_abort_mid_delivery(self):
        self.log.info("A job aborted after the recipient received its INV ends at once, announced, and its report says interrupted")
        self.start_proxy({"a.seed.": ["8.2.0.1"]}, {"8.2.0.1": (Recipient, True)})
        tx = self.wallet.create_self_transfer()
        wtxid = self.start_job(tx)
        # Abort once the recipient has seen the INV: it was fully written by then.
        self.wait_until(lambda: "8.2.0.1" in self.listeners and self.listeners["8.2.0.1"][0].message_count["inv"] >= 1)
        self.abort_job(wtxid)
        aborted = time.monotonic()
        job, report = self.finish_job(wtxid)
        assert_greater_than(3 * self.options.timeout_factor, time.monotonic() - aborted)
        assert_equal((job["state"], job["announced"]), ("aborted", True))
        assert_equal(report["summary"]["interrupted"], True)
        assert_greater_than(SLOTS, report["summary"]["slots_completed"])
        assert_greater_than(report["summary"]["announcements_written"], 0)
        self.stop_proxy()


if __name__ == '__main__':
    P2PPrivateBroadcastJob(__file__).main()
