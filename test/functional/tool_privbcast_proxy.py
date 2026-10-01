#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-privbcast against misbehaving proxies: one that stalls every CONNECT, one that
offers no authentication, one that is not Tor, a slow resolver, and interruption while blocked
in RESOLVE.

The harness and the shared scripted recipients are in test_framework/privbcast.py.
"""


import json
import time

from test_framework.socks5 import (
    Command,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


from test_framework.privbcast import (
    TIME_DIVISOR,
    REGTEST_PORT,
    SLOTS,
    DISCOVERY_WINDOW_S,
    START_GRACE_S,
    HANDSHAKE_TIMEOUT_S,
    drain_socks_commands,
    make_onion,
    Recipient,
    PrivbcastToolTest,
)


class ToolPrivbcastProxy(PrivbcastToolTest):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        self.setup_wallet()
        self.test_stalled_proxy()
        self.test_socks_auth_required()
        self.test_not_tor_proxy()
        self.test_slow_resolve()
        self.test_interrupt_blocked_resolve()

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
        assert_equal(report["summary"]["interrupted"], False)
        assert_equal(report["summary"]["slots_completed"], SLOTS)
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
        # The job ends by its scheduled end: nothing stretched.
        assert report["summary"]["duration_ms"] <= max(s["scheduled_end_ms"] for s in report["slots"]) + 1500
        self.stop_proxy()

    def test_socks_auth_required(self):
        self.log.info("A proxy offering no authentication: the tool resolves nothing and sends nothing")
        onion = make_onion(9)
        self.start_proxy({"a.seed.": ["9.0.0.1"]}, {onion: (Recipient, True)}, proxy_authenticates=False)
        # The tool offers only username and password, which this proxy lacks, so the proxy answers
        # "no acceptable method": no RESOLVE, no CONNECT.
        tx = self.wallet.create_self_transfer()
        # Nothing here depends on time, so a faster clock.
        report, _ = self.run_send(tx["hex"], "-seed=a.seed.", f"-fixedseed={onion}:{REGTEST_PORT}", expected_rc=2, time_divisor=50)
        for _, a in self.attempts(report):
            assert_equal(a["outcome"], "not_announced")
        assert_equal(drain_socks_commands(self.socks5_server), [])
        self.stop_proxy()

    def test_not_tor_proxy(self):
        self.log.info("An authenticating proxy that is not Tor: no exit-path candidates, no onion reached, nothing sent")
        onion = make_onion(10)
        self.start_proxy({"a.seed.": ["9.0.1.1"]}, {onion: (Recipient, True)}, tor=False)
        # Every RESOLVE is refused as an unsupported command, so the only CONNECTs are to the onion, and
        # each fails at the proxy; nothing is announced.
        tx = self.wallet.create_self_transfer()
        report, _ = self.run_send(tx["hex"], "-seed=a.seed.", f"-fixedseed={onion}:{REGTEST_PORT}", expected_rc=2)
        assert_equal(report["discovery"]["exit_path_candidates"], 0)
        for _, a in self.attempts(report):
            assert_equal(a["outcome"], "not_announced")
        commands = drain_socks_commands(self.socks5_server)
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
        # Wait until the proxy holds a RESOLVE reply, so a query is blocked.
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


if __name__ == '__main__':
    ToolPrivbcastProxy(__file__).main()
