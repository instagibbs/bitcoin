#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -privatebroadcast: transactions submitted with sendrawtransaction run as bounded
bitcoin-privbcast jobs inside the node.

The node reaches the network only through its Tor SOCKS5 proxy; here that is the framework's
SOCKS5 server, which answers RESOLVE for the test seed name from a fixed script and redirects
CONNECT requests to Python recipients or to a second bitcoind. The wire behaviour itself is
covered by tool_privbcast.py; this test covers the node side: queueing, concurrency, the RPCs,
abort, the report, and that the node's own mempool only learns the transaction from the network.
"""
import base64
from decimal import Decimal
import hashlib
import threading

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_WITNESS_TX,
    msg_getdata,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    start_p2p_listener,
)
from test_framework.socks5 import start_socks5_server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    p2p_port,
)
from test_framework.v2_p2p import EncryptedP2PState
from test_framework.wallet import MiniWallet

TIME_DIVISOR = 10
MAX_CONCURRENT_JOBS = 2  # node::PrivateBroadcastManager::MAX_CONCURRENT_JOBS
MAX_QUEUED_JOBS = 100
MAX_FINISHED_JOBS = 100
NOT_ENABLED = "Private broadcast is not enabled. Ensure you're running Bitcoin Core with -privatebroadcast=1."


def make_onion(seed: int) -> str:
    pubkey = bytes([seed]) * 32
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + checksum + b"\x03").decode().lower() + ".onion"


class Recipient(P2PInterface):
    """An honest recipient: requests the announced transaction the BIP144 way and answers PING."""

    def __init__(self):
        super().__init__()
        self.txs_received = []

    def on_inv(self, message):
        want = msg_getdata()
        for i in message.inv:
            if i.type == MSG_TX:
                want.inv.append(CInv(MSG_WITNESS_TX, i.hash))
        self.send_without_ping(want)

    def on_tx(self, message):
        self.txs_received.append(message.tx)


class P2PPrivateBroadcast(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_nodes(self):
        self.listeners = {}
        self.lock = threading.Lock()
        self.exit_path = [f"11.22.33.{i}" for i in range(1, 9)]  # routable, as discovery requires
        self.onions = [make_onion(i) for i in range(1, 4)]
        # Most exit-path endpoints are the bitcoind recipient, so every job announces to it at least once
        # (discovery keeps a few of the eight answers per job; at most two of them are not node1).
        node_endpoints = set(self.exit_path[:6])

        self.resolve_count = 0
        self.exit_path_active = list(self.exit_path)  # a test section may narrow the answers

        def resolve_factory(name):
            # One answer per query, cycling through the active exit-path endpoints.
            if name != "a.seed.":
                return None
            with self.lock:
                answer = self.exit_path_active[self.resolve_count % len(self.exit_path_active)]
                self.resolve_count += 1
            return answer

        def destinations_factory(requested_to_addr, requested_to_port, proxy_client):
            with self.lock:
                if requested_to_addr in node_endpoints:
                    return {"actual_to_addr": "127.0.0.1", "actual_to_port": p2p_port(1)}
                # A fresh listener per connection: the framework's listeners accept once, and later
                # jobs dial the same endpoints again.
                listener = Recipient()
                listener.peer_connect_helper(dstaddr="0.0.0.0", dstport=0, net=self.chain, timeout_factor=self.options.timeout_factor)
                listener.peer_connect_send_version(services=P2P_SERVICES)
                listener.v2_state = EncryptedP2PState(initiating=False, net=self.chain)
                addr, port = start_p2p_listener(self.network_thread, listener)
                self.listeners.setdefault(requested_to_addr, []).append(listener)
                return {"actual_to_addr": addr, "actual_to_port": port}

        self.socks5_server = start_socks5_server(destinations_factory, resolve_factory, auth=True, unauth=True)
        self.extra_args = [
            [
                "-privatebroadcast",
                f"-onion=127.0.0.1:{self.socks5_server.conf.addr[1]}",
                "-privatebroadcastseed=a.seed.",
                *[f"-privatebroadcastfixedseed={o}:18444" for o in self.onions],
                f"-privatebroadcasttimedivisor={TIME_DIVISOR}",
                "-v2transport=1",
                "-proxyrandomize=0",  # private broadcast authenticates every stream regardless
                "-debug=privatebroadcast",
            ],
            ["-v2transport=1"],
        ]
        super().setup_nodes()

    def jobs(self):
        return {j["id"]: j for j in self.nodes[0].getprivatebroadcastinfo()["jobs"]}

    def jobs_after_submit(self, hex_tx):
        before = set(self.jobs())
        self.nodes[0].sendrawtransaction(hex_tx)
        new = set(self.jobs()) - before
        assert_equal(len(new), 1)
        return new.pop()

    def wait_for_state(self, job_id, state, timeout=120):
        self.wait_until(lambda: self.jobs()[job_id]["state"] == state, timeout=timeout)
        return self.jobs()[job_id]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 260)  # enough mature coins for the queue-full section

        self.log.info("The RPCs are unavailable without -privatebroadcast")
        assert_raises_rpc_error(-32601, NOT_ENABLED, self.nodes[1].getprivatebroadcastinfo)
        assert_raises_rpc_error(-32601, NOT_ENABLED, self.nodes[1].abortprivatebroadcast, 1)

        self.log.info("A submitted transaction becomes a job that announces it over the proxy and never enters the mempool directly")
        tx = self.wallet.create_self_transfer()
        assert_equal(self.nodes[0].sendrawtransaction(tx["hex"]), tx["txid"])
        assert tx["txid"] not in self.nodes[0].getrawmempool()
        jobs = self.jobs()
        assert_equal(list(jobs), [1])
        assert_equal(jobs[1]["txid"], tx["txid"])
        assert jobs[1]["state"] in ("queued", "running")
        job = self.wait_for_state(1, "done")
        assert_equal(job["announced"], True)
        report = job["report"]
        assert_equal(report["txid"], tx["txid"])
        assert_greater_than_or_equal(report["summary"]["announcements_written"], 1)
        assert "time_started" in job and "time_ended" in job
        # The bitcoind recipient took it, and this node only saw it once the network relayed it back.
        self.wait_until(lambda: tx["txid"] in self.nodes[1].getrawmempool())
        self.wait_until(lambda: tx["txid"] in self.nodes[0].getrawmempool())
        self.wait_until(lambda: "seen_in_mempool" in self.jobs()[1])
        served = [a for s in report["slots"] for a in s["attempts"] if a["tx_written_ms"] is not None]
        assert_greater_than_or_equal(len(served), 1)

        self.log.info("Jobs run two at a time; the queue advances in order; queued and running jobs can be aborted")
        txs = [self.wallet.create_self_transfer() for _ in range(MAX_CONCURRENT_JOBS + 1)]
        for t in txs:
            self.nodes[0].sendrawtransaction(t["hex"])
        ids = [2, 3, 4]
        self.wait_until(lambda: [self.jobs()[i]["state"] for i in ids[:MAX_CONCURRENT_JOBS]] == ["running"] * MAX_CONCURRENT_JOBS)
        assert_equal(self.jobs()[4]["state"], "queued")
        # Aborting a running job ends it early with a report of what it did, and lets the queued one start.
        running = self.nodes[0].abortprivatebroadcast(2)
        assert_equal(running["state"], "running")
        job = self.wait_for_state(2, "aborted", timeout=30)
        assert_equal(job["report"]["summary"]["interrupted"], True)
        self.wait_for_state(4, "running", timeout=30)
        # A queued job aborted before it runs ends with no report.
        extra = self.wallet.create_self_transfer()
        self.nodes[0].sendrawtransaction(extra["hex"])
        assert_equal(self.jobs()[5]["state"], "queued")
        aborted = self.nodes[0].abortprivatebroadcast(5)
        assert_equal(aborted["state"], "aborted")
        assert_equal(aborted["txid"], extra["txid"])
        assert "report" not in self.jobs()[5]
        assert_raises_rpc_error(-8, "No queued or running private broadcast job", self.nodes[0].abortprivatebroadcast, 5)
        assert_raises_rpc_error(-8, "No queued or running private broadcast job", self.nodes[0].abortprivatebroadcast, 99)
        # The same transaction may be queued again as a new job.
        assert_equal(self.nodes[0].sendrawtransaction(extra["hex"]), extra["txid"])
        assert_equal(self.jobs()[6]["txid"], extra["txid"])
        for i in (3, 4, 6):
            self.wait_for_state(i, "done")

        self.log.info("Receipt from the network while a job runs is recorded, and does not stop the job")
        seen = self.wallet.create_self_transfer()
        self.nodes[0].sendrawtransaction(seen["hex"])
        job_id = 7
        assert_equal(self.jobs()[job_id]["txid"], seen["txid"])
        self.nodes[1].sendrawtransaction(seen["hex"])  # the network hands it to node0 right away
        self.wait_until(lambda: seen["txid"] in self.nodes[0].getrawmempool())
        self.wait_until(lambda: "seen_in_mempool" in self.jobs()[job_id])
        assert self.jobs()[job_id]["state"] in ("queued", "running")
        job = self.wait_for_state(job_id, "done")
        assert_equal(job["announced"], True)
        assert_equal(job["report"]["summary"]["interrupted"], False)
        assert_greater_than_or_equal(job["report"]["summary"]["announcements_written"], 1)

        self.log.info("submitpackage with a low-fee parent and its child queues one job that serves the parent on request")
        # The recipient asks for a missing parent after its orphan-resolution delays; with the plan scaled by
        # TIME_DIVISOR the parent hold is 3 s, shorter than the extra delay a node applies while it has
        # wtxid-relay peers. Take the ordinary node0-node1 link away for this part so node1 asks promptly.
        # And let node1 be reached through one endpoint only: with several connections from the same job,
        # node1 may ask a connection that has not served the child for the parent, which the protocol
        # does not answer (one parent, one child, on one connection).
        self.disconnect_nodes(0, 1)
        with self.lock:
            self.exit_path_active = [self.exit_path[0]]
        parent = self.wallet.create_self_transfer(fee_rate=Decimal("0"))
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
        res = self.nodes[0].submitpackage([parent["hex"], child["hex"]])
        assert_equal(res["package_msg"], "parent-reconsiderable")
        assert "min relay fee not met" in res["tx-results"][parent["wtxid"]]["error"]
        assert_equal(res["tx-results"][child["wtxid"]]["error"], "package-not-validated")
        job_id = res["private_broadcast_job"]
        assert_equal(self.jobs()[job_id]["parent_txid"], parent["txid"])
        assert parent["txid"] not in self.nodes[0].getrawmempool()
        job = self.wait_for_state(job_id, "done")
        assert_greater_than_or_equal(job["report"]["summary"]["parents_served"], 1)
        self.wait_until(lambda: child["txid"] in self.nodes[1].getrawmempool() and parent["txid"] in self.nodes[1].getrawmempool())
        assert child["txid"] not in self.nodes[0].getrawmempool()
        # node1 does not announce transactions it already had when a peer connects, so node0 is not
        # expected to learn these two; receipt-back was covered above.
        self.connect_nodes(0, 1)
        with self.lock:
            self.exit_path_active = list(self.exit_path)

        self.log.info("Under -privatebroadcast a package is at most one parent and its child, and a valid single transaction also works")
        p1 = self.wallet.create_self_transfer()
        p2 = self.wallet.create_self_transfer()
        c = self.wallet.create_self_transfer_multi(utxos_to_spend=[p1["new_utxo"], p2["new_utxo"]])
        assert_raises_rpc_error(-8, "one parent and its child", self.nodes[0].submitpackage, [p1["hex"], p2["hex"], c["hex"]])
        single = self.wallet.create_self_transfer()
        res = self.nodes[0].submitpackage([single["hex"]])
        assert_equal(res["package_msg"], "success")
        assert "fees" in res["tx-results"][single["wtxid"]]
        assert single["txid"] not in self.nodes[0].getrawmempool()
        self.wait_for_state(res["private_broadcast_job"], "done")

        self.log.info("Disabling networking aborts running and queued jobs for good; re-enabling admits new ones")
        txs = [self.wallet.create_self_transfer() for _ in range(MAX_CONCURRENT_JOBS + 1)]
        ids = [self.jobs_after_submit(t["hex"]) for t in txs]
        self.wait_until(lambda: [self.jobs()[i]["state"] for i in ids[:MAX_CONCURRENT_JOBS]] == ["running"] * MAX_CONCURRENT_JOBS)
        assert_equal(self.jobs()[ids[-1]]["state"], "queued")
        self.nodes[0].setnetworkactive(False)
        assert_equal(self.jobs()[ids[-1]]["state"], "aborted")
        assert_equal(self.jobs()[ids[-1]]["error"], "networking deactivated")
        assert_raises_rpc_error(None, "Private broadcast job not queued", self.nodes[0].sendrawtransaction, self.wallet.create_self_transfer()["hex"])
        self.nodes[0].setnetworkactive(True)
        for i in ids[:MAX_CONCURRENT_JOBS]:
            job = self.wait_for_state(i, "aborted", timeout=30)
            assert_equal(job["error"], "networking deactivated")
            assert_equal(job["report"]["summary"]["interrupted"], True)
        # setnetworkactive dropped node0's peers asynchronously; restore the ordinary link explicitly.
        self.disconnect_nodes(0, 1)
        self.connect_nodes(0, 1)
        revived = self.wallet.create_self_transfer()
        self.wait_for_state(self.jobs_after_submit(revived["hex"]), "done")

        self.log.info("The queue is bounded; finished jobs are retained up to a bound, oldest dropped first")
        queued = []
        while True:
            t = self.wallet.create_self_transfer()
            try:
                queued.append(self.jobs_after_submit(t["hex"]))
            except JSONRPCException as e:
                assert "Private broadcast job not queued" in e.error["message"]
                break
        states = [j["state"] for j in self.jobs().values()]
        assert_equal(states.count("running"), MAX_CONCURRENT_JOBS)
        assert_equal(states.count("queued"), MAX_QUEUED_JOBS)
        for i in queued:
            if self.jobs()[i]["state"] == "queued":
                self.nodes[0].abortprivatebroadcast(i)
        jobs = self.jobs()
        assert 1 not in jobs  # the first job's report has been trimmed
        assert_greater_than_or_equal(MAX_FINISHED_JOBS + MAX_CONCURRENT_JOBS, len(jobs))
        for i in queued:
            if jobs[i]["state"] == "running":
                self.wait_for_state(i, "done")

        self.log.info("Every proxy stream authenticated with its own credentials, with -proxyrandomize=0")
        creds = set()
        streams = 0
        while not self.socks5_server.queue.empty():
            item = self.socks5_server.queue.get()
            if isinstance(item, Exception):
                raise item
            assert item.username is not None
            creds.add((item.username, item.password))
            streams += 1
        assert_greater_than_or_equal(streams, 20)
        assert_equal(len(creds), streams)

        self.log.info("The node shuts down cleanly with a job running")
        last = self.wallet.create_self_transfer()
        self.wait_for_state(self.jobs_after_submit(last["hex"]), "running")
        # The framework stops both nodes now; a hang or crash here fails the test.
        self.socks5_server.stop()


if __name__ == '__main__':
    P2PPrivateBroadcast(__file__).main()
