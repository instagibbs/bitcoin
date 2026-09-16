#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generalized sibling eviction: pin the ancestors, keep the most valuable rest that fits, pay for what goes."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class SiblingEvictionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-limitclustercount=5", "-checkmempool=1"]]

    def check_mempool(self, txs):
        assert_equal(set(self.nodes[0].getrawmempool()), {tx["txid"] for tx in txs})

    def clear_mempool(self):
        self.generate(self.wallet, 1)
        self.check_mempool([])

    def parent(self, outputs=2, **kwargs):
        return self.wallet.send_self_transfer_multi(
            from_node=self.nodes[0], confirmed_only=True, num_outputs=outputs,
            fee_per_output=100, **kwargs,
        )

    def child(self, utxo, fee=100, **kwargs):
        return self.wallet.send_self_transfer(
            from_node=self.nodes[0], utxo_to_spend=utxo, fee=Decimal(fee) / COIN, **kwargs,
        )

    def candidate(self, utxos, fee=1000, **kwargs):
        return self.wallet.create_self_transfer_multi(utxos_to_spend=utxos, fee_per_output=fee, **kwargs)

    def reject_unchanged(self, tx, reason):
        node = self.nodes[0]
        before = node.getrawmempool()
        result = node.testmempoolaccept([tx["hex"]], maxfeerate=0)[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], reason)
        assert_raises_rpc_error(-26, reason, node.sendrawtransaction, tx["hex"], 0)
        assert_equal(node.getrawmempool(), before)

    def test_versions_and_fees(self):
        self.log.info("Versions 1 and 2: evict only the cheapest sibling, and pay exactly for it")
        node = self.nodes[0]
        for version in (1, 2):
            parent = self.parent(outputs=5, version=version)
            # Three siblings worth keeping and one cheap one. The cluster is full at 5.
            children = [self.child(u, 200, version=version, sequence=0xffffffff) for u in parent["new_utxos"][:3]]
            cheap = self.child(parent["new_utxos"][3], 100, version=version, sequence=0xffffffff)
            self.check_mempool([parent, cheap] + children)
            utxo = parent["new_utxos"][4]
            # Must pay the cheap sibling's 100 sat plus incremental relay for its own ~110 vB.
            for fee in (100, 110):
                self.reject_unchanged(self.candidate([utxo], fee, version=version), "insufficient fee (including sibling eviction)")

            # Fee deltas on both the evicted transaction and the replacement are respected.
            node.prioritisetransaction(cheap["txid"], 0, 10)
            replacement = self.candidate([utxo], 111, version=version)
            self.reject_unchanged(replacement, "insufficient fee (including sibling eviction)")
            node.prioritisetransaction(replacement["txid"], 0, 10)
            assert node.testmempoolaccept([replacement["hex"]])[0]["allowed"]
            self.check_mempool([parent, cheap] + children)

            # A script failure after policy checks must roll back all staged removals.
            bad = self.candidate([utxo], 1000, version=version)
            bad["tx"].wit.vtxinwit[0].scriptWitness.stack[0] = b"\x00"
            assert_equal(node.testmempoolaccept([bad["tx"].serialize().hex()])[0]["allowed"], False)
            self.check_mempool([parent, cheap] + children)

            # Multi-transaction testmempoolaccept does not enable sibling eviction.
            grandchild = self.candidate([replacement["new_utxos"][0]])
            result = node.testmempoolaccept([replacement["hex"], grandchild["hex"]])
            assert not any(r.get("allowed", False) for r in result)
            self.check_mempool([parent, cheap] + children)

            # A transaction individually accepted through submitpackage does enable it.
            result = node.submitpackage([parent["hex"], replacement["hex"]])
            assert_equal(result["package_msg"], "success")
            assert_equal(result["replaced-transactions"], [cheap["txid"]])
            self.check_mempool([parent, replacement] + children)
            self.clear_mempool()

    def test_ancestor_descendants(self):
        self.log.info("Keep an ancestor's other branch where it fits; evict the join that does not")
        node = self.nodes[0]
        grandparent = self.parent(outputs=3)
        parent = self.wallet.send_self_transfer_multi(
            from_node=node, utxos_to_spend=[grandparent["new_utxos"][0]], num_outputs=2, fee_per_output=100,
        )
        uncle = self.child(grandparent["new_utxos"][1])
        cousin = self.child(uncle["new_utxo"])
        join = self.candidate([parent["new_utxos"][1], cousin["new_utxo"]], 100)
        self.wallet.sendrawtransaction(from_node=node, tx_hex=join["hex"])
        conflict_input = self.wallet.get_utxo(confirmed_only=True)
        conflict = self.child(conflict_input)
        # Pinned: grandparent, parent, replacement. Budget 2: uncle, then cousin. join is evicted.
        replacement = self.candidate([parent["new_utxos"][0], grandparent["new_utxos"][2], conflict_input])
        self.check_mempool([grandparent, parent, uncle, cousin, join, conflict])
        assert node.testmempoolaccept([replacement["hex"]])[0]["allowed"]
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([grandparent, parent, uncle, cousin, replacement])
        self.clear_mempool()

    def test_cluster_merging(self):
        self.log.info("Merge two clusters, keeping the most valuable children across both")
        node = self.nodes[0]
        parents = [self.parent(outputs=3) for _ in range(2)]
        rich = [self.child(u, 300) for u in parents[0]["new_utxos"][:2]]
        poor = [self.child(u, 100) for u in parents[1]["new_utxos"][:2]]
        unrelated = self.child(self.wallet.get_utxo(confirmed_only=True))
        # Pinned: both parents and the replacement. Budget 2 goes to the two 300 sat children.
        replacement = self.candidate([p["new_utxos"][2] for p in parents])
        self.check_mempool(parents + rich + poor + [unrelated])
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool(parents + rich + [unrelated, replacement])
        self.clear_mempool()

    def test_other_non_ancestors(self):
        self.log.info("A co-parent branch is kept where it fits; its join and child are evicted")
        node = self.nodes[0]
        grandparent = self.parent()
        parent = self.child(grandparent["new_utxos"][0])
        coparent = self.child(self.wallet.get_utxo(confirmed_only=True))
        join = self.candidate([grandparent["new_utxos"][1], coparent["new_utxo"]], 100)
        self.wallet.sendrawtransaction(from_node=node, tx_hex=join["hex"])
        child = self.child(join["new_utxos"][0])
        self.check_mempool([grandparent, parent, coparent, join, child])
        # Pinned: grandparent, parent, replacement. Budget 2: coparent alone fits, [join, child] does not.
        replacement = self.candidate([parent["new_utxo"]])
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([grandparent, parent, coparent, replacement])
        self.clear_mempool()

        self.log.info("Ordinary RBF that fits leaves other branches intact")
        parent = self.parent()
        original = self.child(parent["new_utxos"][0])
        sibling = self.child(parent["new_utxos"][1])
        replacement = self.candidate([parent["new_utxos"][0]])
        self.check_mempool([parent, original, sibling])
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([parent, sibling, replacement])
        self.clear_mempool()

    def test_ancestor_protection(self):
        self.log.info("Ancestors alone exceeding the limit cannot be rescued by eviction")
        chain = self.wallet.send_self_transfer_chain(from_node=self.nodes[0], chain_length=5)
        replacement = self.candidate([chain[-1]["new_utxo"]])
        self.reject_unchanged(replacement, "too-large-cluster")
        self.check_mempool(chain)
        self.clear_mempool()

    def test_size_limit(self):
        self.log.info("RBF may evict a non-conflicting branch to meet the cluster weight limit")
        node = self.nodes[0]
        self.restart_node(0, extra_args=["-limitclustersize=1", "-checkmempool=1"])
        parent = self.parent(outputs=3)
        original = self.child(parent["new_utxos"][0], 200, target_vsize=200)
        sibling = self.child(parent["new_utxos"][1], 500, target_vsize=500)
        replacement = self.candidate([parent["new_utxos"][0]], 2000, target_vsize=800)
        too_big = self.candidate([parent["new_utxos"][0]], 3000, target_vsize=900)
        self.reject_unchanged(too_big, "too-large-cluster")
        self.check_mempool([parent, original, sibling])
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([parent, replacement])
        self.clear_mempool()

        self.log.info("Direct conflicts are removed first; only what still does not fit is evicted")
        parent = self.parent(outputs=3)
        left = self.child(parent["new_utxos"][0], 300, target_vsize=200)
        right = self.child(parent["new_utxos"][1], 200, target_vsize=200)
        conflict_input = self.wallet.get_utxo(confirmed_only=True)
        join = self.candidate([left["new_utxo"], right["new_utxo"], conflict_input], 200, target_vsize=250)
        node.sendrawtransaction(join["hex"])
        # Ordinary RBF removes join but leaves 190 + 200 + 200 + 500 > 1000 vB. Budget after the
        # pinned parent and replacement is 310 vB: left (300 sat) is kept, right is evicted.
        replacement = self.candidate([parent["new_utxos"][2], conflict_input], 2000, target_vsize=500)
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([parent, left, replacement])
        self.clear_mempool()

        self.log.info("Material disconnected by the direct conflict's removal is neither evicted nor charged")
        parent = self.parent(outputs=3)
        other = self.child(self.wallet.get_utxo(confirmed_only=True), 120, target_vsize=120)
        join = self.candidate([parent["new_utxos"][0], other["new_utxo"]], 200, target_vsize=200)
        node.sendrawtransaction(join["hex"])
        sibling = self.child(parent["new_utxos"][1], 120, target_vsize=120)
        self.check_mempool([parent, other, join, sibling])
        # Replacing join disconnects other. 190 + 120 + 800 > 1000, so sibling is evicted; other stays.
        replacement = self.candidate([parent["new_utxos"][0], parent["new_utxos"][2]], 3000, target_vsize=800)
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([parent, other, replacement])
        self.clear_mempool()

    def test_diagram(self):
        self.log.info("Paying absolute fees and relay costs does not bypass feerate-diagram policy")
        node = self.nodes[0]
        self.restart_node(0, extra_args=["-limitclustercount=2", "-checkmempool=1"])
        parent = self.parent()
        sibling = self.child(parent["new_utxos"][0], 1000)
        replacement = self.candidate([parent["new_utxos"][1]], 2000, target_vsize=2000)
        self.reject_unchanged(replacement, "replacement-failed")
        self.check_mempool([parent, sibling])
        self.clear_mempool()

    def test_full_clusters(self):
        self.log.info("Merge two full 64-transaction clusters, keeping 61 children")
        node = self.nodes[0]
        self.restart_node(0, extra_args=["-checkmempool=1"])
        parents = [self.parent(outputs=64) for _ in range(2)]
        children = [self.child(u) for p in parents for u in p["new_utxos"][:63]]
        replacement = self.candidate([p["new_utxos"][63] for p in parents], 20000)
        # Repeated dry runs exercise staging rollback and graph cache reuse.
        for _ in range(5):
            assert node.testmempoolaccept([replacement["hex"]])[0]["allowed"]
            self.check_mempool(parents + children)
        node.sendrawtransaction(replacement["hex"])
        mempool = set(node.getrawmempool())
        assert_equal(len(mempool), 64)
        assert {p["txid"] for p in parents} | {replacement["txid"]} <= mempool
        assert_equal(len([c for c in children if c["txid"] in mempool]), 61)
        self.clear_mempool()

    def test_cluster_work_limit(self):
        self.log.info("The 100-cluster work limit covers parents' and direct conflicts' clusters together")
        node = self.nodes[0]
        self.restart_node(0, extra_args=["-limitclustercount=5", "-checkmempool=1"])
        parent = self.parent(outputs=5)
        siblings = [self.child(u, 200) for u in parent["new_utxos"][:3]]
        cheap = self.child(parent["new_utxos"][3], 100)
        inputs = [self.wallet.get_utxo(confirmed_only=True) for _ in range(100)]
        conflicts = [self.child(u, 11) for u in inputs]
        replacement = self.candidate(inputs + [parent["new_utxos"][4]], 20000)
        self.reject_unchanged(replacement, "too many potential replacements (including sibling eviction)")
        self.check_mempool([parent, cheap] + siblings + conflicts)
        replacement = self.candidate(inputs[:-1] + [parent["new_utxos"][4]], 20000)
        node.sendrawtransaction(replacement["hex"])
        self.check_mempool([parent, conflicts[-1], replacement] + siblings)
        self.clear_mempool()

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 130)
        self.test_versions_and_fees()
        self.test_ancestor_descendants()
        self.test_cluster_merging()
        self.test_other_non_ancestors()
        self.test_ancestor_protection()
        self.test_size_limit()
        self.test_diagram()
        self.test_full_clusters()
        self.test_cluster_work_limit()


if __name__ == '__main__':
    SiblingEvictionTest(__file__).main()
