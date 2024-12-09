#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test cluster mempool accessors and limits"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import (
    MiniWallet,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

from decimal import Decimal

MAX_CLUSTER_COUNT = 64

class MempoolClusterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            '-datacarriersize=100000',  # needed to pad transaction with MiniWallet
        ]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        node = self.nodes[0]
        # Second output of original parent will be used for kindred eviction
        parent_tx = self.wallet.send_self_transfer_multi(from_node=node, num_outputs=2)
        utxo_to_spend = parent_tx["new_utxos"][0]
        utxo_for_kindred_eviction = parent_tx["new_utxos"][1]
        historical_utxos_spent = [parent_tx["new_utxos"][0]]
        ancestors = [parent_tx["txid"]]
        while len(node.getrawmempool()) < MAX_CLUSTER_COUNT:
            next_tx = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=utxo_to_spend)
            # Confirm that each transaction is in the same cluster as the first.
            assert node.getmempoolcluster(next_tx['txid']) == node.getmempoolcluster(parent_tx['txid'])

            # Confirm that the ancestors are what we expect
            mempool_ancestors = node.getmempoolancestors(next_tx['txid'])
            assert sorted(mempool_ancestors) == sorted(ancestors)

            # Confirm that each successive transaction is added as a descendant.
            assert all([ next_tx["txid"] in node.getmempooldescendants(x) for x in ancestors ])

            # Update for next iteration
            ancestors.append(next_tx["txid"])
            utxo_to_spend = next_tx["new_utxo"]
            historical_utxos_spent.append(next_tx["new_utxo"])

        assert node.getmempoolcluster(parent_tx['txid'])['txcount'] == MAX_CLUSTER_COUNT
        feeratediagram = node.getmempoolfeeratediagram()
        last_val = [0, 0]
        for x in feeratediagram:
            assert x['size'] > 0 or x['fee'] == 0
            assert last_val[0]*x['fee'] >= last_val[1]*x['size']
            last_val = [x['size'], x['fee']]

        # Test that adding one more transaction to the cluster will fail.
        bad_tx = self.wallet.create_self_transfer(utxo_to_spend=utxo_to_spend)
        assert_raises_rpc_error(-26, "too-large-cluster", node.sendrawtransaction, bad_tx["hex"])

        # But if transaction has non-ancestors that can be evicted, it will try an RBF
        kindred_tx = self.wallet.create_self_transfer(utxo_to_spend=utxo_for_kindred_eviction, fee_rate=Decimal("0.006"))
        tx_to_evict = node.getrawtransaction(ancestors[-1])
        evicting_child = node.sendrawtransaction(kindred_tx["hex"], 0)
        assert evicting_child in node.getrawmempool()
        assert ancestors[-1] not in node.getrawmempool()
        assert ancestors[-2] in node.getrawmempool()

        # Re-submitting the same transaction will fail RBF checks due to total fee
        assert_raises_rpc_error(-26, "insufficient fee", node.sendrawtransaction, tx_to_evict)

        # But it works if we up the fee sufficiently
        node.prioritisetransaction(ancestors[-1], 0, 10000000)
        node.sendrawtransaction(tx_to_evict)
        assert evicting_child not in node.getrawmempool()
        assert ancestors[-1] in node.getrawmempool()
        node.prioritisetransaction(ancestors[-1], 0, -10000000)

        # If we make an oversized CPFP off original parent, will evict all non-ancestors required
        huge_kindred_tx = self.wallet.create_self_transfer(utxo_to_spend=utxo_for_kindred_eviction, target_vsize=100000, fee_rate=Decimal("0.006"))
        node.sendrawtransaction(huge_kindred_tx["hex"])
        assert huge_kindred_tx["txid"] in node.getrawmempool()
        last_remaining_ancestor = None
        last_remaining_ancestor_txid = None
        for i in range(len(ancestors)):
            if ancestors[i] in node.getrawmempool():
                last_remaining_ancestor = i
                last_remaining_ancestor_txid = ancestors[i]
        assert last_remaining_ancestor < 20

        # Lastly, test having a direct conflict + requirement to kindred evict by
        # RBFing the last ancestor from ancestors in the mempool with a 100kvB txn
        assert last_remaining_ancestor_txid in node.getrawmempool()
        # 0-index count, plus existing oversized child of ultimate parent
        assert_equal(len(node.getrawmempool()), last_remaining_ancestor + 1 + 1)
        huge_direct_and_kindred_tx = self.wallet.create_self_transfer(utxo_to_spend=historical_utxos_spent[last_remaining_ancestor - 1], target_vsize=100000, fee_rate=Decimal("0.012"))
        node.sendrawtransaction(huge_direct_and_kindred_tx["hex"])
        # Direct RBF for one tx, and kindred eviction for the other, cluster is one smaller
        assert huge_kindred_tx["txid"] not in node.getrawmempool()
        assert last_remaining_ancestor_txid not in node.getrawmempool()
        assert huge_direct_and_kindred_tx["txid"] in node.getrawmempool()
        assert_equal(len(node.getrawmempool()), last_remaining_ancestor + 1 + 1 - 1)

        # TODO: verify that the size limits are also enforced.
        # TODO: add tests that exercise rbf, package submission, and package
        # rbf and verify that cluster limits are enforced.

if __name__ == '__main__':
    MempoolClusterTest(__file__).main()
