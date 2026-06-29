#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the -anticycle park buffer reinstates a replacement-cycled victim.

Runs one replacement cycle (see mempool_replacement_cycling.py for the bare attack) on a node
started with -anticycle=1, and asserts the evicted victim is automatically reinstated once its
input frees up -- the mitigation the bare reproduction shows is absent by default.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet


class AntiCycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = None
        self.extra_args = [["-anticycle=1"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 110)
        mempool = lambda: node.getrawmempool()

        coin_O = wallet.get_utxo(confirmed_only=True)    # the protected input
        coin_ATK = wallet.get_utxo(confirmed_only=True)  # the attacker's cycling input

        # Victim H spends the protected input at a next-block feerate.
        H = wallet.create_self_transfer_multi(utxos_to_spend=[coin_O], fee_per_output=5_000)
        node.sendrawtransaction(H["hex"])
        assert H["txid"] in mempool()

        # Attacker B2 grabs coin_O (+ its own coin) at a higher feerate -> evicts H.
        B2 = wallet.create_self_transfer_multi(utxos_to_spend=[coin_O, coin_ATK], fee_per_output=30_000)
        node.sendrawtransaction(B2["hex"])
        assert H["txid"] not in mempool()

        # Attacker B3 replaces B2 on coin_ATK but does NOT spend coin_O -> frees coin_O.
        B3 = wallet.create_self_transfer_multi(utxos_to_spend=[coin_ATK], fee_per_output=60_000)
        node.sendrawtransaction(B3["hex"])

        # The park buffer reinstates the victim once coin_O is unspent again. (Reinstatement
        # happens on the validation queue, so wait for it.)
        self.wait_until(lambda: H["txid"] in node.getrawmempool())
        self.log.info("Victim reinstated by the -anticycle park buffer")


if __name__ == '__main__':
    AntiCycleTest(__file__).main()
