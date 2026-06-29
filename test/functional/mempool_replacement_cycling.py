#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reproduce a mempool replacement-cycling attack.

This is the reproduction harness for the anti-cycling work: it documents the
*current* (unmitigated) behaviour, where an attacker evicts a near-top victim
transaction and then withdraws the replacement, leaving the victim permanently
gone from the mempool without ever being mined.

One cycle, mirroring the existing "peekaboo" pattern in p2p_orphan_handling.py:

    coin_O    confirmed UTXO that the victim spends (the protected input)
    coin_ATK  the attacker's confirmed UTXO

    H   = spend {coin_O}            low fee   -> broadcast, sits in mempool
    B2  = spend {coin_O, coin_ATK}  higher    -> replaces H (conflict on coin_O)
    B3  = spend {coin_ATK}          higher    -> replaces B2 (conflict on coin_ATK),
                                                 does NOT spend coin_O

After B3: B2 is gone, coin_O is unspent again, and H is gone -- the attacker
paid only for B3 and cycled H out for free.

Note: on an otherwise-empty regtest mempool the "next-block line" is trivial
(everything is in the next block), so this harness exercises cycle *mechanics*
only. The chunk-feerate policy ("park only near-top evictions") gets its own
test once a real next-block margin is set up.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class MempoolReplacementCyclingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = None

    def assert_spent_by(self, outpoint, expected_txid):
        """Assert outpoint is spent in the mempool by expected_txid (None = unspent)."""
        [result] = self.nodes[0].gettxspendingprevout([{"txid": outpoint["txid"], "vout": outpoint["vout"]}])
        if expected_txid is None:
            assert "spendingtxid" not in result, f"expected {outpoint['txid']}:{outpoint['vout']} unspent, got {result}"
        else:
            assert_equal(result.get("spendingtxid"), expected_txid)

    def test_single_cycle(self):
        node = self.nodes[0]
        wallet = self.wallet
        mempool = lambda: node.getrawmempool()

        self.log.info("One replacement cycle evicts the victim for free")

        coin_O = wallet.get_utxo(confirmed_only=True)
        coin_ATK = wallet.get_utxo(confirmed_only=True)

        # Victim H spends the protected input coin_O.
        H = wallet.create_self_transfer_multi(utxos_to_spend=[coin_O], fee_per_output=5_000)
        node.sendrawtransaction(H["hex"])
        assert H["txid"] in mempool()
        self.assert_spent_by(coin_O, H["txid"])

        # Attacker B2 grabs coin_O (+ its own coin) at a higher feerate -> evicts H.
        B2 = wallet.create_self_transfer_multi(utxos_to_spend=[coin_O, coin_ATK], fee_per_output=30_000)
        node.sendrawtransaction(B2["hex"])
        assert H["txid"] not in mempool()
        assert B2["txid"] in mempool()
        self.assert_spent_by(coin_O, B2["txid"])

        # Attacker B3 replaces B2 on coin_ATK but does NOT spend coin_O -> frees coin_O.
        B3 = wallet.create_self_transfer_multi(utxos_to_spend=[coin_ATK], fee_per_output=60_000)
        node.sendrawtransaction(B3["hex"])
        assert B2["txid"] not in mempool()
        assert B3["txid"] in mempool()

        # The cycle is complete: coin_O is unspent again, yet the victim is gone
        # and was never mined. This is the vulnerability the buffer must fix.
        self.assert_spent_by(coin_O, None)
        assert H["txid"] not in mempool()

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 110)
        self.test_single_cycle()


if __name__ == '__main__':
    MempoolReplacementCyclingTest(__file__).main()
