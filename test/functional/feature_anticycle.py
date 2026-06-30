#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Adversarial scenarios for the -anticycle park buffer.

The bare reproduction (mempool_replacement_cycling.py) shows that, by default, an attacker can
RBF-evict a near-top victim and then withdraw, leaving the victim gone for free. These scenarios
run on a node started with -anticycle=1 and exercise both the mitigation (victims get reinstated
when their input frees up) and its restraint (it does not fight legitimate replacements, and it
does not resurrect victims whose input was spent on-chain).

Fee convention (sats per output; MiniWallet RBF-signals by default):
    victim         5_000
    attacker grab 30_000   (spends victim's input + the attacker's own coin)
    attacker free 60_000   (spends only the attacker's coin, freeing the victim's input)
so each replacement strictly raises both absolute fee and feerate.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mempool_util import fill_mempool
from test_framework.util import assert_equal

from test_framework.wallet import MiniWallet

VICTIM_FEE = 5_000
GRAB_FEE = 30_000
FREE_FEE = 60_000


class AntiCycleScenariosTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = None
        # -maxmempool=5 for fill_mempool; -debug=anticycle to surface the lifecycle log lines.
        self.extra_args = [["-anticycle=1", "-maxmempool=5", "-debug=anticycle"]]

    # --- helpers -----------------------------------------------------------------------------

    def send(self, utxos, fee_per_output):
        """Build and broadcast a tx spending `utxos`, returning the tx dict."""
        tx = self.wallet.create_self_transfer_multi(utxos_to_spend=utxos, fee_per_output=fee_per_output)
        self.nodes[0].sendrawtransaction(tx["hex"])
        return tx

    def in_mempool(self, tx):
        return tx["txid"] in self.nodes[0].getrawmempool()

    def fresh_slate(self):
        """Confirm everything in the mempool and the buffer's parked entries for a clean start."""
        self.generate(self.wallet, 1)
        assert_equal(self.nodes[0].getrawmempool(), [])

    def coin(self):
        return self.wallet.get_utxo(confirmed_only=True)

    # --- scenarios ---------------------------------------------------------------------------

    def test_single_tx_cycle(self):
        self.log.info("1) single-tx cycle: victim is reinstated when its input frees")
        self.fresh_slate()
        o, atk = self.coin(), self.coin()
        victim = self.send([o], VICTIM_FEE)
        assert self.in_mempool(victim)
        with self.nodes[0].assert_debug_log(expected_msgs=["parked", "reinstated"]):
            self.send([o, atk], GRAB_FEE)            # evict the victim
            assert not self.in_mempool(victim)
            self.send([atk], FREE_FEE)               # withdraw, freeing the victim's input
            self.wait_until(lambda: self.in_mempool(victim))
        # The stats RPC reflects the park + reinstate that just happened.
        info = self.nodes[0].getanticycleinfo()
        assert info["enabled"]
        assert info["total_parked"] >= 1 and info["reinstated"] >= 1

    def test_1p1c_package_cycle(self):
        self.log.info("2) 1P1C cycle: the CPFP child is reinstated, the parent is untouched")
        self.fresh_slate()
        o, atk = self.coin(), self.coin()
        parent = self.send([o], VICTIM_FEE)
        child = self.send([parent["new_utxos"][0]], VICTIM_FEE)   # spends the parent's output
        assert self.in_mempool(parent) and self.in_mempool(child)
        # Attacker grabs the parent's output (the "anchor") -> evicts the child; parent survives.
        self.send([parent["new_utxos"][0], atk], GRAB_FEE)
        assert self.in_mempool(parent) and not self.in_mempool(child)
        self.send([atk], FREE_FEE)               # frees the parent's output
        self.wait_until(lambda: self.in_mempool(child))
        assert self.in_mempool(parent)

    def test_sustained_cycling(self):
        self.log.info("3) sustained cycling: the victim survives every round; the attacker pays each time")
        self.fresh_slate()
        o = self.coin()
        victim = self.send([o], VICTIM_FEE)
        assert self.in_mempool(victim)
        rounds = 3
        for i in range(rounds):
            atk = self.coin()                    # a fresh attacker coin per round
            self.send([o, atk], GRAB_FEE)        # evict
            assert not self.in_mempool(victim)
            self.send([atk], FREE_FEE)           # withdraw
            self.wait_until(lambda: self.in_mempool(victim))   # reinstated again
        self.log.info(f"   victim survived {rounds} cycling rounds")

    def test_multiple_victims(self):
        self.log.info("4) multiple independent victims cycled at once: all reinstated")
        self.fresh_slate()
        o1, o2, a1, a2 = self.coin(), self.coin(), self.coin(), self.coin()
        v1 = self.send([o1], VICTIM_FEE)
        v2 = self.send([o2], VICTIM_FEE)
        self.send([o1, a1], GRAB_FEE)
        self.send([o2, a2], GRAB_FEE)
        assert not self.in_mempool(v1) and not self.in_mempool(v2)
        self.send([a1], FREE_FEE)
        self.send([a2], FREE_FEE)
        self.wait_until(lambda: self.in_mempool(v1) and self.in_mempool(v2))

    def test_package_evicted_together(self):
        self.log.info("7) parent+child evicted by one replacement: reinstated together as a package")
        self.fresh_slate()
        o, atk = self.coin(), self.coin()
        parent = self.send([o], VICTIM_FEE)
        child = self.send([parent["new_utxos"][0]], VICTIM_FEE)   # spends the parent's output
        assert self.in_mempool(parent) and self.in_mempool(child)
        # A single replacement spends the parent's *input* -> evicts the parent and, as its
        # descendant, the child too. The whole cluster must be parked as one package.
        self.send([o, atk], GRAB_FEE)
        assert not self.in_mempool(parent) and not self.in_mempool(child)
        self.send([atk], FREE_FEE)               # frees the parent's input
        # Both reinstated together (re-added as a package).
        self.wait_until(lambda: self.in_mempool(parent) and self.in_mempool(child))

    def test_outpoint_spent_onchain_no_reinstate(self):
        self.log.info("5) attacker's replacement confirms: victim is gone for good, not reinstated")
        self.fresh_slate()
        node = self.nodes[0]
        o, atk = self.coin(), self.coin()
        victim = self.send([o], VICTIM_FEE)
        grab = self.send([o, atk], GRAB_FEE)     # evict (victim parked)
        assert not self.in_mempool(victim)
        # The attacker lets the replacement confirm -- i.e. pays for it. The victim's input is
        # now spent on-chain, so it can never be reinstated; the buffer must drop it.
        self.generate(self.wallet, 1)
        assert not self.in_mempool(grab)         # confirmed
        self.generate(self.wallet, 1)            # a further block: still no resurrection
        assert not self.in_mempool(victim)

    def test_honest_fee_bump_not_fought(self):
        self.log.info("6) honest fee-bump: the owner's replacement wins; the old tx is not resurrected")
        self.fresh_slate()
        node = self.nodes[0]
        o = self.coin()
        v = self.send([o], VICTIM_FEE)
        bumped = self.send([o], FREE_FEE)        # the owner's own RBF replacement on the same input
        assert not self.in_mempool(v)            # replaced
        assert self.in_mempool(bumped)
        # The buffer saw v evicted and parked it, but must NOT resurrect it over the owner's
        # replacement while that replacement legitimately holds the input.
        self.send([self.coin()], VICTIM_FEE)     # unrelated tx -> drives the validation queue
        self.sync_all()
        assert not self.in_mempool(v)
        assert self.in_mempool(bumped)

    def test_b_to_a_clear_under_pressure(self):
        self.log.info("8) B->A clear under pressure: a parked victim is dropped when its outpoint is legitimately retaken")
        self.fresh_slate()
        node = self.nodes[0]
        # Congest the mempool so there is a real next-block line above minrelay; one block connect
        # then re-refreshes the coordinator's cached line (the mempool stays > 1 block).
        fill_mempool(self, node)
        self.generate(self.wallet, 1)
        o, p, atk = self.coin(), self.coin(), self.coin()
        # Fees well above the ~150 sat/vB fill line, but under sendrawtransaction's relay fee cap.
        # Near-top victim V spends o and p; cycled out by the attacker, it is parked (keyed by both).
        victim = self.send([o, p], 300_000)
        assert self.in_mempool(victim)
        self.send([o, atk], 600_000)             # attacker grabs o -> evicts and parks V
        assert not self.in_mempool(victim)
        # A near-top tx legitimately (re-)takes V's other input p -- a B->A on p -- which clears the
        # stale parked victim, so it is not resurrected when o later frees.
        self.send([p], 300_000)
        self.send([atk], 900_000)                # attacker withdraws, freeing o
        self.sync_all()
        assert not self.in_mempool(victim)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 150)
        self.test_single_tx_cycle()
        self.test_1p1c_package_cycle()
        self.test_sustained_cycling()
        self.test_multiple_victims()
        self.test_package_evicted_together()
        self.test_outpoint_spent_onchain_no_reinstate()
        self.test_honest_fee_bump_not_fought()
        self.test_b_to_a_clear_under_pressure()
        self.log.info("All anti-cycling scenarios passed")


if __name__ == '__main__':
    AntiCycleScenariosTest(__file__).main()
