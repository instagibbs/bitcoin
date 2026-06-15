#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that orphans are reconsidered when their missing ancestor is confirmed
in a block (not just when it enters the mempool via relay).

Mempool acceptance of a parent re-arms reconsideration of its orphan children
(AddChildrenToWorkSet). A parent that instead reaches the chain via a mined block
must do the same, otherwise an orphan whose low-fee ancestor was confirmed (e.g. a
miner picking up a prefix of a long, similar-feerate chain) is never reconsidered
and the mempool permanently diverges.

Scenario:

    R (root)        low feerate, below this node's mempool min fee
      `-> M (middle) low feerate
            `-> C (child) good feerate -- acceptable once its parent is confirmed

  1. The node learns C via relay -> orphan, walks up fetching M -> orphan, then R.
  2. R is rejected on fee; opportunistic 1p1c {R,M} is also sub-floor and rejected
     (a >=3 chain is what insulates the tail child C from any 1p1c rescue).
  3. A miner confirms the prefix {R, M} (C is NOT in the block).
  4. C's parent M is now a confirmed UTXO and C's own feerate clears the floor, so C
     must be reconsidered and accepted into the mempool automatically.
"""
import time
from decimal import Decimal

from test_framework.mempool_util import tx_in_orphanage
from test_framework.messages import (
    CInv,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    OVERLOADED_PEER_TX_DELAY,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode

# All possible tx-request delays + 1, so the exact value does not matter.
TXREQUEST_TIME_SKIP = NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY + OVERLOADED_PEER_TX_DELAY + 1

LOW = Decimal("0.00002")   # 2 sat/vB  -- below the node's 10 sat/vB floor
HIGH = Decimal("0.00050")  # 50 sat/vB -- well above the floor


class OrphanBlockResolutionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Elevate the mempool min fee so the low-fee ancestors are rejected by this
        # node, while still being perfectly minable by a miner.
        self.extra_args = [["-minrelaytxfee=0.00010000"]]  # 10 sat/vB

    def relay_tx(self, peer, tx):
        """Announce a tx by wtxid and hand it over when requested."""
        peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=tx.wtxid_int)]))
        self.nodes[0].bumpmocktime(TXREQUEST_TIME_SKIP)
        peer.wait_for_getdata([tx.wtxid_int])
        peer.send_and_ping(msg_tx(tx))

    def provide_requested_parent(self, peer, parent_tx):
        """Wait for the node to request a missing parent (by txid) and hand it over."""
        self.nodes[0].bumpmocktime(TXREQUEST_TIME_SKIP)
        peer.wait_for_getdata([parent_tx.txid_int])
        peer.send_and_ping(msg_tx(parent_tx))

    def run_test(self):
        node = self.nodes[0]
        node.setmocktime(int(time.time()))
        self.wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)
        self.generate(self.wallet, 120)

        # R -> M -> C
        root = self.wallet.create_self_transfer(fee_rate=LOW)
        middle = self.wallet.create_self_transfer(utxo_to_spend=root["new_utxo"], fee_rate=LOW)
        child = self.wallet.create_self_transfer(utxo_to_spend=middle["new_utxo"], fee_rate=HIGH)

        peer = node.add_p2p_connection(P2PTxInvStore())

        self.log.info("Relay the tail child -> orphan; node walks up the chain fetching parents")
        self.relay_tx(peer, child["tx"])
        assert tx_in_orphanage(node, child["tx"])
        self.provide_requested_parent(peer, middle["tx"])
        assert tx_in_orphanage(node, middle["tx"])

        self.log.info("Provide the low-fee root -> rejected on fee; 1p1c {R,M} too cheap to rescue")
        self.provide_requested_parent(peer, root["tx"])
        assert_equal(node.getrawmempool(), [])
        assert tx_in_orphanage(node, child["tx"])

        self.log.info("Miner confirms the prefix {R, M} in a block (child NOT included)")
        self.generateblock(
            node,
            output=self.wallet.get_address(),
            transactions=[root["tx"].serialize().hex(), middle["tx"].serialize().hex()],
        )
        # Confirm M landed in the chain (ignore the mempool, where the child may
        # already be spending M's output once it is reconsidered below).
        assert_equal(node.gettxout(middle["tx"].txid_hex, 0, include_mempool=False)["confirmations"], 1)

        self.log.info("Child must now be reconsidered and accepted automatically")
        peer.sync_with_ping()
        self.wait_until(lambda: child["tx"].txid_hex in node.getrawmempool(), timeout=10)
        assert not tx_in_orphanage(node, child["tx"])


if __name__ == '__main__':
    OrphanBlockResolutionTest(__file__).main()
