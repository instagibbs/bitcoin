#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet."""
from decimal import Decimal
from io import BytesIO
from itertools import product
import base64

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_array_result,
    assert_equal,
    assert_fee_amount,
    assert_raises_rpc_error,
    find_vout_for_address,
)
from test_framework.wallet_util import test_address

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    MAX_MONEY,
    SEQUENCE_FINAL,
    tx_from_hex,
    uint256_from_str,
    deser_string,
    ser_compact_size,
)

# like from_hex, but without the hex part
def FromBinary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert len(stream.read()) == 0
    return obj

class PSBTMap:
    """Class for serializing and deserializing PSBT maps"""

    def __init__(self, map=None):
        self.map = map if map is not None else {}

    def deserialize(self, f):
        m = {}
        while True:
            k = deser_string(f)
            if len(k) == 0:
                break
            v = deser_string(f)
            if len(k) == 1:
                k = k[0]
            assert k not in m
            m[k] = v
        self.map = m

    def serialize(self):
        m = b""
        for k,v in self.map.items():
#            if k == 0x07:
#                from pdb import set_trace
#                set_trace()
            if isinstance(k, int) and 0 <= k and k <= 255:
                k = bytes([k])
            m += ser_compact_size(len(k)) + k
            m += ser_compact_size(len(v)) + v
        m += b"\x00"
        return m

class PSBT:
    """Class for serializing and deserializing PSBTs"""

    def __init__(self):
        self.g = PSBTMap()
        self.i = []
        self.o = []
        self.tx = None

    def deserialize(self, f):
        assert f.read(5) == b"psbt\xff"
        self.g = FromBinary(PSBTMap, f)
        assert 0 in self.g.map
        self.tx = FromBinary(CTransaction, self.g.map[0])
        self.i = [FromBinary(PSBTMap, f) for _ in self.tx.vin]
        self.o = [FromBinary(PSBTMap, f) for _ in self.tx.vout]
        return self

    def serialize(self):
        assert isinstance(self.g, PSBTMap)
        assert isinstance(self.i, list) and all(isinstance(x, PSBTMap) for x in self.i)
        assert isinstance(self.o, list) and all(isinstance(x, PSBTMap) for x in self.o)
        assert 0 in self.g.map
        tx = FromBinary(CTransaction, self.g.map[0])
        assert len(tx.vin) == len(self.i)
        assert len(tx.vout) == len(self.o)

        psbt = [x.serialize() for x in [self.g] + self.i + self.o]
        return b"psbt\xff" + b"".join(psbt)

    def to_base64(self):
        return base64.b64encode(self.serialize()).decode("utf8")

    @classmethod
    def from_base64(cls, b64psbt):
        return FromBinary(cls, base64.b64decode(b64psbt))




class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [[
            "-walletrejectlongchains=0", "-trueoutputs=1"
        ]] * self.num_nodes
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Only need nodes 0-2 running at start of test
        self.stop_node(3)
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.sync_all(self.nodes[0:3])

    def check_fee_amount(self, curr_balance, balance_with_fee, fee_per_byte, tx_size):
        """Return curr_balance after asserting the fee was in range"""
        fee = balance_with_fee - curr_balance
        assert_fee_amount(fee, tx_size, fee_per_byte * 1000)
        return curr_balance

    def get_vsize(self, txn):
        return self.nodes[0].decoderawtransaction(txn)['vsize']

    def run_test(self):

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        self.log.info("Mining blocks...")

        self.generate(self.nodes[0], 1, sync_fun=self.no_op)

        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], 50)
        assert_equal(walletinfo['balance'], 0)

        self.sync_all(self.nodes[0:3])
        self.generate(self.nodes[1], COINBASE_MATURITY + 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))

        assert_equal(self.nodes[0].getbalance(), 50)
        assert_equal(self.nodes[1].getbalance(), 50)
        assert_equal(self.nodes[2].getbalance(), 0)

        # Generated by CLN, we can just fund the spent output thanks to APO signature
        psbt = "cHNidP8BAJMCAAAAAb72fk4vud3us0YZc81MYquzUFCxrddymVuCC1hKSISJAAAAAAAqAAAAAwAAAAAAAAAAAVEQJwAAAAAAACJRIMLyWtWxOVmczrG6GzMN+r4+kpjk0U7sEl0ilTbVMu94HOgAAAAAAAAiUSAjAveAqdMSGNv9A/TUEKsIA5le1Hldx5Y+oQWwIN5YqwAAAAAAAQErLA8BAAAAAAAiUSCwy0EI2FKwpvVdThyPc7Hc+CwAcJzqhYecegfUlTyCdAEIqQJlQdenKmwarJEYB4wYVSeDkd6pHJOAoSXnFBa+FeBXO37O7xHL2vQNAchGOeTRdm+j+qHrn0BJq+dk3HXmLgtQdeXBIQF5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmKxBwUQrVY0kML4BD8OqQFp4uB08JUFF/JbcKPk0fkdIzHCkbrCcs8B6dJk6DClM+guH1aqdl5+MSw4Cvi+lYbQW0zMAAAAA"
        decoded_psbt = self.nodes[0].decodepsbt(psbt)
        eltoo_update_addr = decoded_psbt["inputs"][0]["witness_utxo"]["scriptPubKey"]["address"]
        final_tx = self.nodes[0].finalizepsbt(psbt)
        tx = final_tx['hex']
        assert final_tx['complete']

        funding_txid = self.nodes[0].sendtoaddress(eltoo_update_addr, Decimal('0.00069420')) # this value allows fee to be 0
        raw_funding_tx = self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(funding_txid)["hex"])
        c_settle_tx = tx_from_hex(tx)

        # Rebind the tx to current prevout
        c_settle_tx.vin[0].prevout.hash = uint256_from_str(bytes.fromhex(funding_txid)[::-1])
        c_settle_tx.vin[0].prevout.n = 0 if raw_funding_tx["vout"][0]["value"] == Decimal('0.00069420') else 1
        rebind_settle = c_settle_tx.serialize().hex()

        res = self.nodes[0].testmempoolaccept([rebind_settle])
        assert_equal(res[0]["reject-reason"], 'non-BIP68-final')

        self.generate(self.nodes[0], 43, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        res = self.nodes[0].testmempoolaccept([rebind_settle])
        assert_equal(res[0]["reject-reason"], 'min relay fee not met')

        # Test if anchoring gets us into mempool via package submission
        funding_coin = self.nodes[0].listunspent()[0]
        anchor_spend = self.nodes[0].createpsbt(inputs=[{"txid": res[0]['txid'], "vout": 0}, {"txid":funding_coin["txid"], "vout": funding_coin["vout"]}], outputs=[{self.nodes[0].getnewaddress(): funding_coin["amount"]-Decimal('0.001')}])

        # Inject witness utxo data and dummy final scriptsig because empty fields are simply ignored by Core
        anchor_psbt = PSBT.from_base64(anchor_spend)
        anchor_psbt.i[0].map[0x01] = bytes.fromhex("00000000000000000151")
        anchor_psbt.i[0].map[0x07] = bytes.fromhex("deadbeef")
        anchor_spend = anchor_psbt.to_base64()

        # Double process due to bug in precomputed data struct
        anchor_spend = self.nodes[0].walletprocesspsbt(anchor_spend)
        anchor_spend = self.nodes[0].walletprocesspsbt(anchor_spend['psbt'])

        anchor_spend_hex = self.nodes[0].finalizepsbt(anchor_spend['psbt'])['hex']
        anchor_spend_hex = anchor_spend_hex.replace("04deadbeef", "00")

        package_result = self.nodes[0].submitpackage([rebind_settle, anchor_spend_hex])
        print(package_result)


if __name__ == '__main__':
    WalletTest().main()
