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
            "-trueoutputs=1", "-annexcarrier=1",
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

        # All generated by CLN, we can just fund the spent output thanks to APO signature
        settle_psbt_0 = "cHNidP8BAJMCAAAAAb72fk4vud3us0YZc81MYquzUFCxrddymVuCC1hKSISJAAAAAAAqAAAAAwAAAAAAAAAAAVEQJwAAAAAAACJRIMLyWtWxOVmczrG6GzMN+r4+kpjk0U7sEl0ilTbVMu94HOgAAAAAAAAiUSAjAveAqdMSGNv9A/TUEKsIA5le1Hldx5Y+oQWwIN5YqwBlzR0AAQErLA8BAAAAAAAiUSDD/8L1fqdAkqDt74HQR7ZHp0unxR6FUEzMz9XHkOWr4wEIqQJlQak6poCeFOIZZ1jb3uc/Sgd+pI4SlxbHn/BFkqneFcdgEuRtZ6y+WIL1JOzXLktAr7o646E7NiFROROBPDYX7JTBIQF5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmKxBwEQrVY0kML4BD8OqQFp4uB08JUFF/JbcKPk0fkdIzHCkoiKWkKphGr7iVbr5xijajg+rRYVz5XRVhXGO0OC083QAAAAA"
        update_psbt_0 = "cHNidP8BAF4CAAAAAb72fk4vud3us0YZc81MYquzUFCxrddymVuCC1hKSISJAAAAAAD9////ASwPAQAAAAAAIlEgw//C9X6nQJKg7e+B0Ee2R6dLp8UehVBMzM/Vx5Dlq+MAZc0dAAEBKywPAQAAAAAAIlEgLjTyoY4huF/Et4G6j7cTaUAvtEchYd2gMj0hdItUYhABCIoEQUD2BQAmpkWnP3wAPi/IeTuVJVZJORSgLrgy7bqy5g6TqAGf6FfMkFelOCCOI5b4CIhRgOuEk+h2zh7Yrzn/SQXDAlGsIcFEK1WNJDC+AQ/DqkBaeLgdPCVBRfyW3Cj5NH5HSMxwpCFQtLbGboh5+EJlf7OlOVSPEm6LQhHGnlHLBSlxmGVSmJsAAA=="
        settle_psbt_1 = "cHNidP8BAJMCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAAAAwAAAAAAAAAAAVERJwAAAAAAACJRIMLyWtWxOVmczrG6GzMN+r4+kpjk0U7sEl0ilTbVMu94G+gAAAAAAAAiUSAjAveAqdMSGNv9A/TUEKsIA5le1Hldx5Y+oQWwIN5YqwFlzR0AAQErLA8BAAAAAAAiUSDIuqGheqMn10Kl5gy++Ud2Qk5Qelt2soTvKn89WrvfJgEIqQJlQfQ0EZfTJQbAeznKyNr7EOm83yV9hYSzkWNHez5MHwpNS723CMV7nHHthcYZil628mhAMjMYDYx7IG5LB7q2uZfBIQF5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmKxBwEQrVY0kML4BD8OqQFp4uB08JUFF/JbcKPk0fkdIzHCke57ASXM2XWrW0RTL5LH1rhzTQCywrZgQGcsnFS+UzA8AAAAA"
        # bound to funding output
        update_psbt_1A = "cHNidP8BAF4CAAAAAb72fk4vud3us0YZc81MYquzUFCxrddymVuCC1hKSISJAAAAAAD9////ASwPAQAAAAAAIlEgyLqhoXqjJ9dCpeYMvvlHdkJOUHpbdrKE7yp/PVq73yYBZc0dAAEBKywPAQAAAAAAIlEgLjTyoY4huF/Et4G6j7cTaUAvtEchYd2gMj0hdItUYhABCIoEQcdy8gnCIwmQNGq9Y808CfNcCMASpnt8YiZTr2I/sr+PZH/bh3WKkKIZTIMkiua5CQKynXN7xq8ofw51rq/PO+fDAlGsIcFEK1WNJDC+AQ/DqkBaeLgdPCVBRfyW3Cj5NH5HSMxwpCFQ3LxbkIF7a+hOjLxUy6XQndhmslo2UelwH8Gj++pjvAoAAA=="
        # bound to update_psbt_0's state output
        update_psbt_1B = "cHNidP8BAF4CAAAAAb72fk4vud3us0YZc81MYquzUFCxrddymVuCC1hKSISJAAAAAAD9////ASwPAQAAAAAAIlEgyLqhoXqjJ9dCpeYMvvlHdkJOUHpbdrKE7yp/PVq73yYBZc0dAAEBKywPAQAAAAAAIlEgE9M6Sr6kj2H7iQKxbfMKAZKswDyVRsF2rgHu797RJPIBCLAEQcdy8gnCIwmQNGq9Y808CfNcCMASpnt8YiZTr2I/sr+PZH/bh3WKkKIZTIMkiua5CQKynXN7xq8ofw51rq/PO+fDCFGtBABlzR2yQcBEK1WNJDC+AQ/DqkBaeLgdPCVBRfyW3Cj5NH5HSMxwpLS2xm6IefhCZX+zpTlUjxJui0IRxp5RywUpcZhlUpibIVDcvFuQgXtr6E6MvFTLpdCd2GayWjZR6XAfwaP76mO8CgAA"

        # No psbt should have fees (update tx get fees later. settle tx get CPFP)
        decoded_update_psbt_0 = self.nodes[0].decodepsbt(update_psbt_0)
        assert(decoded_update_psbt_0["fee"] == 0)
        decoded_update_psbt_1A = self.nodes[0].decodepsbt(update_psbt_1A)
        assert(decoded_update_psbt_1A["fee"] == 0)
        decoded_update_psbt_1B = self.nodes[0].decodepsbt(update_psbt_1B)
        assert(decoded_update_psbt_1B["fee"] == 0)
        decoded_settle_psbt_0 = self.nodes[0].decodepsbt(settle_psbt_0)
        assert(decoded_settle_psbt_0["fee"] == 0)
        decoded_settle_psbt_1 = self.nodes[0].decodepsbt(settle_psbt_1)
        assert(decoded_settle_psbt_1["fee"] == 0)

        # Fund the contract
        eltoo_funding_addr = decoded_update_psbt_0["inputs"][0]["witness_utxo"]["scriptPubKey"]["address"]
        funding_txid = self.nodes[0].sendtoaddress(eltoo_funding_addr, Decimal('0.00069420'))
        raw_funding_tx = self.nodes[0].decoderawtransaction(self.nodes[0].gettransaction(funding_txid)["hex"])
        funding_outpoint = COutPoint(hash=uint256_from_str(bytes.fromhex(funding_txid)[::-1]), n=[x['n'] for x in raw_funding_tx["vout"] if x["scriptPubKey"]["address"] == eltoo_funding_addr][0])

        # First rebind the first update tx to whatever the funding output ends up being
        update_raw_psbt = PSBT.from_base64(update_psbt_0)
        update_raw_tx = tx_from_hex(update_raw_psbt.g.map[0x00].hex())
        update_raw_tx.vin[0].prevout = funding_outpoint

        # Next we need to BYOF the update tx using wallet
        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[0:3]))
        byof_coin = self.nodes[0].listunspent()[0]
        update_raw_tx.vin.append(CTxIn(outpoint=COutPoint(hash=uint256_from_str(bytes.fromhex(byof_coin['txid'])[::-1]), n=byof_coin['vout'])))
        update_raw_psbt.i.append(PSBTMap())
        update_raw_tx.vout.append(CTxOut(nValue=int(Decimal(byof_coin["amount"])*100_000_000 - 10000), scriptPubKey=bytes.fromhex(byof_coin["scriptPubKey"])))
        update_raw_psbt.o.append(PSBTMap())

        # Stitch the transaction back together and put back in psbt form
        update_raw_psbt.g.map[0x00] = update_raw_tx.serialize()
        update_raw_psbt = PSBT.to_base64(update_raw_psbt)
        update_raw_psbt = self.nodes[0].walletprocesspsbt(update_raw_psbt)['psbt']
        update_raw_psbt = self.nodes[0].walletprocesspsbt(update_raw_psbt)['psbt']
        decoded_update_psbt = self.nodes[0].decodepsbt(update_raw_psbt)
        assert(decoded_update_psbt['fee'] == Decimal("0.00010000")) # Funded!
        final_update_tx = self.nodes[0].finalizepsbt(update_raw_psbt)
        update_tx = final_update_tx['hex'] # complete!
        update_txid = self.nodes[0].sendrawtransaction(update_tx)

        # Settlement PSBT is ready to go, just needs rebinding
        final_tx = self.nodes[0].finalizepsbt(settle_psbt_0)
        settle_tx = final_tx['hex']
        assert final_tx['complete']
        c_settle_tx = tx_from_hex(settle_tx)

        # Rebind the settle tx to current update prevout
        c_settle_tx.vin[0].prevout.hash = uint256_from_str(bytes.fromhex(update_txid)[::-1])
        c_settle_tx.vin[0].prevout.n = 0 # Always the first output
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
