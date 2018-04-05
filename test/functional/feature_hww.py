#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os, stat, sys

# Node 0 is hww node
# Node 1 is software signing node
# Node 2 is hww node with non-standard derivation path

class ExternalHDTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [[], [], []]

    def setup_network(self, split=False):
        self.add_nodes(3, self.extra_args)

    def run_test(self):

        print("Make sure your device is plugged in and loaded to the btc testnet app...")

        hww_driver_path = self.options.tmpdir+"/node0/bitcoin-hww-ledger.py"
        contrib_file = open('contrib/bitcoin-hww-ledger.py', 'r')
        datadir_file = open(hww_driver_path, 'w')
        for line in contrib_file:
            datadir_file.write(line)

        datadir_file.close()
        contrib_file.close()

        os.chmod(hww_driver_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        self.assert_start_raises_init_error(0, ['-hardwarewallet=dummy.py'], "Error getting xpub from device. Make sure your `-hardwarewallet` path is correct and the device plugged in and unlocked.")
        self.assert_start_raises_init_error(0, ['-hardwarewallet='+hww_driver_path, '-externalhd=tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm'], "externalhd and hardwarewallet cannot be both set.")
        self.assert_start_raises_init_error(0, ['-hardwarewallet='+hww_driver_path, "-derivationpath=mm/44'/0'/0'"], "Derivation path is malformed. Example: m/44'/0'/0'")
        self.assert_start_raises_init_error(0, ['-hardwarewallet='+hww_driver_path, "-derivationpath=m/44'/0'/0'/"], "Derivation path is malformed. Example: m/44'/0'/0'")
        self.assert_start_raises_init_error(0, ['-hardwarewallet='+hww_driver_path, "-derivationpath=m/44h/0h/0h"], "Derivation path is malformed. Example: m/44'/0'/0'")

        # One node will be the default BIP44 path, one some bizarre specified path
        # Have to start nodes separately to not conflict with each other asking for xpubs
        self.start_node(0, ['-hardwarewallet='+hww_driver_path, '-walletrbf=1'])
        self.start_node(1, [])
        self.start_node(2, ['-hardwarewallet='+hww_driver_path, "-derivationpath=m/42/0'/5'"])
        connect_nodes_bi(self.nodes,0,1)

        self.stop_nodes()


        self.assert_start_raises_init_error(0, [], "Error loading wallet.dat: You must provide a -hardwarewallet argument for a hww wallet file.")
        self.assert_start_raises_init_error(0, ['-hardwarewallet='+hww_driver_path, "-derivationpath=m/44'/0'/0"], "Error loading wallet.dat: You can't enable a different `-derivationpath` on an already initialized hww. Fix or remove the argument.")

        self.start_nodes([['-hardwarewallet='+hww_driver_path, '-walletrbf=1'], [], ['-hardwarewallet='+hww_driver_path, "-derivationpath=m/42/0'/5'"]])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)


        assert_equal(self.nodes[0].getbalance(), 0)
        self.nodes[0].generate(1)
        self.sync_all()
        self.nodes[1].generate(100)
        self.sync_all()

        print("Begin hardwarewallet tests...")

        # Get and validate some addresses
        # If this part is working, it means xpub and paths are correct
        p2sh_address = self.nodes[0].getnewaddress()
        native_address = self.nodes[0].getnewaddress("", "bech32")
        legacy_address = self.nodes[0].getnewaddress("", "legacy")

        # Full keypaths are stored, BIP44 or otherwise
        non_std_path_addr = self.nodes[2].getnewaddress()
        print("Validate non-standard path address: "+non_std_path_addr)
        assert(self.nodes[2].validateaddress(non_std_path_addr)["hdkeypath"] == "m/42/0'/5'/0/0")

        p2sh_change = self.nodes[0].getrawchangeaddress()
        native_change = self.nodes[0].getrawchangeaddress("bech32")
        legacy_change = self.nodes[0].getrawchangeaddress("legacy")

        print("Just validating the keypaths, just approve both")
        assert(self.nodes[0].validateaddress(p2sh_address)["hdkeypath"] == "m/44'/0'/0'/0/1")
        assert(self.nodes[0].validateaddress(p2sh_change)["hdkeypath"] == "m/44'/0'/0'/1/0")

        # Have user validate each one
        print("Validating user addresses:")
        print("P2SH: "+p2sh_address)
        self.nodes[0].validateaddress(p2sh_address)
        print("Native segwit: "+native_address)
        self.nodes[0].validateaddress(native_address)
        print("Legacy: "+legacy_address)
        self.nodes[0].validateaddress(legacy_address)

        # Have user validate change too

        print("Validating user change addresses:")
        print("P2SH: "+p2sh_change)
        self.nodes[0].validateaddress(p2sh_change)
        print("Native segwit: "+native_change)
        self.nodes[0].validateaddress(native_change)
        print("Legacy: "+legacy_change)
        self.nodes[0].validateaddress(legacy_change)

        # Sign a message and verify it

        print("Testing sign/verifymessage with hww...")
        print("Address should show: "+legacy_address)
        signature = self.nodes[0].signmessage(legacy_address, "mic check")
        assert(self.nodes[0].verifymessage(legacy_address, signature, "mic check"))
        print("Verifies!")


        # Cannot use other address types for signing
        assert_raises_rpc_error(-3, "Address does not refer to key", self.nodes[0].signmessage, p2sh_address, "mic check")
        assert_raises_rpc_error(-3, "Address does not refer to key", self.nodes[0].signmessage, native_address, "mic check")

        print("Now a series of sends, one output to confirm per send:")
        # Make some transactions, check balance
        node0_bal = self.nodes[0].getbalance()
        # Balance for hww with `hardwarewallet` set will all be non-watchonly
        assert(self.nodes[0].getunconfirmedbalance() == 0)

        # Keys we will send to, then eventually import
        privkey_address = "n3NkSZqoPMCQN5FENxUBw4qVATbytH6FDK"
        privkey = "cNaQCDwmmh4dS9LzCgVtyy1e1xjCJ21GUDHe9K98nzb689JvinGV"

        print("non-segwit signing steps may show p2sh change, bug filed")
        print("Send of 10 to: "+privkey_address)
        self.nodes[0].sendtoaddress(privkey_address, 10) #change not being recognized by ledger
        # Seems to be related to p2sh change???
        node0_bal -= 10
        print("2 to " + legacy_address)
        self.nodes[0].sendtoaddress(legacy_address, 2)
        print("3 to " + p2sh_address)
        self.nodes[0].sendtoaddress(p2sh_address, 3)
        print("4 to " + native_address)
        self.nodes[0].sendtoaddress(native_address, 4)

        # Self-send to cause a mixed spend
        print("Mixed input spending of all funds to self. Ledger will need to sign twice.")
        print(str(self.nodes[0].getbalance()) + " minus fees to "+ native_address)
        self.nodes[0].sendtoaddress(native_address, self.nodes[0].getbalance(), "", "", True)

        self.nodes[0].generate(1)
        node0_bal += 50

        self.sync_all()

        # Mature fees
        self.nodes[0].generatetoaddress(100, "mwoD9tx3Sh3vciyM9hs3fDAVGqxWFLgMv7")
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), node0_bal)

        print("Funds check out! Now for a sendmany, 3 outputs at 5 each, same addresses as before, followed by a single 7 output to "+privkey_address)
        print()
        self.nodes[0].sendmany("", {legacy_address:5, p2sh_address:5, native_address:5, privkey_address:7})
        node0_bal -= 7

        self.nodes[0].generate(1)
        node0_bal += 25

        # Mature fees
        self.nodes[0].generatetoaddress(100, "mwoD9tx3Sh3vciyM9hs3fDAVGqxWFLgMv7")

        assert_equal(self.nodes[0].getbalance(), node0_bal)

        print("Wallet sending checks out.")

        assert_raises_rpc_error(-4, "Hardware wallets are not allowed to import addresses or keys.", self.nodes[0].importaddress, privkey_address)

        #privkey has 17 btc
        self.nodes[0].importprivkey(privkey)
        node0_bal += 17
        assert_equal(self.nodes[0].getbalance(), node0_bal)

        print("Sending all funds, including imported to self")
        self.nodes[0].sendtoaddress(native_address, node0_bal, "", "", True)

        self.nodes[0].generate(1)
        self.nodes[0].generatetoaddress(100, "mwoD9tx3Sh3vciyM9hs3fDAVGqxWFLgMv7")
        node0_bal += Decimal("12.5")
        assert_equal(self.nodes[0].getbalance(), node0_bal)

        utxo = self.nodes[0].listunspent()[0]

        print("Raw signing test")
        # Simple sign{hww, raw}transaction test
        rawtx = self.nodes[0].createrawtransaction([{"txid":utxo["txid"], "vout":utxo["vout"]}], {self.nodes[0].getnewaddress():1})

        signed_tx_ret = self.nodes[0].signrawtransaction(rawtx)

        assert_equal(signed_tx_ret["complete"], True)

        signed_tx_ret = self.nodes[0].signhwwtransaction(rawtx, [self.nodes[0].gettransaction(utxo["txid"])["hex"]])

        assert_equal(signed_tx_ret["complete"], True)

        # Node 0 signs 2 input transaction, 1 from software, 1 from hardware
        hw_addr = self.nodes[0].getnewaddress()
        self.nodes[1].sendtoaddress(hw_addr, 1)
        self.nodes[1].sendtoaddress(privkey_address, 1)
        self.sync_all()
        utxo1 = None
        utxo2 = None
        raw1 = None
        raw2 = None
        for utxo in self.nodes[0].listunspent(0):
            if utxo["address"] == hw_addr:
                utxo1 = (utxo["txid"], utxo["vout"])
                raw1 = self.nodes[0].gettransaction(utxo1[0])["hex"]

            if utxo["address"] == privkey_address:
                utxo2 = (utxo["txid"], utxo["vout"])
                raw2 = self.nodes[0].gettransaction(utxo2[0])["hex"]

        assert(utxo1 and utxo2)

        rawtx2 = self.nodes[0].createrawtransaction([{"txid":utxo1[0], "vout":utxo1[1]}, {"txid":utxo2[0], "vout":utxo2[1]}], {self.nodes[0].getnewaddress():1})

        # This will self-verify the scripts being signed, but not amounts or other policy constraints
        assert_equal(self.nodes[0].signrawtransaction(rawtx2)["complete"], True)
        # Only will do one input, has no knowledge of sw wallet
        assert_equal(self.nodes[0].signhwwtransaction(rawtx2, [raw1, raw2])["complete"], False)

        # Node 1 signs an input, node 0 then signs to complete
        node1_utxo = self.nodes[1].listunspent(0)[0]
        rawtx3 = self.nodes[0].createrawtransaction([{"txid":utxo1[0], "vout":utxo1[1]}, {"txid":node1_utxo["txid"], "vout":node1_utxo["vout"]}], {self.nodes[0].getnewaddress():1})
        part_signed = self.nodes[1].signrawtransaction(rawtx3)
        assert_equal(part_signed["complete"], False)
        full_signed = self.nodes[0].signrawtransaction(part_signed["hex"])
        # Wallet has no notion of 1 of the input transactions, will fail
        # since either signing mode requires information such as amount, or trusted inputs
        assert_equal(full_signed["complete"], False)
        # Passing in the full prevtxs fixes this
        full_signed = self.nodes[0].signhwwtransaction(part_signed["hex"], [raw1, self.nodes[1].gettransaction(node1_utxo["txid"])["hex"]])
        assert(full_signed["complete"])

        print("Bumpfee test")
        # super basic bumpfee test
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        txid2 = self.nodes[0].bumpfee(txid)["txid"]
        self.nodes[0].generate(1)
        assert_equal(self.nodes[0].gettransaction(txid2)["confirmations"], 1)

if __name__ == '__main__':
    ExternalHDTest().main()
