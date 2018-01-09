#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import os, stat

xpub = "yourtpubhere"

class ExternalHDTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-externalhd="+xpub]]

    def setup_network(self, split=False):
        self.add_nodes(1, self.extra_args)
        self.start_nodes()

    def run_test(self):

        assert_equal(self.nodes[0].getbalance(), 0)
        self.nodes[0].generate(1)
        self.nodes[0].generatetoaddress(100, "mwoD9tx3Sh3vciyM9hs3fDAVGqxWFLgMv7")

        print("Make sure your device is plugged in and loaded to the btc testnet app...")

        hww_driver_path = self.options.tmpdir+"/node0"
        contrib_file = open('contrib/bitcoin-hww-ledger.py', 'r')
        datadir_file = open(hww_driver_path+"/bitcoin-hww-ledger.py", 'w')
        for line in contrib_file:
            datadir_file.write(line)

        datadir_file.close()
        contrib_file.close()

        os.chmod(hww_driver_path+"/bitcoin-hww-ledger.py", stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        self.stop_nodes()

        self.start_nodes([['-externalhd='+xpub, '-hardwarewallet=bitcoin-hww-ledger.py']])

        print("Begin hardwarewallet tests...")

        # Get and validate some addresses
        # If this part is working, it means xpub and paths are correct
        p2sh_address = self.nodes[0].getnewaddress()
        native_address = self.nodes[0].getnewaddress("", "bech32")
        legacy_address = self.nodes[0].getnewaddress("", "legacy")

        p2sh_change = self.nodes[0].getrawchangeaddress()
        native_change = self.nodes[0].getrawchangeaddress("bech32")
        legacy_change = self.nodes[0].getrawchangeaddress("legacy")

        # Have user validate each one
        print("Validating user addresses:")
        print("P2SH: "+p2sh_address)
        self.nodes[0].validateaddress(p2sh_address)
        print("Native segwit(regtest != testnet, first and last part might differ): "+native_address)
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

        self.sync_all()

        # Mature fees
        self.nodes[0].generatetoaddress(100, "mwoD9tx3Sh3vciyM9hs3fDAVGqxWFLgMv7")
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), node0_bal)

        print("Wallet sending checks out.")

        assert_raises_rpc_error(-4, "External HD wallets are not allowed to import addresses or keys.", self.nodes[0].importaddress, privkey_address)

        #privkey has 17 btc
        self.nodes[0].importprivkey(privkey)
        node0_bal += 17
        assert_equal(self.nodes[0].getbalance(), node0_bal)

if __name__ == '__main__':
    ExternalHDTest().main()
