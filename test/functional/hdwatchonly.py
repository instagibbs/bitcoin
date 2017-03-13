#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class HDWatchOnlyTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = self.start_nodes(self.num_nodes, self.options.tmpdir, [['-hdwatchonly=tpubD6NzVbkrYhZ4YMc8VtVEChv2fv6eB5RK8ZKmn52hFuqmbGwauf1NjuzzscFzikw7sa41mdE46d9w274Gw29WuFkeVw2VESXxgcMwBQ6NNSf'],[]])
        self.is_network_split=False

    def run_test(self):
        print("Mining blocks...")

        # tprv8ZgxMBicQKsPetaLcEpdoJFv6tai1kEQZFizVYzPqe3NkngpHGBnZRP8hUVrrxgaXgckrr2V38HKMTzPMGG5cJq6RymQ1Bn8v9ACJgh9RvG

        # Can generate change address
        address = self.nodes[0].getrawchangeaddress()
        assert_equal(address, 'mvumWx631FFTDtgWP55ph623xvUfp5Y1xz')
        validated_address = self.nodes[0].validateaddress(address)
        assert_equal(validated_address['hdkeypath'], 'm/1/0')
        address = self.nodes[0].getrawchangeaddress()
        assert_equal(address, 'mkrg25GL23RAdnhP6Ttxtu7DzgknmZz3yc')
        validated_address = self.nodes[0].validateaddress(address)
        assert_equal(validated_address['hdkeypath'], 'm/1/1')

        # Check if getwalletinfo show the hd pubkey info
        assert_equal(self.nodes[0].getwalletinfo()["hdwatchonlykey"], 'tpubD6NzVbkrYhZ4YMc8VtVEChv2fv6eB5RK8ZKmn52hFuqmbGwauf1NjuzzscFzikw7sa41mdE46d9w274Gw29WuFkeVw2VESXxgcMwBQ6NNSf')

        # Can generate new address (m/0/0 is generated by default at wallet creation)
        address = self.nodes[0].getnewaddress()
        assert_equal(address, 'mxKeRQP6gTdCW6jHhn9FW8bGXD8W1UpR6n')
        validated_address = self.nodes[0].validateaddress(address)
        assert_equal(validated_address['hdkeypath'], 'm/0/1')

        self.nodes[0].generatetoaddress(1, address)
        self.nodes[0].generate(101)

        unspent = self.nodes[0].listunspent()
        assert_equal(len(unspent), 2)

        # generatetoaddress with p2pkh
        assert_equal(unspent[0]['solvable'], True)

        # generate mine to p2pk, so let's just be sure we can solve it
        assert_equal(unspent[1]['solvable'], True)

        self.stop_nodes()

        # check for graceful failure due to any invalid hdwatchonly parameters
        assert_start_raises_init_error(0, self.options.tmpdir, ['-hdwatchonly=eopipwd'],
        'Invalid ExtPubKey format')
        assert_start_raises_init_error(0, self.options.tmpdir, ['-hdwatchonly=tprv8ZgxMBicQKsPetaLcEpdoJFv6tai1kEQZFizVYzPqe3NkngpHGBnZRP8hUVrrxgaXgckrr2V38HKMTzPMGG5cJq6RymQ1Bn8v9ACJgh9RvG'],
        'Invalid ExtPubKey format')
        assert_start_raises_init_error(0, self.options.tmpdir, ['-hdwatchonly=xpubD6NzVbkrYhZ4YTNYPw3XmSoBRZWmfn8mRerv3SEaC8UFiz5geKgCJH42cp9KUzRcfQNSuCQgdM1grUH7FgWYahWKDST3E9NYJMBwMKooTaY'],
        'Invalid ExtPubKey format')

        # should restart fine if hdwatchonly is the same as current wallet
        self.nodes = self.start_nodes(self.num_nodes, self.options.tmpdir, [['-hdwatchonly=tpubD6NzVbkrYhZ4YMc8VtVEChv2fv6eB5RK8ZKmn52hFuqmbGwauf1NjuzzscFzikw7sa41mdE46d9w274Gw29WuFkeVw2VESXxgcMwBQ6NNSf'],[]])

        self.stop_nodes()
        # should not restart if hdwatchonly is different from the current one
        assert_start_raises_init_error(0, self.options.tmpdir, ['-hdwatchonly=tpubD6NzVbkrYhZ4YTNYPw3XmSoBRZWmfn8mRerv3SEaC8UFiz5geKgCJH42cp9KUzRcfQNSuCQgdM1grUH7FgWYahWKDST3E9NYJMBwMKooTaY'],
        'Cannot specify new hdwatchonly on an already existing wallet')

        # check the hdkeypath has persisted
        self.nodes = self.start_nodes(self.num_nodes, self.options.tmpdir, [[],[]])
        validated_address = self.nodes[0].validateaddress('mxKeRQP6gTdCW6jHhn9FW8bGXD8W1UpR6n')
        assert_equal(validated_address['hdkeypath'], 'm/0/1')

        # check the hd key has persisted
        address = self.nodes[0].getnewaddress()
        assert_equal(address, 'moZamE3ykhxM5kuBNfnDLnH3iAGd5f8gS5')
        validated_address = self.nodes[0].validateaddress(address)
        assert_equal(validated_address['hdkeypath'], 'm/0/3')

        # check that scriptPubKey generated by hdwatchonly are safe
        self.stop_nodes()
        self.nodes = self.start_nodes(2, self.options.tmpdir, [[],[]])
        unspent = self.nodes[0].listunspent()
        assert_equal(len(unspent), 2)
        connect_nodes(self.nodes[1], 0)
        sync_chain([self.nodes[0], self.nodes[1]])
        # using private key of mxKeRQP6gTdCW6jHhn9FW8bGXD8W1UpR6n
        self.nodes[1].importprivkey("cTNoggeWzJPVK2EQtLb3Yj1J4sxH8Ktx81X9NvxUFwBv1RoPrxUA")
        self.nodes[1].sendtoaddress("moZamE3ykhxM5kuBNfnDLnH3iAGd5f8gS5", "0.1")
        sync_mempools([self.nodes[0], self.nodes[1]])
        unspent = self.nodes[0].listunspent(0)
        # The unconfirmed transaction should be safe
        safe_unconf_found = False
        for utxo in unspent:
            safe_unconf_found |= (utxo["confirmations"] == 0 and utxo["safe"])
        assert(safe_unconf_found)

if __name__ == '__main__':
    HDWatchOnlyTest().main()
