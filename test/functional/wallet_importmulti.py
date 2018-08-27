#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the importmulti RPC."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

class ImportMultiTest (BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-addresstype=legacy"], ["-addresstype=legacy"]]
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def run_test (self):
        self.log.info("Mining blocks...")
        self.nodes[0].generate(1)
        self.nodes[1].generate(1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())['mediantime']

        node0_address1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())

        #Check only one address
        assert_equal(node0_address1['ismine'], True)

        #Node 1 sync test
        assert_equal(self.nodes[1].getblockcount(),1)

        #Address Test - before import
        address_info = self.nodes[1].getaddressinfo(node0_address1['address'])
        assert_equal(address_info['iswatchonly'], False)
        assert_equal(address_info['ismine'], False)


        # RPC importmulti -----------------------------------------------

        # Bitcoin Address
        self.log.info("Should import an address")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], timestamp)
        watchonly_address = address['address']
        watchonly_timestamp = timestamp

        self.log.info("Should not import an invalid address")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": "not valid address",
            },
            "timestamp": "now",
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -5)
        assert_equal(result[0]['error']['message'], 'Invalid address')

        # ScriptPubKey + internal
        self.log.info("Should import a scriptPubKey with internal flag")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "internal": True
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], timestamp)

        # ScriptPubKey + !internal
        self.log.info("Should not import a scriptPubKey without internal flag")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], 'Internal must be set for hex scriptPubKey')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # Address + Public key + !Internal
        self.log.info("Should import an address with public key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "pubkeys": [ address['pubkey'] ]
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], timestamp)


        # ScriptPubKey + Public key + internal
        self.log.info("Should import a scriptPubKey with internal and with public key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        request = [{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "pubkeys": [ address['pubkey'] ],
            "internal": True
        }]
        result = self.nodes[1].importmulti(request)
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], timestamp)

        # ScriptPubKey + Public key + !internal
        self.log.info("Should not import a scriptPubKey without internal and with public key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        request = [{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "pubkeys": [ address['pubkey'] ]
        }]
        result = self.nodes[1].importmulti(request)
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], 'Internal must be set for hex scriptPubKey')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)

        # Address + Private key + !watchonly
        self.log.info("Should import an address with private key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address['address']) ]
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], True)
        assert_equal(address_assert['timestamp'], timestamp)

        self.log.info("Should not import an address with private key if is already imported")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address['address']) ]
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -4)
        assert_equal(result[0]['error']['message'], 'The wallet already contains the private key for this address or script')

        # Address + Private key + watchonly
        self.log.info("Should not import an address with private key and with watchonly")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address['address']) ],
            "watchonly": True
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], 'Incompatibility found between watchonly and keys')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)

        # ScriptPubKey + Private key + internal
        self.log.info("Should import a scriptPubKey with internal and with private key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address['address']) ],
            "internal": True
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], True)
        assert_equal(address_assert['timestamp'], timestamp)

        # ScriptPubKey + Private key + !internal
        self.log.info("Should not import a scriptPubKey without internal and with private key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address['address']) ]
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], 'Internal must be set for hex scriptPubKey')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # P2SH address
        sig_address_1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_3 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        multi_sig_script = self.nodes[0].createmultisig(2, [sig_address_1['pubkey'], sig_address_2['pubkey'], sig_address_3['pubkey']])
        self.nodes[1].generate(100)
        self.nodes[1].sendtoaddress(multi_sig_script['address'], 10.00)
        self.nodes[1].generate(1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())['mediantime']

        self.log.info("Should import a p2sh")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": multi_sig_script['address']
            },
            "timestamp": "now",
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(multi_sig_script['address'])
        assert_equal(address_assert['isscript'], True)
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['timestamp'], timestamp)
        p2shunspent = self.nodes[1].listunspent(0,999999, [multi_sig_script['address']])[0]
        assert_equal(p2shunspent['spendable'], False)
        assert_equal(p2shunspent['solvable'], False)


        # P2SH + Redeem script
        sig_address_1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_3 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        multi_sig_script = self.nodes[0].createmultisig(2, [sig_address_1['pubkey'], sig_address_2['pubkey'], sig_address_3['pubkey']])
        self.nodes[1].generate(100)
        self.nodes[1].sendtoaddress(multi_sig_script['address'], 10.00)
        self.nodes[1].generate(1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())['mediantime']

        self.log.info("Should import a p2sh with respective redeem script")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": multi_sig_script['address']
            },
            "timestamp": "now",
            "redeemscript": multi_sig_script['redeemScript']
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(multi_sig_script['address'])
        assert_equal(address_assert['timestamp'], timestamp)

        p2shunspent = self.nodes[1].listunspent(0,999999, [multi_sig_script['address']])[0]
        assert_equal(p2shunspent['spendable'], False)
        assert_equal(p2shunspent['solvable'], True)


        # P2SH + Redeem script + Private Keys + !Watchonly
        sig_address_1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_3 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        multi_sig_script = self.nodes[0].createmultisig(2, [sig_address_1['pubkey'], sig_address_2['pubkey'], sig_address_3['pubkey']])
        self.nodes[1].generate(100)
        self.nodes[1].sendtoaddress(multi_sig_script['address'], 10.00)
        self.nodes[1].generate(1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())['mediantime']

        self.log.info("Should import a p2sh with respective redeem script and private keys")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": multi_sig_script['address']
            },
            "timestamp": "now",
            "redeemscript": multi_sig_script['redeemScript'],
            "keys": [ self.nodes[0].dumpprivkey(sig_address_1['address']), self.nodes[0].dumpprivkey(sig_address_2['address'])]
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(multi_sig_script['address'])
        assert_equal(address_assert['timestamp'], timestamp)

        p2shunspent = self.nodes[1].listunspent(0,999999, [multi_sig_script['address']])[0]
        assert_equal(p2shunspent['spendable'], False)
        assert_equal(p2shunspent['solvable'], True)

        # P2SH + Redeem script + Private Keys + Watchonly
        sig_address_1 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        sig_address_3 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        multi_sig_script = self.nodes[0].createmultisig(2, [sig_address_1['pubkey'], sig_address_2['pubkey'], sig_address_3['pubkey']])
        self.nodes[1].generate(100)
        self.nodes[1].sendtoaddress(multi_sig_script['address'], 10.00)
        self.nodes[1].generate(1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())['mediantime']

        self.log.info("Should import a p2sh with respective redeem script and private keys")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": multi_sig_script['address']
            },
            "timestamp": "now",
            "redeemscript": multi_sig_script['redeemScript'],
            "keys": [ self.nodes[0].dumpprivkey(sig_address_1['address']), self.nodes[0].dumpprivkey(sig_address_2['address'])],
            "watchonly": True
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], 'Incompatibility found between watchonly and keys')


        # Address + Public key + !Internal + Wrong pubkey
        self.log.info("Should not import an address with a wrong public key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        address2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "pubkeys": [ address2['pubkey'] ]
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -5)
        assert_equal(result[0]['error']['message'], 'Consistency check failed')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # ScriptPubKey + Public key + internal + Wrong pubkey
        self.log.info("Should not import a scriptPubKey with internal and with a wrong public key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        address2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        request = [{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "pubkeys": [ address2['pubkey'] ],
            "internal": True
        }]
        result = self.nodes[1].importmulti(request)
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -5)
        assert_equal(result[0]['error']['message'], 'Consistency check failed')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # Address + Private key + !watchonly + Wrong private key
        self.log.info("Should not import an address with a wrong private key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        address2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": address['address']
            },
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address2['address']) ]
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -5)
        assert_equal(result[0]['error']['message'], 'Consistency check failed')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # ScriptPubKey + Private key + internal + Wrong private key
        self.log.info("Should not import a scriptPubKey with internal and with a wrong private key")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        address2 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        result = self.nodes[1].importmulti([{
            "scriptPubKey": address['scriptPubKey'],
            "timestamp": "now",
            "keys": [ self.nodes[0].dumpprivkey(address2['address']) ],
            "internal": True
        }])
        assert_equal(result[0]['success'], False)
        assert_equal(result[0]['error']['code'], -5)
        assert_equal(result[0]['error']['message'], 'Consistency check failed')
        address_assert = self.nodes[1].getaddressinfo(address['address'])
        assert_equal(address_assert['iswatchonly'], False)
        assert_equal(address_assert['ismine'], False)
        assert_equal('timestamp' in address_assert, False)


        # Importing existing watch only address with new timestamp should replace saved timestamp.
        assert_greater_than(timestamp, watchonly_timestamp)
        self.log.info("Should replace previously saved watch only timestamp.")
        result = self.nodes[1].importmulti([{
            "scriptPubKey": {
                "address": watchonly_address,
            },
            "timestamp": "now",
        }])
        assert_equal(result[0]['success'], True)
        address_assert = self.nodes[1].getaddressinfo(watchonly_address)
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], timestamp)
        watchonly_timestamp = timestamp


        # restart nodes to check for proper serialization/deserialization of watch only address
        self.stop_nodes()
        self.start_nodes()
        address_assert = self.nodes[1].getaddressinfo(watchonly_address)
        assert_equal(address_assert['iswatchonly'], True)
        assert_equal(address_assert['ismine'], False)
        assert_equal(address_assert['timestamp'], watchonly_timestamp)

        # Bad or missing timestamps
        self.log.info("Should throw on invalid or missing timestamp values")
        assert_raises_rpc_error(-3, 'Missing required timestamp field for key',
            self.nodes[1].importmulti, [{
                "scriptPubKey": address['scriptPubKey'],
            }])
        assert_raises_rpc_error(-3, 'Expected number or "now" timestamp value for key. got type string',
            self.nodes[1].importmulti, [{
                "scriptPubKey": address['scriptPubKey'],
                "timestamp": "",
            }])

        # Importing multiple public keys with 2-of-2 p2sh multisig
        self.log.info("Pubkeys should be available after importing 2-of-2 p2sh multisig with pubkeys")
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[1].getnewaddress()
        pub1 = self.nodes[1].getaddressinfo(addr1)['pubkey']
        pub2 = self.nodes[1].getaddressinfo(addr2)['pubkey']
        ms = self.nodes[1].createmultisig(2, [pub1, pub2])
        result = self.nodes[0].importmulti(
            [{
                'scriptPubKey' : { 'address' : ms['address']},
                'redeemscript' : ms['redeemScript'],
                'pubkeys' : [pub1, pub2],
                "timestamp": "now",
            }]
        )
        assert result[0]['success']
        import_pub1 = self.nodes[0].getaddressinfo(addr1)['pubkey']
        assert_equal(pub1, import_pub1)
        import_pub2 = self.nodes[0].getaddressinfo(addr2)['pubkey']
        assert_equal(pub2, import_pub2)

        # Import some public keys to the keypool of a no privkey wallet
        self.log.info("Adding pubkey to keypool of disableprivkey wallet")
        self.nodes[1].createwallet(wallet_name="noprivkeys", disable_private_keys=True)
        wrpc = self.nodes[1].get_wallet_rpc("noprivkeys")

        addr1 = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()
        pub1 = self.nodes[0].getaddressinfo(addr1)['pubkey']
        pub2 = self.nodes[0].getaddressinfo(addr2)['pubkey']
        ms = self.nodes[0].createmultisig(2, [pub1, pub2])
        result = wrpc.importmulti(
            [{
                'scriptPubKey' : { 'address' : ms['address']},
                'redeemscript' : ms['redeemScript'],
                'pubkeys' : [pub1, pub2],
                'keypool' : True,
                "timestamp": "now",
            }]
        )
        assert result[0]['success']
        newaddr1 = wrpc.getnewaddress()
        assert_equal(addr1, newaddr1)
        newaddr2 = wrpc.getnewaddress()
        assert_equal(addr2, newaddr2)

        # Import some public keys to the internal keypool of a no privkey wallet
        self.log.info("Adding pubkey to internal keypool of disableprivkey wallet")
        addr1 = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()
        pub1 = self.nodes[0].getaddressinfo(addr1)['pubkey']
        pub2 = self.nodes[0].getaddressinfo(addr2)['pubkey']
        ms = self.nodes[0].createmultisig(2, [pub1, pub2])
        result = wrpc.importmulti(
            [{
                'scriptPubKey' : { 'address' : ms['address']},
                'redeemscript' : ms['redeemScript'],
                'pubkeys' : [pub1, pub2],
                'keypool' : True,
                'internal' : True,
                "timestamp": "now",
            }]
        )
        assert result[0]['success']
        newaddr1 = wrpc.getrawchangeaddress()
        assert_equal(addr1, newaddr1)
        newaddr2 = wrpc.getrawchangeaddress()
        assert_equal(addr2, newaddr2)
        # Import pubkeys with key origin info
        self.log.info("Addresses should have hd keypath and master key id after import with key origin")
        pub_addr = self.nodes[1].getnewaddress()
        info = self.nodes[1].getaddressinfo(pub_addr)
        pub = info['pubkey']
        pub_keypath = info['hdkeypath']
        pub_masterid = info['hdmasterkeyid']
        result = self.nodes[0].importmulti(
            [{
                'scriptPubKey' : { 'address' : pub_addr},
                'pubkeys' : [{pub:{pub_masterid:pub_keypath}}],
                "timestamp": "now",
            }]
        )
        assert result[0]['success']
        pub_import_info = self.nodes[0].getaddressinfo(pub_addr)
        assert_equal(pub_import_info['hdmasterkeyid'], pub_masterid)
        assert_equal(pub_import_info['pubkey'], pub)
        assert_equal(pub_import_info['hdkeypath'], pub_keypath)

        # Import privkeys with key origin info
        priv_addr = self.nodes[1].getnewaddress()
        info = self.nodes[1].getaddressinfo(priv_addr)
        priv = self.nodes[1].dumpprivkey(priv_addr)
        priv_keypath = info['hdkeypath']
        priv_masterid = info['hdmasterkeyid']
        result = self.nodes[0].importmulti(
            [{
                'scriptPubKey' : { 'address' : priv_addr},
                'keys' : [{priv:{priv_masterid:priv_keypath}}],
                "timestamp": "now",
            }]
        )
        assert result[0]['success']
        priv_import_info = self.nodes[0].getaddressinfo(priv_addr)
        assert_equal(priv_import_info['hdmasterkeyid'], priv_masterid)
        assert_equal(priv_import_info['hdkeypath'], priv_keypath)

        # Make sure the key origin info are still there after a restart
        self.stop_nodes()
        self.start_nodes()
        import_info = self.nodes[0].getaddressinfo(pub_addr)
        assert_equal(import_info['hdmasterkeyid'], pub_masterid)
        assert_equal(import_info['hdkeypath'], pub_keypath)
        import_info = self.nodes[0].getaddressinfo(priv_addr)
        assert_equal(import_info['hdmasterkeyid'], priv_masterid)
        assert_equal(import_info['hdkeypath'], priv_keypath)

        # Cannot import those pubkeys to keypool of wallet with privkeys
        self.log.info("Pubkeys cannot be added to the keypool of a wallet with private keys")
        wrpc = self.nodes[1].get_wallet_rpc("")
        assert wrpc.getwalletinfo()['private_keys_enabled']
        result = wrpc.importmulti([{
            'scriptPubKey' : { 'address' : ms['address']},
            'redeemscript' : ms['redeemScript'],
            'pubkeys' : [pub1, pub2],
            'keypool' : True,
            "timestamp": "now",
        }])
        assert_equal(result[0]['error']['code'], -8)
        assert_equal(result[0]['error']['message'], "Keys can only be imported to the keypool when private keys are disabled")

if __name__ == '__main__':
    ImportMultiTest ().main ()
