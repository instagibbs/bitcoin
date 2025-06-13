#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test OP_TEMPLATEHASH committed hash spends and mutations. See feature_taproot.py for more coverage"""

from test_framework.key import (
    generate_privkey,
    compute_xonly_pubkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    msg_tx,
    SEQUENCE_FINAL,
)
from test_framework.p2p import (
    P2PInterface,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    OP_2,
    OP_EQUAL,
    OP_RETURN,
    OP_TEMPLATEHASH,
    OP_TRUE,
    TaggedHash,
    taproot_construct,
    TemplateMsg,
)
from test_framework.script_util import (
    script_to_p2sh_p2wsh_script,
    script_to_p2sh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
)


def get_template_hash(txTo, input_index=0, annex=None):
    return TaggedHash("TemplateHash", TemplateMsg(txTo, input_index, annex))


class TemplateHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[f"-vbparams=templatehash:0:{2**63 - 1}"]] # test activation of templatehash

    def test_discourage_no_disconnect(self):
        self.log.info("Testing discouragement doesn't result in disconnection")
        node = self.nodes[0]

        # Checking for non-disconnection
        peer = node.add_p2p_connection(P2PInterface())
        scripts = [
            ("basic", CScript([OP_TEMPLATEHASH])),
        ]
        tap = taproot_construct(self.public_keys[0], scripts)

        # Seed a utxo with script
        commit_tx = self.wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=330)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(commit_tx["tx"].rehash(), 16), commit_tx["sent_vout"]), b"", SEQUENCE_FINAL))
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x00\x00\x00\x00"])))

        # And fill out witness data for spend
        tx.wit.vtxinwit = [CTxInWitness()]
        control_block = bytes([tap.leaves["basic"].version | tap.negflag]) + tap.internal_pubkey + tap.leaves["basic"].merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [tap.leaves["basic"].script, control_block]

        assert_raises_rpc_error(-26, "non-mandatory-script-verify-flag (Templatehash is not active)", node.sendrawtransaction, tx.serialize().hex())
        peer.send_and_ping(msg_tx(tx))
        node.disconnect_p2ps()
        self.generate(self.wallet, 1)

    def test_basic(self):
        self.log.info("Testing basic committed OP_TEMPLATEHASH spend")
        node = self.nodes[0]

        # Generate a spending tx ahead of time that will allow for a valid spend to be created later
        # Just burns everything to fees for simplicity.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0), b"", SEQUENCE_FINAL))
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x00\x00\x00\x00"])))

        # Single tapscript that commits to future spend
        real_template_hash = get_template_hash(tx, input_index=0)
        scripts = [
            ("basic", CScript([real_template_hash, OP_TEMPLATEHASH, OP_EQUAL])),
        ]
        tap = taproot_construct(self.public_keys[0], scripts)

        # Seed a utxo with committed hash
        commit_tx = self.wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=330)

        # Now that funding tx is generated, the spending transaction
        # prevout can be properly bound
        tx.vin[0].prevout.hash = int(commit_tx["tx"].rehash(), 16)
        tx.vin[0].prevout.n = commit_tx["sent_vout"]

        # And fill out witness data for spend
        tx.wit.vtxinwit = [CTxInWitness()]

        # template digest should be unchanged
        assert_equal(get_template_hash(tx, input_index=0), real_template_hash)

        control_block = bytes([tap.leaves["basic"].version | tap.negflag]) + tap.internal_pubkey + tap.leaves["basic"].merklebranch
        assert_equal(len(control_block), 33)
        tx.wit.vtxinwit[0].scriptWitness.stack = [tap.leaves["basic"].script, control_block]

        node.sendrawtransaction(tx.serialize().hex(), maxfeerate=0)
        self.generate(self.wallet, 1)

    def test_mutations(self):
        self.log.info("Basic testing of mutations of OP_TEMPLATEHASH spend")
        node = self.nodes[0]

        # Checking for non-disconnection
        peer = node.add_p2p_connection(P2PInterface())

        # Generate a spending tx ahead of time that will allow for a valid spend to be created later
        # Just burns everything to fees for simplicity.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0), b"", SEQUENCE_FINAL))
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x00\x00\x00\x00"])))

        # Single tapscript that commits to future spend
        real_template_hash = get_template_hash(tx, input_index=0)
        scripts = [
            ("basic", CScript([real_template_hash, OP_TEMPLATEHASH, OP_EQUAL])),
            ("alt", CScript([OP_RETURN])),
        ]
        tap = taproot_construct(self.public_keys[0], scripts)

        # Seed a utxo with committed hash
        commit_tx = self.wallet.send_to(from_node=node, scriptPubKey=tap.scriptPubKey, amount=330)

        # Now that funding tx is generated, the spending transaction
        # prevout can be properly bound
        tx.vin[0].prevout.hash = int(commit_tx["tx"].rehash(), 16)
        tx.vin[0].prevout.n = commit_tx["sent_vout"]

        # And fill out witness data for spend
        tx.wit.vtxinwit = [CTxInWitness()]

        # template digest should be unchanged
        assert_equal(get_template_hash(tx, input_index=0), real_template_hash)

        control_block = bytes([tap.leaves["basic"].version | tap.negflag]) + tap.internal_pubkey + tap.leaves["basic"].merklebranch
        assert_equal(len(control_block), 33 + 32)
        tx.wit.vtxinwit[0].scriptWitness.stack = [tap.leaves["basic"].script, control_block]

        # Tx would have been ok
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Mutate version
        tx.version = 1
        peer.send_and_ping(msg_tx(tx))
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.version = 2
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Mutate locktime
        tx.nLockTime += 1
        peer.send_and_ping(msg_tx(tx))
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.nLockTime -= 1
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Mutate nsequence
        tx.vin[0].nSequence -= 1
        peer.send_and_ping(msg_tx(tx))
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.vin[0].nSequence += 1
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Mutate output amount
        tx.vout[0].nValue += 1
        peer.send_and_ping(msg_tx(tx))
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.vout[0].nValue -= 1
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Add extraneous output
        tx.vout.append(tx.vout[-1])
        peer.send_and_ping(msg_tx(tx))
        assert not node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        del tx.vout[1]
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # Mutate annex (not relay standard)
        tx.wit.vtxinwit[0].scriptWitness.stack.append(bytes([ANNEX_TAG]) + b"\x00")
        peer.send_and_ping(msg_tx(tx))
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.wit.vtxinwit[0].scriptWitness.stack = tx.wit.vtxinwit[0].scriptWitness.stack[:-1]
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        # "Ok" to mutate other witness data
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x00"] + tx.wit.vtxinwit[0].scriptWitness.stack
        peer.send_and_ping(msg_tx(tx))
        assert_raises_rpc_error(-25, "TestBlockValidity failed: mandatory-script-verify-flag-failed (Stack size must be exactly one after execution)", self.generateblock, node, output="raw(51)", transactions=[commit_tx["hex"], tx.serialize().hex()])
        tx.wit.vtxinwit[0].scriptWitness.stack = tx.wit.vtxinwit[0].scriptWitness.stack[1:]
        assert node.testmempoolaccept([tx.serialize().hex()])[0]["allowed"]

        node.disconnect_p2ps()

    def run_test(self):
        node = self.nodes[0]

        # Can be expanded to mix keys
        self.secret_keys = [generate_privkey() for _ in range(1)]
        self.public_keys = [compute_xonly_pubkey(sec)[0] for sec in self.secret_keys]

        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)
        assert_equal(node.getdeploymentinfo()["deployments"]["templatehash"]["bip9"]["status"], "defined")

        self.test_discourage_no_disconnect()

        self.log.info("Activating templatehash")
        self.generate(self.nodes[0], 432-101)
        assert_equal(node.getdeploymentinfo()["deployments"]["templatehash"]["bip9"]["status"], "active")

        self.test_basic()
        self.test_mutations()

if __name__ == '__main__':
    TemplateHashTest(__file__).main()
