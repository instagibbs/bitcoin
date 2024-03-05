#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test compact blocks (BIP 152)."""
import random

from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    BlockTransactions,
    BlockTransactionsRequest,
    CBlock,
    CBlockHeader,
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    from_hex,
    HeaderAndShortIDs,
    MSG_BLOCK,
    MSG_CMPCT_BLOCK,
    MSG_WITNESS_FLAG,
    P2PHeaderAndShortIDs,
    PrefilledTransaction,
    calculate_shortid,
    msg_block,
    msg_wblocktxn,
    msg_cmpctblock,
    msg_getdata,
    msg_getheaders,
    msg_getwblocktxn,
    msg_headers,
    msg_inv,
    msg_no_witness_block,
    msg_no_witness_blocktxn,
    msg_sendcmpct,
    msg_sendheaders,
    msg_tx,
    msg_weakcmpctblock,
    ser_uint256,
    tx_from_hex,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    softfork_active,
)
from test_framework.wallet import (
    MiniWallet,
)


# TestP2PConn: A peer we use to send messages to bitcoind, and store responses.
class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_sendcmpct = []
        self.block_announced = False
        # Store the hashes of blocks we've seen announced.
        # This is for synchronizing the p2p message traffic,
        # so we can eg wait until a particular block is announced.
        self.announced_blockhashes = set()

    def on_sendcmpct(self, message):
        self.last_sendcmpct.append(message)

    def on_cmpctblock(self, message):
        self.block_announced = True
        self.last_message["cmpctblock"].header_and_shortids.header.calc_sha256()
        self.announced_blockhashes.add(self.last_message["cmpctblock"].header_and_shortids.header.sha256)

    def on_headers(self, message):
        self.block_announced = True
        for x in self.last_message["headers"].headers:
            x.calc_sha256()
            self.announced_blockhashes.add(x.sha256)

    def on_inv(self, message):
        for x in self.last_message["inv"].inv:
            if x.type == MSG_BLOCK:
                self.block_announced = True
                self.announced_blockhashes.add(x.hash)

    # Requires caller to hold p2p_lock
    def received_block_announcement(self):
        return self.block_announced

    def clear_block_announcement(self):
        with p2p_lock:
            self.block_announced = False
            self.last_message.pop("inv", None)
            self.last_message.pop("headers", None)
            self.last_message.pop("cmpctblock", None)

    def clear_getwblocktxn(self):
        with p2p_lock:
            self.last_message.pop("getwblocktxn", None)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.send_message(msg)

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_message(headers_message)

    def request_headers_and_sync(self, locator, hashstop=0):
        self.clear_block_announcement()
        self.get_headers(locator, hashstop)
        self.wait_until(self.received_block_announcement, timeout=30)
        self.clear_block_announcement()

    # Block until a block announcement for a particular block hash is
    # received.
    def wait_for_block_announcement(self, block_hash, timeout=30):
        def received_hash():
            return (block_hash in self.announced_blockhashes)
        self.wait_until(received_hash, timeout=timeout)

    def send_await_disconnect(self, message, timeout=30):
        """Sends a message to the node and wait for disconnect.

        This is used when we want to send a message into the node that we expect
        will get us disconnected, eg an invalid block."""
        self.send_message(message)
        self.wait_for_disconnect(timeout)

class CompactBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[
            "-acceptnonstdtxn=1",
        ]] * self.num_nodes
        self.utxos = []

    def build_block_on_tip(self, node):
        block = create_block(tmpl=node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS))
        block.solve()
        return block

    # Create 10 more anyone-can-spend utxo's for testing.
    def make_utxos(self):
        block = self.build_block_on_tip(self.nodes[0])
        self.test_node.send_and_ping(msg_no_witness_block(block))
        assert int(self.nodes[0].getbestblockhash(), 16) == block.sha256
        self.generate(self.wallet, COINBASE_MATURITY)

        total_value = block.vtx[0].vout[0].nValue
        out_value = total_value // 10
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(block.vtx[0].sha256, 0), b''))
        for _ in range(10):
            tx.vout.append(CTxOut(out_value, CScript([OP_TRUE])))
        tx.rehash()

        block2 = self.build_block_on_tip(self.nodes[0])
        block2.vtx.append(tx)
        block2.hashMerkleRoot = block2.calc_merkle_root()
        block2.solve()
        self.test_node.send_and_ping(msg_no_witness_block(block2))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block2.sha256)
        self.utxos.extend([[tx.sha256, i, out_value] for i in range(10)])

    # Create a chain of transactions from given utxo, and add to a new block.
    def build_weak_block_with_transactions(self, node, utxo, num_transactions):
        block = self.build_block_on_tip(node)

        for _ in range(num_transactions):
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(utxo[0], utxo[1]), b''))
            # mix in num_transactions for unique tx chain to generate conflict
            tx.vout.append(CTxOut(utxo[2] - (1000 + num_transactions), CScript([OP_TRUE, OP_DROP] * 15 + [OP_TRUE])))
            tx.rehash()
            utxo = [tx.sha256, 0, tx.vout[0].nValue]
            block.vtx.append(tx)

        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve_weak()
        return block

    # Test "sendcmpct" (between peers preferring the same version):
    # - No compact block announcements unless sendcmpct is sent.
    # - If sendcmpct is sent with version = 1, the message is ignored.
    # - If sendcmpct is sent with version > 2, the message is ignored.
    # - If sendcmpct is sent with boolean 0, then block announcements are not
    #   made with compact blocks.
    # - If sendcmpct is then sent with boolean 1, then new block announcements
    #   are made with compact blocks.
    def test_sendcmpct(self, test_node):
        node = self.nodes[0]

        # Make sure we get a SENDCMPCT message from our peer
        def received_sendcmpct():
            return (len(test_node.last_sendcmpct) > 0)
        test_node.wait_until(received_sendcmpct, timeout=30)
        with p2p_lock:
            # Check that version 2 is received.
            assert_equal(test_node.last_sendcmpct[0].version, 2)
            test_node.last_sendcmpct = []

        tip = int(node.getbestblockhash(), 16)

        def check_announcement_of_new_block(node, peer, predicate):
            peer.clear_block_announcement()
            block_hash = int(self.generate(node, 1)[0], 16)
            peer.wait_for_block_announcement(block_hash, timeout=30)
            assert peer.block_announced

            with p2p_lock:
                assert predicate(peer), (
                    "block_hash={!r}, cmpctblock={!r}, inv={!r}".format(
                        block_hash, peer.last_message.get("cmpctblock", None), peer.last_message.get("inv", None)))

        # We shouldn't get any block announcements via cmpctblock yet.
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message)

        # Try one more time, this time after requesting headers.
        test_node.request_headers_and_sync(locator=[tip])
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message and "inv" in p.last_message)

        # Test a few ways of using sendcmpct that should NOT
        # result in compact block announcements.
        # Before each test, sync the headers chain.
        test_node.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with too-low version
        test_node.send_and_ping(msg_sendcmpct(announce=True, version=1))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message)

        # Headers sync before next test.
        test_node.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with too-high version
        test_node.send_and_ping(msg_sendcmpct(announce=True, version=3))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message)

        # Headers sync before next test.
        test_node.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with valid version, but announce=False
        test_node.send_and_ping(msg_sendcmpct(announce=False, version=2))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message)

        # Headers sync before next test.
        test_node.request_headers_and_sync(locator=[tip])

        # Finally, try a SENDCMPCT message with announce=True
        test_node.send_and_ping(msg_sendcmpct(announce=True, version=2))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" in p.last_message)

        # Try one more time (no headers sync should be needed!)
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" in p.last_message)

        # Try one more time, after turning on sendheaders
        test_node.send_and_ping(msg_sendheaders())
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" in p.last_message)

        # Try one more time, after sending a version=1, announce=false message.
        test_node.send_and_ping(msg_sendcmpct(announce=False, version=1))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" in p.last_message)

        # Now turn off announcements
        test_node.send_and_ping(msg_sendcmpct(announce=False, version=2))
        check_announcement_of_new_block(node, test_node, lambda p: "cmpctblock" not in p.last_message and "headers" in p.last_message)

    def test_invalid_weakcmpctblock_message(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        block = self.build_block_on_tip(self.nodes[0])

        comp_block = P2PHeaderAndShortIDs()
        comp_block.header = CBlockHeader(block)
        comp_block.prefilled_txn_length = 1
        # This index will be too high
        prefilled_txn = PrefilledTransaction(1, block.vtx[0])
        comp_block.prefilled_txn = [prefilled_txn]
        self.test_node.send_await_disconnect(msg_weakcmpctblock(comp_block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

    def test_getwcmpctblock_message(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        #block = self.build_block_on_tip(self.nodes[0])
        utxo = self.utxos.pop(0)
        block = self.build_weak_block_with_transactions(self.nodes[0], utxo, 1)

        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, prefill_list=[0], use_witness=True)

        self.test_node.clear_getwblocktxn()
        self.test_node.send_and_ping(msg_weakcmpctblock(comp_block.to_p2p()))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # Expect a getwblocktxn message.
        with p2p_lock:
            assert "getwblocktxn" in self.test_node.last_message

        # Respond to it wtih WBLOCKTXN, look for reconstruction
        msg = msg_wblocktxn()
        msg.weak_block_transactions.blockhash = block.sha256
        msg.weak_block_transactions.transactions = block.vtx[1:]

        assert_equal(self.nodes[0].getrawmempool(), [])

        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg)

        assert_equal(self.nodes[0].getrawmempool(), [block.vtx[-1].rehash()])


    def test_basic_weakcmpctblock_message(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        # hb peer but won't hear about weakblock due to lack of advertised chaintip
        hb_test_node = self.nodes[0].add_p2p_connection(TestP2PConn())
        hb_test_node.send_and_ping(msg_sendcmpct(announce=True, version=2))
        assert self.nodes[0].getpeerinfo()[-1]['bip152_hb_from']

        # Generate transactions and make sure node has all txns
        utxo = self.utxos.pop(0)
        block = self.build_weak_block_with_transactions(self.nodes[0], utxo, 10)
        assert not block.is_valid()
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])
        for tx in block.vtx[1:]:
            self.test_node.send_message(msg_tx(tx))
        self.test_node.sync_with_ping()
        # Make sure all transactions were accepted.
        mempool = self.nodes[0].getrawmempool()
        for tx in block.vtx[1:]:
            assert tx.hash in mempool

        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, prefill_list=[0], use_witness=True)

        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg_weakcmpctblock(comp_block.to_p2p()))
        # Doesn't move the chain forward
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # Clear the test node's mempool of those txns, should still reconstruct
        conflict_block = self.build_weak_block_with_transactions(self.nodes[0], utxo, 1)
        new_txid = conflict_block.vtx[1].rehash()
        self.nodes[0].prioritisetransaction(new_txid, 0, 1000000)
        self.test_node.send_message(msg_tx(conflict_block.vtx[1]))
        self.test_node.sync_with_ping()
        assert_equal(self.nodes[0].getrawmempool(), [new_txid])

        # Second peer should hear about weak compact block from first
        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]) and \
            self.nodes[1].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg_weakcmpctblock(comp_block.to_p2p()))
        # Doesn't move the chain forward
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # Since node has reconstructed the block, we should be able to get requests
        # for weak block txns returned
        msg = msg_getwblocktxn()
        msg.weak_block_txn_request = BlockTransactionsRequest(comp_block.header.rehash(), [])
        num_to_request = random.randint(1, len(block.vtx))
        msg.weak_block_txn_request.from_absolute(sorted(random.sample(range(len(block.vtx)), num_to_request)))
        self.test_node.send_message(msg)
        self.test_node.wait_until(lambda: "wblocktxn" in self.test_node.last_message, timeout=10)

        # Node should not be telling hb peers about new weak blocks unless they advertised
        # knowledge of chain tip
        with p2p_lock:
            assert "wcmpctblock" not in hb_test_node.last_message

    def test_blank_weakcmpctblock_message(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        block = self.build_block_on_tip(self.nodes[0])

        block.solve_weak()
        assert not block.is_valid()

        comp_block = P2PHeaderAndShortIDs()
        comp_block.header = CBlockHeader(block)
        comp_block.prefilled_txn_length = 1
        prefilled_txn = PrefilledTransaction(0, block.vtx[0])
        comp_block.prefilled_txn = [prefilled_txn]
        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg_weakcmpctblock(comp_block))
        # Doesn't move the chain forward
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # full PoW weakblocks would work too
        block.solve()
        assert block.is_valid()

        comp_block.header = CBlockHeader(block)
        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg_weakcmpctblock(comp_block))
        # Doesn't move the chain forward
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # But not if block doesn't meet the multiplier threshold FIXME make really low PoW block
        # first by raising nBits?
        '''
        block.unsolve()
        assert not block.is_valid()

        comp_block.header = CBlockHeader(block)
        with self.nodes[0].assert_debug_log(expected_msgs=["Reconstructed weak compact block"]):
            self.test_node.send_and_ping(msg_weakcmpctblock(comp_block))
        # Doesn't move the chain forward
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)
        '''

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # Setup the p2p connections
        self.test_node = self.nodes[0].add_p2p_connection(TestP2PConn())

        # We will need UTXOs to construct transactions in later tests.
        self.make_utxos()

        assert softfork_active(self.nodes[0], "segwit")

        self.log.info("Testing SENDCMPCT p2p message... ")
        self.test_sendcmpct(self.test_node)

        self.log.info("Testing blank wcmpctblock message...")
        self.test_blank_weakcmpctblock_message()

        self.log.info("testing half round trip non-empty wcmpctblock message...")
        self.test_basic_weakcmpctblock_message()

        self.log.info("Test getwcmpctblock message is sent in return to incomplete block")
        self.test_getwcmpctblock_message()

        self.log.info("Test weak block not better than tip is ignored")
        # FIXME

        self.log.info("Testing invalid index in wcmpctblock message...")
        self.test_invalid_weakcmpctblock_message()

if __name__ == '__main__':
    CompactBlocksTest().main()
