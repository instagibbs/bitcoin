#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test Taproot softfork (BIPs 340-342)

from test_framework.blocktools import (
    create_coinbase,
    create_block,
    add_witness_commitment,
    MAX_BLOCK_SIGOPS,
)
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    CScriptNum,
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    LOCKTIME_THRESHOLD,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_0,
    OP_1,
    OP_2,
    OP_1SUB,
    OP_1NEGATE,
    OP_2DROP,
    OP_2DUP,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CHECKSIGVERIFY,
    OP_CODESEPARATOR,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_HASH160,
    OP_IF,
    OP_NOT,
    OP_NOTIF,
    OP_PUSHDATA1,
    OP_RETURN,
    OP_SWAP,
    OP_VERIF,
    SIGHASH_DEFAULT,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    TaprootSignatureHash,
    is_op_success,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, hex_str_to_bytes, assert_equal
from test_framework.key import generate_privkey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey
from test_framework.address import program_to_witness, script_to_p2sh, hash160
from collections import namedtuple
from io import BytesIO
import random
import struct

EMPTYWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)"
INVALIDKEYPATHSIG_ERROR = "non-mandatory-script-verify-flag (Invalid signature for Taproot key path spending) (code 64)"
UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"

DUST_LIMIT = 600
MIN_FEE = 5000

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

def get_version1_p2sh(info):
    if isinstance(info, tuple):
        info = info[0]
    return script_to_p2sh(info)

def get_p2sh_spk(info):
    if isinstance(info, tuple):
        info = info[0]
    return CScript([OP_HASH160, hash160(info), OP_EQUAL])

def random_op_success():
    ret = 0
    while (not is_op_success(ret)):
        ret = random.randint(0x50, 0xfe)
    return CScriptOp(ret)

def random_unknown_leaf_ver(no_annex_tag=True):
    ret = LEAF_VERSION_TAPSCRIPT
    while (ret == LEAF_VERSION_TAPSCRIPT or (no_annex_tag and ret == (ANNEX_TAG & 0xfe))):
        ret = random.randrange(128) * 2
    return ret

def random_bytes(n):
    return bytes(random.getrandbits(8) for i in range(n))

# TODO-TAPROOT Use this in a test
def random_script(size, no_success=True):
    ret = bytes()
    while (len(ret) < size):
        remain = size - len(ret)
        opcode = random.randrange(256)
        while (no_success and is_op_success(opcode)):
            opcode = random.randrange(256)
        if opcode == 0 or opcode >= OP_1NEGATE:
            ret += bytes([opcode])
        elif opcode <= 75 and opcode <= remain - 1:
            ret += bytes([opcode]) + random_bytes(opcode)
        elif opcode == 76 and remain >= 2:
            pushsize = random.randint(0, min(0xff, remain - 2))
            ret += bytes([opcode]) + bytes([pushsize]) + random_bytes(pushsize)
        elif opcode == 77 and remain >= 3:
            pushsize = random.randint(0, min(0xffff, remain - 3))
            ret += bytes([opcode]) + struct.pack(b'<H', pushsize) + random_bytes(pushsize)
        elif opcode == 78 and remain >= 5:
            pushsize = random.randint(0, min(0xffffffff, remain - 5))
            ret += bytes([opcode]) + struct.pack(b'<I', pushsize) + random_bytes(pushsize)
    assert len(ret) == size
    return ret

# TODO-TAPROOT Use this in a test
def random_invalid_push(size):
    assert size > 0
    ret = bytes()
    opcode = 78
    if size <= 75:
        opcode = random.randint(75, 78)
    elif size <= 255:
        opcode = random.randint(76, 78)
    elif size <= 0xffff:
        opcode = random.randint(77, 78)
    if opcode == 75:
        ret = bytes([size]) + random_bytes(size - 1)
    elif opcode == 76:
        ret = bytes([opcode]) + bytes([size]) + random_bytes(size - 2)
    elif opcode == 77:
        ret = bytes([opcode]) + struct.pack(b'<H', size) + random_bytes(max(0, size - 3))
    else:
        ret = bytes([opcode]) + struct.pack(b'<I', size) + random_bytes(max(0, size - 5))
    assert len(ret) >= size
    return ret[:size]

def random_checksig_style(pubkey):
    """Creates a random CHECKSIG* tapscript that would succeed with only the valid signature on witness stack."""
    opcode = random.choice([OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD])
    if (opcode == OP_CHECKSIGVERIFY):
        ret = CScript([pubkey, opcode, OP_1])
    elif (opcode == OP_CHECKSIGADD):
        num = random.choice([0, 0x7fffffff, -0x7fffffff])
        ret = CScript([num, pubkey, opcode, num + 1, OP_EQUAL])
    else:
        ret = CScript([pubkey, opcode])
    return bytes(ret)

def damage_bytes(b):
    """Flips one bit at random in a byte string."""
    return (int.from_bytes(b, 'big') ^ (1 << random.randrange(len(b) * 8))).to_bytes(len(b), 'big')

# Each spender is a tuple of:
# - A scriptPubKey which is to be spent from (CScript)
# - An address for that scriptPubKey (string)
# - A comment describing the test (string)
# - Whether the spending (on itself) is expected to be standard (bool)
# - A witness stack-producing lambda taking as inputs:
#   - A transaction to sign (CTransaction)
#   - An input position (int)
#   - The spent UTXOs by this transaction (list of CTxOut)
#   - Whether to produce a valid spend (bool)
# - A string with an expected error message for failure case if known

Spender = namedtuple("Spender", "script,address,comment,is_standard,sat_function,err_msg")

def spend_no_sig(tx, input_index, spent_utxos, info, script):
    """Construct witness."""
    script = script["script"]
    tx.wit.vtxinwit[input_index].scriptWitness.stack = [script, info[2][script]]

def spend_single_sig(tx, input_index, spent_utxos, info, key, annex=None, hashtype=0, prefix=None, suffix=None, script=None, pos=-1, damage=False):
    if prefix is None:
        prefix = []
    if suffix is None:
        suffix = []

    ht = hashtype

    damage_type = random.randrange(5) if damage else -1
    '''
    * 0. bit flip the sighash
    * 1. bit flip the signature
    * If the expected hashtype is 0:
    -- 2. append a 0 to the signature
    -- 3. append a random value of 1-255 to the signature
    * If the expected hashtype is not 0:
    -- 2. do not append hashtype to the signature
    -- 3. append a random incorrect value of 0-255 to the signature
    * 4. extra witness element
    '''

    # Taproot key path spend: tweak key
    if script is None:
        _, negated = compute_xonly_pubkey(key)
        key = tweak_add_privkey(key, info[1], negated)
        assert(key is not None)

    # Change SIGHASH_SINGLE into SIGHASH_ALL if no corresponding output
    if (ht & 3 == SIGHASH_SINGLE and input_index >= len(tx.vout)):
        ht ^= 2
    # Compute sighash
    if script:
        sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath=True, script=script, codeseparator_pos=pos, annex=annex)
    else:
        sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath=False, annex=annex)
    if damage_type == 0:
        sighash = damage_bytes(sighash)
    # Compute signature
    sig = sign_schnorr(key, sighash)
    if damage_type == 1:
        sig = damage_bytes(sig)
    if damage_type == 2:
        if ht == 0:
            sig += bytes([0])
    elif damage_type == 3:
        random_ht = ht
        while random_ht == ht:
            random_ht = random.randrange(256)
        sig += bytes([random_ht])
    elif ht > 0:
        sig += bytes([ht])
    # Construct witness
    ret = prefix + [sig] + suffix
    if script is not None:
        ret += [script, info[2][script]]
    if annex is not None:
        ret += [annex]
    if damage_type == 4:
        ret = [random_bytes(random.randrange(5))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret

def spend_alwaysvalid(tx, input_index, info, script, annex=None, damage=False):
    if isinstance(script, tuple):
        version, script = script
    ret = [script, info[2][script]]
    if damage:
        # With 50% chance, we bit flip the script (unless the script is an empty vector)
        # With 50% chance, we bit flip the control block
        if random.choice([True, False]) or len(ret[0]) == 0:
            # Annex is always required for leaf version 0x50
            # Unless the original version is 0x50, we couldn't convert it to 0x50 without using annex
            tmp = damage_bytes(ret[1])
            while annex is None and tmp[0] == ANNEX_TAG and ret[1][0] != ANNEX_TAG:
                tmp = damage_bytes(ret[1])
            ret[1] = tmp
        else:
            ret[0] = damage_bytes(ret[0])
    if annex is not None:
        ret += [annex]
    # Randomly add input witness
    if random.choice([True, False]):
        for i in range(random.randint(1, 10)):
            ret = [random_bytes(random.randint(0, MAX_SCRIPT_ELEMENT_SIZE * 2))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret

# N.B. Function arguments below: t(ransaction), i(ndex to spend), u(txos being spent), v(alid signature?)

def spender_sighash_mutation(spenders, info, comment, standard=True, **kwargs):
    """Mutates signature randomly when failure for the inputs is requested."""
    spk = info[0]
    addr = get_taproot_bech32(info)

    def fn(t, i, u, v):
        return spend_single_sig(t, i, u, damage=not v, info=info, **kwargs)

    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn, err_msg=None))

def spender_two_paths(spenders, info, comment, standard, success, failure, err_msg=None):
    """Gives caller a way to specify two merkle paths to test validity satisfaction: One expected success, and one failure."""
    spk = info[0]
    addr = get_taproot_bech32(info)

    def fn(t, i, u, v):
        return spend_single_sig(t, i, u, damage=False, info=info, **(success if v else failure))

    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn, err_msg=err_msg))

def spender_alwaysvalid(spenders, info, comment, err_msg=None, **kwargs):
    """Mutates the witness when requested, intended for otherwise always true scripts."""
    spk = info[0]
    addr = get_taproot_bech32(info)

    def fn(t, i, u, v):
        return spend_alwaysvalid(t, i, damage=not v, info=info, **kwargs)

    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=False, sat_function=fn, err_msg=err_msg))

def spender_two_paths_alwaysvalid(spenders, info, comment, standard, success, failure, err_msg=None):
    """Allows specifying both a success and failure script without any signatures or additional witness data required."""
    spk = info[0]
    addr = get_taproot_bech32(info)

    def fn(t, i, u, v):
        return spend_no_sig(t, i, u, info, (success if v else failure))

    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn, err_msg=err_msg))

def spender_alwaysvalid_p2sh(spenders, info, comment, standard, script, err_msg=None):
    """Tests that p2sh-wrapping witness program v1 are always valid, since they are not covered by tapscript."""
    spk = get_p2sh_spk(info)
    addr = get_version1_p2sh(info)

    def fn(t, i, u, v):
        if v:
            t.vin[i].scriptSig = CScript([info[0]])
            # Empty control block is only invalid if we apply taproot rules,
            # which we shouldn't if the spend is wrapped in P2SH
            t.wit.vtxinwit[i].scriptWitness.stack = [script, bytes()]
        else:
            t.vin[i].scriptSig = CScript()
        return

    spenders.append(Spender(script=spk, address=addr, comment=comment, is_standard=standard, sat_function=fn, err_msg=err_msg))

def nested_script(script, depth):
    if depth == 0:
        return script
    return [nested_script(script, depth - 1), CScript([OP_RETURN])]

UTXOData = namedtuple('UTXOData', 'input,output,spender')

class TaprootTest(BitcoinTestFramework):

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-par=1"]]

    def block_submit(self, node, txs, msg, err_msg, cb_pubkey=None, fees=0, witness=False, accept=False):

        # Deplete block of any non-tapscript sigops using a single additional 0-value coinbase output
        # It's physically impossible to fit enough tapscript sigops to hit the old 80k limit without
        # busting txin-level limits. We simply have to account for the p2pk outputs in all
        # transactions. N.B. this test means no spenders can ever spend non-taproot/tapscript outputs,
        # or those at least have to be accounted for here.

        def MaybeIsPayToPubKey(script):
            return script[-1] == OP_CHECKSIG

        legacy_checksigs = 0 if cb_pubkey is None else 1 # P2PK output in coinbase back to wallet
        for tx in txs:
            for output in tx.vout:
                if MaybeIsPayToPubKey(output.scriptPubKey):
                    legacy_checksigs += 1
        extra_output_script = CScript([OP_CHECKSIG]*(MAX_BLOCK_SIGOPS-legacy_checksigs))

        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1, pubkey=cb_pubkey, extra_output_script=extra_output_script, fees=fees), self.lastblocktime + 1)
        block.nVersion = 4
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        witness and add_witness_commitment(block)
        block.rehash()
        block.solve()
        block_response = node.submitblock(block.serialize(True).hex())
        if err_msg is not None:
            assert err_msg in block_response
        if (accept):
            assert node.getbestblockhash() == block.hash, "Failed to accept: " + msg
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert node.getbestblockhash() == self.lastblockhash, "Failed to reject: " + msg

    def test_spenders(self, spenders, input_counts):
        """Run randomized tests with a number of "spenders".

        Steps:
            1) Generate an appropriate UTXO for each spender to test spend conditions
            2) Generate 100 random addresses of all wallet types: pkh/sh_wpkh/wpkh
            3) Select random number of inputs from (1)
            4) Select random number of addresses from (2) as outputs

        Each spender embodies a test; in a large randomized test, it is verified
        that toggling the valid argument to each lambda toggles the validity of
        the transaction. This is accomplished by constructing transactions consisting
        of all valid inputs, except one invalid one.
        """

        # Construct a UTXO to spend for each of the spenders, with the script to satisfy being given by the spender
        self.nodes[0].generate(110)
        bal = self.nodes[0].getbalance() * 3 / (4 * len(spenders))
        random.shuffle(spenders)
        num_spenders = len(spenders)
        utxos = []
        while len(spenders):
            # Create the necessary outputs in multiple transactions, as sPKs may be repeated in test cases(which sendmany does not support)
            outputs = {}
            new_spenders = []
            batch = []
            for spender in spenders:
                addr = spender.address
                if len(batch) == 100 or addr in outputs:
                    new_spenders.append(spender)
                else:
                    amount = random.randrange(int(bal * 95000000), int(bal * 105000000))
                    outputs[addr] = amount / 100000000
                    batch.append(spender)
            self.log.info("Constructing %i UTXOs for spending tests" % len(batch))
            tx = tx_from_hex(self.nodes[0].getrawtransaction(self.nodes[0].sendmany("", outputs)))
            tx.rehash()
            spenders = new_spenders
            random.shuffle(spenders)

            # Map created UTXOs back to the spenders they were created for
            for n, out in enumerate(tx.vout):
                for spender in batch:
                    if out.scriptPubKey == spender.script:
                        utxos.append(UTXOData(input=COutPoint(tx.sha256, n), output=out, spender=spender))
                        break
        assert(len(utxos) == num_spenders)
        random.shuffle(utxos)
        self.nodes[0].generate(1)

        # Construct a bunch of sPKs that send coins back to the host wallet
        self.log.info("Constructing 100 addresses for returning coins")
        host_spks = []
        host_pubkeys = []
        for i in range(100):
            addr = self.nodes[0].getnewaddress(address_type=random.choice(["legacy", "p2sh-segwit", "bech32"]))
            info = self.nodes[0].getaddressinfo(addr)
            spk = hex_str_to_bytes(info['scriptPubKey'])
            host_spks.append(spk)
            host_pubkeys.append(hex_str_to_bytes(info['pubkey']))

        # Pick random subsets of UTXOs to construct transactions with
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']
        while len(utxos):
            tx = CTransaction()
            tx.nVersion = random.choice([1, 2, random.randint(-0x80000000, 0x7fffffff)])
            min_sequence = (tx.nVersion != 1 and tx.nVersion != 0) * 0x80000000  # The minimum sequence number to disable relative locktime
            if random.choice([True, False]):
                tx.nLockTime = random.randrange(LOCKTIME_THRESHOLD, self.lastblocktime - 7200)  # all absolute locktimes in the past
            else:
                tx.nLockTime = random.randrange(self.lastblockheight + 1)  # all block heights in the past

            # Pick 1 to 4 UTXOs to construct transaction inputs
            acceptable_input_counts = [cnt for cnt in input_counts if cnt <= len(utxos)]
            while True:
                inputs = random.choice(acceptable_input_counts)
                remaining = len(utxos) - inputs
                if remaining == 0 or remaining >= max(input_counts) or remaining in input_counts:
                    break
            input_utxos = utxos[-inputs:]
            utxos = utxos[:-inputs]
            fee = random.randrange(MIN_FEE * 2, MIN_FEE * 4)  # 10000-20000 sat fee
            in_value = sum(utxo.output.nValue for utxo in input_utxos) - fee
            tx.vin = [CTxIn(outpoint=input_utxos[i].input, nSequence=random.randint(min_sequence, 0xffffffff)) for i in range(inputs)]
            tx.wit.vtxinwit = [CTxInWitness() for i in range(inputs)]
            self.log.info("Test: %s" % (", ".join(utxo.spender.comment for utxo in input_utxos)))

            # Add 1 to 4 outputs
            outputs = random.choice([1, 2, 3, 4])
            assert in_value >= 0 and fee - outputs * DUST_LIMIT >= MIN_FEE
            for i in range(outputs):
                tx.vout.append(CTxOut())
                if in_value <= DUST_LIMIT:
                    tx.vout[-1].nValue = DUST_LIMIT
                elif i < outputs - 1:
                    tx.vout[-1].nValue = in_value
                else:
                    tx.vout[-1].nValue = random.randint(DUST_LIMIT, in_value)
                in_value -= tx.vout[-1].nValue
                tx.vout[-1].scriptPubKey = random.choice(host_spks)
            fee += in_value
            assert(fee >= 0)

            # Sign each input incorrectly once on each complete signing pass, except the very last
            for fail_input in range(inputs + 1):
                # Expected message with each input failure, may be None(which is ignored)
                expected_fail_msg = None if fail_input == inputs else input_utxos[fail_input].spender.err_msg
                # Wipe scriptSig/witness
                for i in range(inputs):
                    tx.vin[i].scriptSig = CScript()
                    tx.wit.vtxinwit[i] = CTxInWitness()
                # Fill inputs/witnesses
                for i in range(inputs):
                    fn = input_utxos[i].spender.sat_function
                    fn(tx, i, [utxo.output for utxo in input_utxos], i != fail_input)
                # Submit to mempool to check standardness
                is_standard_tx = fail_input == inputs and all(utxo.spender.is_standard for utxo in input_utxos) and tx.nVersion >= 1 and tx.nVersion <= 2
                tx.rehash()
                if is_standard_tx:
                    self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
                    assert(self.nodes[0].getmempoolentry(tx.hash) is not None)
                else:
                    assert_raises_rpc_error(-26, None, self.nodes[0].sendrawtransaction, tx.serialize().hex(), 0)
                # Submit in a block
                msg = ','.join(utxo.spender.comment + ("*" if n == fail_input else "") for n, utxo in enumerate(input_utxos))
                self.block_submit(self.nodes[0], [tx], msg, witness=True, accept=fail_input == inputs, cb_pubkey=random.choice(host_pubkeys), fees=fee, err_msg=expected_fail_msg)

    def build_spenders(self):
        VALID_SIGHASHES = [SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY + SIGHASH_ALL,
                SIGHASH_ANYONECANPAY + SIGHASH_NONE, SIGHASH_ANYONECANPAY + SIGHASH_SINGLE]
        spenders = []

        # Two features: No annex, and annex with random number of random bytes.
        for annex in [None, bytes([ANNEX_TAG]) + random_bytes(random.randrange(0, 250))]:
            # Non-empty annex is non-standard
            no_annex = annex is None
            sec1, sec2 = generate_privkey(), generate_privkey()
            pub1, _ = compute_xonly_pubkey(sec1)
            pub2, _ = compute_xonly_pubkey(sec2)

            # Sighash mutation tests (test all sighash combinations)
            for hashtype in VALID_SIGHASHES:
                # Pure pubkey
                info = taproot_construct(pub1)
                # As an example, comment argument under this line means "Sighash test for p2tr, spent through taproot key".
                spender_sighash_mutation(spenders, info, "sighash/pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=no_annex)
                # Pubkey/P2PK script combination
                scripts = [CScript(random_checksig_style(pub2))]
                info = taproot_construct(pub1, scripts)
                # As an example, comment argument under this line means "Sighash test for p2pk script in p2tr pubkey, spent through taproot key".
                spender_sighash_mutation(spenders, info, "sighash/p2pk#pk", key=sec1, hashtype=hashtype, annex=annex, standard=no_annex)
                # As an example, comment argument under this line means "Sighash test for p2pk script in p2tr pubkey, spent through p2pk key".
                spender_sighash_mutation(spenders, info, "sighash/p2pk#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=no_annex)

            # For more complex scripts only test one sighash type
            hashtype = random.choice(VALID_SIGHASHES)
            scripts = [
                CScript(random_checksig_style(pub2) + bytes([OP_CODESEPARATOR])),  # codesep after checksig
                CScript(bytes([OP_CODESEPARATOR]) + random_checksig_style(pub2)),  # codesep before checksig
                CScript([bytes([1,2,3]), OP_DROP, OP_IF, OP_CODESEPARATOR, pub1, OP_ELSE, OP_CODESEPARATOR, pub2, OP_ENDIF, OP_CHECKSIG]),  # branch dependent codesep
            ]
            info = taproot_construct(pub1, scripts)
            spender_sighash_mutation(spenders, info, "sighash/codesep#pk", key=sec1, hashtype=hashtype, annex=annex, standard=no_annex)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s0", script=scripts[0], key=sec2, hashtype=hashtype, annex=annex, standard=no_annex)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s1", script=scripts[1], key=sec2, hashtype=hashtype, annex=annex, pos=0, standard=no_annex)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s2a", script=scripts[2], key=sec1, hashtype=hashtype, annex=annex, pos=3, suffix=[bytes([1])], standard=no_annex)
            spender_sighash_mutation(spenders, info, "sighash/codesep#s2b", script=scripts[2], key=sec2, hashtype=hashtype, annex=annex, pos=6, suffix=[bytes([])], standard=no_annex)

            # Taproot max Merkle path length
            scripts = [
                CScript([pub2, OP_CHECKSIG]),
                [
                    CScript([pub1, OP_CHECKSIG]),
                    CScript([OP_RETURN])
                ]
            ]
            info = taproot_construct(pub1, nested_script(scripts, 127))
            spender_two_paths(spenders, info, "taproot/merklelimit", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0]}, failure={"key": sec1, "hashtype": hashtype, "annex": annex, "script": scripts[1][0]}, err_msg="Invalid Taproot control block size")

            # Above OP_16 to avoid minimal encoding complaints
            checksigadd_val = random.randrange(17, 100)
            checksigadd_arg = CScriptNum(checksigadd_val)
            checksigadd_result = CScriptNum(checksigadd_val+1)

            # Illegally-large number for script arithmetic input
            oversize_number = 2**31
            assert_equal(len(CScriptNum.encode(CScriptNum(oversize_number))), 6)
            assert_equal(len(CScriptNum.encode(CScriptNum(oversize_number-1))), 5)

            # Various BIP342 features
            scripts = [
                # 0) drop stack element and OP_CHECKSIG
                CScript([OP_DROP, pub2, OP_CHECKSIG]),
                # 1) normal OP_CHECKSIG
                CScript([pub2, OP_CHECKSIG]),
                # 2) normal OP_CHECKSIGVERIFY
                CScript([pub2, OP_CHECKSIGVERIFY, OP_1]),
                # 3) Hypothetical OP_CHECKMULTISIG script that takes a single sig as input
                CScript([OP_0, OP_SWAP, OP_1, pub2, OP_1, OP_CHECKMULTISIG]),
                # 4) Hypothetical OP_CHECKMULTISIGVERIFY script that takes a single sig as input
                CScript([OP_0, OP_SWAP, OP_1, pub2, OP_1, OP_CHECKMULTISIGVERIFY, OP_1]),
                # 5) OP_IF script that needs a true input
                CScript([OP_IF, pub2, OP_CHECKSIG, OP_ELSE, OP_RETURN, OP_ENDIF]),
                # 6) OP_NOTIF script that needs a true input
                CScript([OP_NOTIF, OP_RETURN, OP_ELSE, pub2, OP_CHECKSIG, OP_ENDIF]),
                # 7) OP_CHECKSIG with an empty key
                CScript([OP_0, OP_CHECKSIG]),
                # 8) OP_CHECKSIGVERIFY with an empty key
                CScript([OP_0, OP_CHECKSIGVERIFY, OP_1]),
                # 9) normal OP_CHECKSIGADD that also ensures return value is correct
                CScript([OP_0, pub2, OP_CHECKSIGADD, OP_1, OP_EQUAL]),
                # 10) OP_CHECKSIGADD with empty key
                CScript([OP_0, OP_0, OP_CHECKSIGADD]),
                # 11) OP_CHECKSIGADD with missing counter stack element
                CScript([pub2, OP_CHECKSIGADD]),
                # 12) OP_CHECKSIG that needs invalid signature
                CScript([pub2, OP_CHECKSIGVERIFY, pub1, OP_CHECKSIG, OP_NOT]),
                # 13) OP_CHECKSIG with empty key that needs invalid signature
                CScript([pub2, OP_CHECKSIGVERIFY, OP_0, OP_CHECKSIG, OP_NOT]),
                # 14) OP_CHECKSIGADD that needs invalid signature
                CScript([pub2, OP_CHECKSIGVERIFY, OP_0, pub1, OP_CHECKSIGADD, OP_NOT]),
                # 15) OP_CHECKSIGADD with empty key that needs invalid signature
                CScript([pub2, OP_CHECKSIGVERIFY, OP_0, OP_0, OP_CHECKSIGADD, OP_NOT]),
                # 16) OP_CHECKSIG with unknown pubkey type
                CScript([OP_1, OP_CHECKSIG]),
                # 17) OP_CHECKSIGADD with unknown pubkey type
                CScript([OP_0, OP_1, OP_CHECKSIGADD]),
                # 18) OP_CHECKSIGVERIFY with unknown pubkey type
                CScript([OP_1, OP_CHECKSIGVERIFY, OP_1]),
                # 19) script longer than 10000 bytes and over 201 non-push opcodes
                CScript([OP_0, OP_0, OP_2DROP] * 10001 + [pub2, OP_CHECKSIG]),
                # 20) OP_CHECKSIGVERIFY with empty key
                CScript([pub2, OP_CHECKSIGVERIFY, OP_0, OP_0, OP_CHECKSIGVERIFY, OP_1]),
                # 21) Script that grows the stack to 1000 elements
                CScript([pub2, OP_CHECKSIGVERIFY, OP_1] + [OP_DUP] * 999 + [OP_DROP] * 999),
                # 22) Script that grows the stack to 1001 elements
                CScript([pub2, OP_CHECKSIGVERIFY, OP_1] + [OP_DUP] * 1000 + [OP_DROP] * 1000),
                # 23) Script that expects an input stack of 1000 elements
                CScript([OP_DROP] * 999 + [pub2, OP_CHECKSIG]),
                # 24) Script that expects an input stack of 1001 elements
                CScript([OP_DROP] * 1000 + [pub2, OP_CHECKSIG]),
                # 25) Script that pushes a 520 byte element
                CScript([random_bytes(520), OP_DROP, pub2, OP_CHECKSIG]),
                # 26) Script that pushes a 521 byte element
                CScript([random_bytes(521), OP_DROP, pub2, OP_CHECKSIG]),
                # 27) Script that pushes a 521 byte element and OP_SUCCESSX
                CScript([random_bytes(521), OP_DROP, pub2, OP_CHECKSIG, random_op_success()]),
                # 28) Pushes random CScriptNum value, checks OP_CHECKSIGADD result
                CScript([checksigadd_arg, pub2, OP_CHECKSIGADD, checksigadd_result, OP_EQUAL]),
                # 30) CHECKSIGADD that succeeds with proper sig because numeric argument number is <=4 bytes
                CScript([CScriptNum(oversize_number-1), pub2, OP_CHECKSIGADD]),
                # 29) CHECKSIGADD that must fail because numeric argument number is >4 bytes
                CScript([CScriptNum(oversize_number), pub2, OP_CHECKSIGADD]),
            ]
            # For the next test we must predict the exact witness size
            witness_size = 141 + (hashtype != 0) + (0 if annex is None else len(annex) + 1)
            checks = (witness_size + 50) // 48
            scripts2 = [
                # 0) Script with variable number of duplicated signature checks
                CScript([pub2, OP_SWAP, OP_1SUB, OP_IF, OP_2DUP, OP_CHECKSIGVERIFY, OP_ENDIF] + [OP_2DUP, OP_CHECKSIGVERIFY] * (checks - 1) + [OP_CHECKSIG])
            ]
            info = taproot_construct(pub1, scripts)
            info2 = taproot_construct(pub1, scripts2)
            # Test that 520 byte stack element inputs are valid, but 521 byte ones are not.
            spender_two_paths(spenders, info, "tapscript/input520limit", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(520)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]}, err_msg="Push value size limit exceeded")
            # Test that 80 byte stack element inputs are valid and standard; 81 bytes ones are valid and nonstandard
            spender_two_paths(spenders, info, "tapscript/input80limit", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(80)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]}, err_msg="Push value size limit exceeded")
            spender_two_paths(spenders, info, "tapscript/input81limit", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(81)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[0], "suffix": [random_bytes(521)]}, err_msg="Push value size limit exceeded")
            # Test that OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY cause failure, but OP_CHECKSIG and OP_CHECKSIGVERIFY work.
            spender_two_paths(spenders, info, "tapscript/disabled/checkmultisig", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[1]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[3]}, err_msg="Attempted to use a disabled opcode")
            spender_two_paths(spenders, info, "tapscript/disabled/checkmultisigverify", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[2]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[4]}, err_msg="Attempted to use a disabled opcode")
            # Test that OP_IF and OP_NOTIF do not accept 0x02 as truth value (the MINIMALIF rule is consensus in Tapscript)
            spender_two_paths(spenders, info, "tapscript/minimalif", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[5], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[5], "suffix": [bytes([2])]}, err_msg="OP_IF/NOTIF argument must be minimal")
            spender_two_paths(spenders, info, "tapscript/minimalnotif", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[6], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[6], "suffix": [bytes([3])]}, err_msg="OP_IF/NOTIF argument must be minimal")
            # Test that 1-byte public keys (which are unknown) are acceptable but nonstandard with unrelated signatures, but 0-byte public keys are not valid.
            spender_two_paths(spenders, info, "tapscript/unkpk/checksig", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[16]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/unkpk/checksigadd", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[17]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[10]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/unkpk/checksigverify", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[18]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[8]}, err_msg="Public key is neither compressed or uncompressed")
            # Test that 0-byte public keys are not acceptable.
            spender_two_paths(spenders, info, "tapscript/emptypk/checksig", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[1]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/emptypk/checksigverify", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[2]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[8]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/emptypk/checksigadd", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[9]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[10]}, err_msg="Public key is neither compressed or uncompressed")
            # Test that OP_CHECKSIGADD results are as expected
            spender_two_paths(spenders, info, "tapscript/checksigaddresults", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[28]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[30]}, err_msg="unknown error")
            spender_two_paths(spenders, info, "tapscript/checksigaddoversize", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[29]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[30]}, err_msg="unknown error")
            # Test that OP_CHECKSIGADD requires 3 stack elements.
            spender_two_paths(spenders, info, "tapscript/checksigadd3args", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[9]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[11]}, err_msg="Operation not valid with the current stack size")
            # Test that empty signatures do not cause script failure in OP_CHECKSIG and OP_CHECKSIGADD (but do fail with empty pubkey, and do fail OP_CHECKSIGVERIFY)
            spender_two_paths(spenders, info, "tapscript/emptysigs/checksig", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[12], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[13], "prefix": [bytes([])]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/emptysigs/nochecksigverify", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[12], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[20], "prefix": [bytes([])]}, err_msg="Public key is neither compressed or uncompressed")
            spender_two_paths(spenders, info, "tapscript/emptysigs/checksigadd", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[14], "prefix": [bytes([])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[15], "prefix": [bytes([])]}, err_msg="Public key is neither compressed or uncompressed")
            # Test that scripts over 10000 bytes (and over 201 non-push ops) are acceptable.
            spender_two_paths(spenders, info, "tapscript/no10000limit", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[19]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[7]}, err_msg="Public key is neither compressed or uncompressed")
            # Test that the (witsize+50 >= 50*(1+sigchecks)) rule is enforced (but only for executed checksigs)
            spender_two_paths(spenders, info2, "tapscript/sigopratio", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts2[0], "suffix": [bytes([1])]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts2[0], "suffix": [bytes([2])]}, err_msg="Too much signature validation relative to witness weight")
            # Test that a stack size of 1000 elements is permitted, but 1001 isn't.
            spender_two_paths(spenders, info, "tapscript/1000stack", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[21]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[22]}, err_msg="Stack size limit exceeded")
            # Test that an input stack size of 1000 elements is permitted, but 1001 isn't.
            spender_two_paths(spenders, info, "tapscript/1000stack", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[23], "suffix": [bytes() for _ in range(999)]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[24], "suffix": [bytes() for _ in range(1000)]}, err_msg="Stack size limit exceeded")
            # Test that pushing a 520 byte stack element is valid, but a 521 byte one is not.
            spender_two_paths(spenders, info, "tapscript/push520limit", standard=no_annex, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[25]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[26]}, err_msg="Push value size limit exceeded")
            # ... unless there exists an OP_SUCCESSX somewhere in the script
            spender_two_paths(spenders, info, "tapscript/push520limit", standard=False, success={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[27]}, failure={"key": sec2, "hashtype": hashtype, "annex": annex, "script": scripts[26]}, err_msg="Push value size limit exceeded")


            # OP_SUCCESSx and unknown leaf versions
            scripts = [
                CScript([random_op_success()]),
                CScript([OP_0, OP_IF, random_op_success(), OP_RETURN]),
                CScript([random_op_success(), OP_VERIF]),
                (random_unknown_leaf_ver(), CScript([OP_RETURN])),
                (ANNEX_TAG & 0xfe, CScript()),
                # 5) Script that pushes beyond the script length, bypassing OP_SUCCESSX
                CScript([OP_PUSHDATA1, OP_2, random_op_success()]),
                # 6) Script that pushes beyond the script length, after OP_SUCCESSX
                CScript([random_op_success(), OP_PUSHDATA1]),
            ]
            info = taproot_construct(pub1, scripts)
            spender_sighash_mutation(spenders, info, "alwaysvalid/pk", key=sec1, hashtype=random.choice(VALID_SIGHASHES), annex=annex, standard=no_annex)
            spender_alwaysvalid(spenders, info, "alwaysvalid/success", script=scripts[0], annex=annex, err_msg="Witness program hash mismatch")
            spender_alwaysvalid(spenders, info, "alwaysvalid/success#if", script=scripts[1], annex=annex, err_msg="Witness program hash mismatch")
            spender_alwaysvalid(spenders, info, "alwaysvalid/success#verif", script=scripts[2], annex=annex, err_msg="Witness program hash mismatch")
            spender_alwaysvalid(spenders, info, "alwaysvalid/unknownversion#return", script=scripts[3], annex=annex, err_msg="Witness program hash mismatch")
            spender_alwaysvalid_p2sh(spenders, info, "alwaysvalid/success/p2sh", standard=False, script=scripts[0], err_msg="Operation not valid with the current stack size")
            # Test that OP_SUCCESSX works when hit before unparseable script opcode, but not after.
            spender_two_paths_alwaysvalid(spenders, info, "alwaysvalid/unparsesuccess", standard=False, success={"script":scripts[6]}, failure={"script":scripts[5]}, err_msg="Opcode missing or not understood")

            if (info[2][scripts[4][1]][0] != ANNEX_TAG):
                # Annex is mandatory for control block with leaf version 0x50
                spender_alwaysvalid(spenders, info, "alwaysvalid/unknownversion#fe", script=scripts[4], annex=annex, err_msg="Witness program hash mismatch")

        return spenders

    def run_test(self):
        # Run all tests once with individual inputs
        spenders = self.build_spenders()
        self.test_spenders(spenders, input_counts=[1])

        # Run 10 instances of all tests in groups of 2, 3, and 4 inputs.
        spenders = []
        for i in range(10):
            spenders += self.build_spenders()
        self.test_spenders(spenders, input_counts=[2, 3, 4])

if __name__ == '__main__':
    TaprootTest().main()
