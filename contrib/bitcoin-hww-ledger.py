#!/usr/bin/env python2
import sys
from jsonrpc import JSONRPCResponseManager, Dispatcher
import logging
import json
from btchip.btchip import *
from btchip.btchipUtils import *
import struct
import base64
import hashlib

'''
NOTE: This file should be placed in the base datadir

xpub can be derived using https://www.ledgerwallet.com/api/demo.html or any other standard tool

btchip python library can be found here https://github.com/LedgerHQ/btchip-python
or installed with `pip install btchip-python`
'''

# TODO: get these upstreamed to btchip-python
def format_transaction(dongleOutputData, trustedInputsAndInputScripts, version=0x01, lockTime=0, trusted=True, witness=""):
        transaction = bitcoinTransaction()
        transaction.version = []
        transaction.witnessScript = witness
        transaction.witness = True if witness != "" else False
        writeUint32LE(version, transaction.version)
        for item in trustedInputsAndInputScripts:
                newInput = bitcoinInput()
                newInput.prevOut = item[0][4:4+36] if trusted else item[0][:36]
                newInput.script = item[1]
                if len(item) > 2:
                        newInput.sequence = bytearray(item[2].decode('hex'))
                else:
                        newInput.sequence = bytearray([0xff, 0xff, 0xff, 0xff])
                transaction.inputs.append(newInput)
        result = transaction.serialize(True)
        result.extend(dongleOutputData)
        if witness != "":
            result.extend(witness)
        writeUint32LE(lockTime, result)
        return bytearray(result)

def get_witness_keyhash_witness(signature, pubkey):
    result = []
    writeVarint(len(signature), result)
    result.extend(signature)
    writeVarint(len(pubkey), result)
    result.extend(pubkey)
    return bytearray(result)

def build_witness_stack(witnesses):
    witness = bytearray()
    for i in range(len(witnesses)):
        writeVarint((2 if len(witnesses[i]) != 0 else 0), witness)
        if len(witnesses[i]) != 0:
            witness.extend(witnesses[i])
    return witness

# Keypath prepend, based on xpub path
keypath_start = "44'/0'/0'"

def signhwwtransaction(txtosign, prevtxstospend):
    tx = json.loads(txtosign)
    prevtxs = json.loads(prevtxstospend)

    # Load Ledger dongle
    dongle = getDongle(True)
    app = btchip(dongle)

    # Get keypaths of things you're spending, prepend m/44'/0'/0'
    keypaths = []
    prevouts = []
    input_types = []
    input_pubkeys = []
    sequence_numbers = []
    # only for segwit
    input_amounts = []
    for vin in tx["vin"]:
        if "hdKeypath" not in vin or len(vin["hdKeypath"]) == 0:
            keypaths.append("")
            input_pubkeys.append("")
        else:
            keypaths.append(keypath_start+vin["hdKeypath"][1:])
            pubkey_bytes = compress_public_key(app.getWalletPublicKey(keypaths[-1])["publicKey"])
            input_pubkeys.append(pubkey_bytes)


        prevouts.append((vin["txid"], vin["vout"]))
        input_type = None
        input_amount = -1
        for prevtx in prevtxs:
            if vin["txid"] == prevtx["txid"]:
                input_type = prevtx["vout"][vin["vout"]]["scriptPubKey"]["type"]
                input_amount = prevtx["vout"][vin["vout"]]["value"]
                break

        input_types.append(input_type)
        input_amounts.append(input_amount)

        seq = format(vin["sequence"], 'x')
        seq = seq.zfill(len(seq)+len(seq)%2)
        seq = bytearray(seq.decode('hex'))
        seq.reverse()
        seq = ''.join('{:02x}'.format(x) for x in seq)
        sequence_numbers.append(seq)

    # Define change if possible
    change_path = "0'/0'/0'/1'"
    for output in tx["vout"]:
        if "hdKeypath" in output and len(output["hdKeypath"]) != 0:
            # Core marks anything not in address book as change... make sure it's 1/k
            if output["hdKeypath"].split('/')[-2] != '1':
                continue
            change_path = keypath_start+output["hdKeypath"][1:]
            break

    # Build trusted(legacy) and segwit inputs
    prevoutScriptPubkey = []
    outputData = ""
    trusted_inputs = []
    segwit_inputs = []
    signatures = [[]]*len(prevouts)
    input_scripts = [""]*len(prevouts)

    tx_bytes = bytearray(tx["hex"].decode('hex'))

    has_legacy = False
    has_segwit = False

    # Any input with a keypath will be signed
    # Anytime a key is passed in, p2sh is assumed to be p2sh-p2wpkh
    for i in range(len(prevouts)):
        if keypaths[i] == "":
            continue
        if input_types[i] == "pubkeyhash" or input_types[i] == "pubkey":
            has_legacy = True
        elif input_types[i] == "scripthash" or input_types[i] == "witness_v0_keyhash":
            has_segwit = True
        else:
            raise Exception("Unsupported input type for signing: "+input_types[i])

    assert(has_legacy or has_segwit)

    if has_legacy:
        # Compile trusted inputs for non-segwit signing
        for i in range(len(prevouts)):
            inputTransaction = bitcoinTransaction(bytearray(prevtxs[i]["hex"].decode('hex')))
            trusted_inputs.append(app.getTrustedInput(inputTransaction, prevouts[i][1]))
            trusted_inputs[-1]["sequence"] = sequence_numbers[i]
            prevoutScriptPubkey.append(inputTransaction.outputs[prevouts[i][1]].script)

        newTx = True
        # Now we legacy sign the transaction, input by input for the ones we know
        for i in range(len(prevouts)):
            signature = []
            prevoutscript = prevoutScriptPubkey[i]
            app.startUntrustedTransaction(newTx, i, trusted_inputs, prevoutscript, tx["version"])
            newTx = False
            outputData = app.finalizeInput("DUMMY", -1, -1, change_path, tx_bytes)
            if keypaths[i] == "":
                input_scripts[i] = bytearray(tx["vin"][i]["scriptSig"]["hex"].decode('hex'))
                continue
            # Provide the key that is signing the input
            signature.append(app.untrustedHashSign(keypaths[i], "", tx["locktime"], 0x01))
            if input_types[i] != "pubkeyhash" and input_types[i] != "pubkey":
                continue
            signatures[i] = signature

            # We're signing everything we can, tossing what's unneeded
            if input_types[i] == "pubkeyhash":
                input_scripts[i] = get_regular_input_script(signatures[i][0], input_pubkeys[i])
            elif input_types[i] == "pubkey":
                input_scripts[i] = get_p2pk_input_script(signatures[i][0])

    witnesses = [bytearray(0x00)]*len(prevouts)
    if has_segwit:
        # Build segwit inputs
        for i in range(len(prevouts)):
            if input_amounts[i] == -1:
                raise Exception("Not all input amounts given for a segwit tx")
            txid = bytearray(prevouts[i][0].decode('hex'))
            txid.reverse()
            vout = prevouts[i][1]
            amount = input_amounts[i]
            segwit_inputs.append({"value":txid+struct.pack("<I", vout)+struct.pack("<Q", int(amount*100000000)), "witness":True, "sequence":sequence_numbers[i]})

        newTx = True
        # Process them front with all inputs
        prevoutscript = bytearray()
        for i in range(len(prevouts)):
            app.startUntrustedTransaction(newTx, i, segwit_inputs, prevoutscript, tx["version"])
            newTx = False

        # Then finalize, and process each input as a single-input transaction
        outputData = app.finalizeInput("DUMMY", -1, -1, change_path, tx_bytes)
        # Sign segwit inputs
        for i in range(len(prevouts)):
            if keypaths[i] == "":
                input_scripts[i] = bytearray(tx["vin"][i]["scriptSig"]["hex"].decode('hex'))
                continue

            if input_types[i] != "scripthash" and input_types[i] != "witness_v0_keyhash":
                continue

            signature = []
            # For p2wpkh, we need to convert the script into something sensible to the ledger:
            # OP_DUP OP_HASH160 <program> OP_EQUALVERIFY OP_CHECKSIG

            # Compute keyhash
            sha2 = hashlib.sha256()
            sha2.update(input_pubkeys[i])
            riped = hashlib.new('ripemd160')
            riped.update(sha2.digest())
            key_hash = riped.digest()

            redeemscript = bytearray("0014".decode('hex'))+key_hash
            sha2 = hashlib.sha256()
            sha2.update(redeemscript)
            riped = hashlib.new('ripemd160')
            riped.update(sha2.digest())
            script_hash = riped.digest()
            scriptCode = bytearray("76a914".decode('hex'))+key_hash+bytearray("88ac".decode("hex"))

            app.startUntrustedTransaction(newTx, 0, [segwit_inputs[i]], scriptCode, tx["version"])
            signature.append(app.untrustedHashSign(keypaths[i], "", tx["locktime"], 0x01))
            signatures[i] = signature

            if input_types[i] == "scripthash":
                # Just the redeemscript, we need to insert the signature to witness
                inputScript = bytearray()
                write_pushed_data_size(redeemscript, inputScript)
                inputScript.extend(redeemscript)
                input_scripts[i] = inputScript
                witnesses[i] = get_witness_keyhash_witness(signatures[i][0], input_pubkeys[i])
            elif input_types[i] == "witness_v0_keyhash":
                input_scripts[i] = ""
                witnesses[i] = get_witness_keyhash_witness(signatures[i][0], input_pubkeys[i])

    witness = bytearray()
    if has_segwit:
        witness = build_witness_stack(witnesses)

    processed_inputs = segwit_inputs if has_segwit else trusted_inputs

    trusted_inputs_and_scripts = []
    for processed_input, input_script in zip(processed_inputs, input_scripts):
        trusted_inputs_and_scripts.append([processed_input['value'], input_script, sequence_numbers[i]])

    transaction = format_transaction(outputData['outputData'], trusted_inputs_and_scripts, tx["version"], tx["locktime"], not has_segwit, witness)
    transaction_hex = ''.join('{:02x}'.format(x) for x in transaction)

    # Write to file as workaround
    file = open("writeout.txt", 'w')
    file.write(transaction_hex)
    file.close()

    return { "hex": transaction_hex}

def signmessage(keypathjson, messagejson, segwit, native):

    keypath = keypathjson
    message = messagejson

    dongle = getDongle(True)
    app = btchip(dongle)

    total_keypath = keypath_start+keypath[1:]

    app.getWalletPublicKey(total_keypath, True, segwit, native)

    app.signMessagePrepare(total_keypath, bytearray(message, 'utf8'))

    signature = app.signMessageSign()

    # Convert signature to Bitcoin "standard"
    rLength = signature[3]
    r = signature[4 : 4 + rLength]
    sLength = signature[4 + rLength + 1]
    s = signature[4 + rLength + 2:]
    if rLength == 33:
        r = r[1:]
    if sLength == 33:
        s = s[1:]
    r = str(r)
    s = str(s)

    sig = chr(27 + 4 + (signature[0] & 0x01)) + r + s

    # Write to file as workaround
    file = open("writeout.txt", 'w')
    file.write(base64.b64encode(sig))
    file.close()

    return {"signature":base64.b64encode(sig)}

def validateaddress(keypath, segwit, native):
    dongle = getDongle(True)
    app = btchip(dongle)

    total_keypath = keypath_start+keypath[1:]

    app.getWalletPublicKey(total_keypath, True, segwit, native)

    return {}

dispatcher = Dispatcher({
    "signhwwtransaction": signhwwtransaction,
    "signmessage": signmessage,
    "validateaddress": validateaddress
})

logging.basicConfig()
request = sys.stdin.read()
response = JSONRPCResponseManager.handle(request, dispatcher)
print(response.json)
