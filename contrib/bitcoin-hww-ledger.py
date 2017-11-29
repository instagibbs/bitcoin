#!/usr/bin/env python2
import sys
from jsonrpc import JSONRPCResponseManager, Dispatcher
import logging
import json
from btchip.btchip import *
from btchip.btchipUtils import *
import struct
import base64

'''
NOTE: This file should be placed in the base datadir

xpub can be derived using https://www.ledgerwallet.com/api/demo.html or any other standard tool

btchip python library can be found here https://github.com/LedgerHQ/btchip-python
or installed with `pip install btchip-python`
'''

# Keypath prepend, based on xpub path
#keypath_start = "44'/0'/0'"
keypath_start = "0'/0'/0'/0'"

def signhwwtransaction(txtosign, prevtxstospend):
    tx = json.loads(txtosign)
    prevtxs = json.loads(prevtxstospend)

    # Load Ledger dongle
    dongle = getDongle(True)
    app = btchip(dongle)

    # Get prevout information (for now we support p2pk(h))

    # Get keypaths of things you're spending, prepend m/44'/0'/0'
    keypaths = []
    prevouts = []
    input_types = []
    input_pubkeys = []
    sequence_numbers = []
    for vin in tx["vin"]:
        if "hdKeypath" not in vin:
            raise Exception("All inputs must be signable by this seed.")
            keypaths.append("")
        else:
            keypaths.append(keypath_start+vin["hdKeypath"][1:])

        pubkey_bytes = compress_public_key(app.getWalletPublicKey(keypaths[-1])["publicKey"])
        input_pubkeys.append(pubkey_bytes)

        prevouts.append((vin["txid"], vin["vout"]))
        input_type = None
        for prevtx in prevtxs:
            if vin["txid"] == prevtx["txid"]:
                input_type = prevtx["vout"][vin["vout"]]["scriptPubKey"]["type"]
                break
        input_types.append(input_type)

        seq = format(vin["sequence"], 'x')
        seq = seq.zfill(len(seq)+len(seq)%2)
        seq = bytearray(seq.decode('hex'))
        seq.reverse()
        seq = ''.join('{:02x}'.format(x) for x in seq)
        sequence_numbers.append(seq)

    # Define change if possible
    change_path = "0'/0'/0'/1'"
    for output in tx["vout"]:
        if "hdKeypath" in output:
            change_path = keypath_start+output["hdKeypath"][1:]
            break

    # Build trusted inputs
    prevoutScriptPubkey = []
    outputData = ""
    trusted_inputs = []
    signatures = [[]]*len(prevouts)

    tx_bytes = bytearray(tx["hex"].decode('hex'))

    # Compile trusted inputs for non-segwit signing
    for i in range(len(prevouts)):
        inputTransaction = bitcoinTransaction(bytearray(prevtxs[i]["hex"].decode('hex')))
        trusted_inputs.append(app.getTrustedInput(inputTransaction, prevouts[i][1]))
        trusted_inputs[-1]["sequence"] = sequence_numbers[i]
        prevoutScriptPubkey.append(inputTransaction.outputs[prevouts[i][1]].script)

    newTx = True
    # Now we legacy sign the transaction, input by input
    for i in range(len(prevouts)):
        signature = []
        prevoutscript = prevoutScriptPubkey[i]
        app.startUntrustedTransaction(newTx, i, trusted_inputs, prevoutscript, tx["version"])
        newTx = False
        outputData = app.finalizeInput("DUMMY", -1, -1, change_path, tx_bytes)
        # Provide the key that is signing the input
        signature.append(app.untrustedHashSign(keypaths[i], "", tx["locktime"], 0x01))
        signatures[i] = signature

    input_scripts = []
    for i in range(len(signatures)):
        if input_types[i] == "pubkeyhash":
            input_scripts.append(get_regular_input_script(signatures[i][0], input_pubkeys[i]))
        elif input_types[i] == "pubkey":
            input_scripts.append(get_p2pk_input_script(signatures[i][0]))
        else:
            raise Exception("Only p2pkh and p2pk supported at this time.")

    processed_inputs = trusted_inputs

    trusted_inputs_and_scripts = []
    for processed_input, input_script in zip(processed_inputs, input_scripts):
        trusted_inputs_and_scripts.append([processed_input['value'], input_script, sequence_numbers[i]])

    transaction = format_transaction(outputData['outputData'], trusted_inputs_and_scripts, tx["version"], tx["locktime"])
    transaction_hex = ''.join('{:02x}'.format(x) for x in transaction)

    publength = []
    for pubkey in input_pubkeys:
        publength.append(len(pubkey))

    input_lengths = []
    for input in input_scripts:
        input_lengths.append(len(input))

    # Write to file as workaround
    file = open("writeout.txt", 'w')
    file.write(transaction_hex)
    file.close()

    return { "hex": transaction_hex}

def signmessage(keypathjson, messagejson):

    keypath = keypathjson#json.loads(keypathjson)
    message = messagejson#json.loads(messagejson)

    dongle = getDongle(True)
    app = btchip(dongle)

    total_keypath = keypath_start+keypath[1:]

    app.getWalletPublicKey(total_keypath, True)

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

def validateaddress(keypath):
    dongle = getDongle(True)
    app = btchip(dongle)

    total_keypath = keypath_start+keypath[1:]

    app.getWalletPublicKey(total_keypath, True)

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
