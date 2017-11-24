#!/usr/bin/env python2
import sys
from jsonrpc import JSONRPCResponseManager, Dispatcher
import logging
import json
from btchip.btchip import *
from btchip.btchipUtils import *
import struct

def signhwwtransaction(txtosign, prevtxstospend):
    tx = json.loads(txtosign)
    prevtxs = json.loads(prevtxstospend)

    # Load Ledger dongle
    dongle = getDongle(True)
    app = btchip(dongle)

    # Get prevout information (for now we support p2pkh)

    # Get keypaths of things you're spending, prepend m/44'/0'/0'
    keypath_start = "44'/0'/0'"
    keypaths = []
    prevouts = []
    input_types = []
    sequence_numbers = []
    for vin in tx["vin"]:
        if "hdKeypath" not in vin:
            keypaths.append("")
        else:
            keypaths.append(keypath_start+vin["hdKeypath"][1:])

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
    change_path = "0'/0'/0'/0'"
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
            input_scripts.append(get_regular_input_script(signatures[i][0], inputPubKey[i]))
        elif input_types[i] == "pubkey":
            input_scripts.append(get_p2pk_input_script(signatures[i][0]))
        else:
            raise Exception("Only p2pkh and p2pk supported at this time.")

    processed_inputs = trusted_inputs
    process_trusted = True

    trusted_inputs_and_scripts = []
    for processed_input, input_script in zip(processed_inputs, input_scripts):
        trusted_inputs_and_scripts.append([processed_input['value'], input_script, sequence_numbers[i]])

    transaction = format_transaction(outputData['outputData'], trusted_inputs_and_scripts, tx["version"], tx["locktime"], process_trusted)
    transaction_hex = ''.join('{:02x}'.format(x) for x in transaction)

    return { "hex": transaction_hex, "prehex": tx["hex"]}


dispatcher = Dispatcher({
    "signhwwtransaction": signhwwtransaction,
})

logging.basicConfig()
request = sys.stdin.read()
response = JSONRPCResponseManager.handle(request, dispatcher)
jsonout = json.loads(response.json)
txout = jsonout["result"]["hex"]
file = open("writeout.txt", 'w')
file.write(response.json+"\n")
file.write(txout)
file.close()
print(response.json)
