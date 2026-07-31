// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <key.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/keyorigin.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/transaction_utils.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/translation.h>

#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

void initialize_script_sign()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET(script_sign, .init = initialize_script_sign)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const std::vector<uint8_t> key = ConsumeRandomLengthByteVector(fuzzed_data_provider, 128);

    {
        DataStream random_data_stream{ConsumeDataStream(fuzzed_data_provider)};
        std::map<CPubKey, KeyOriginInfo> hd_keypaths;
        try {
            DeserializeHDKeypaths(random_data_stream, key, hd_keypaths);
        } catch (const std::ios_base::failure&) {
        }
        DataStream serialized{};
        SerializeHDKeypaths(serialized, hd_keypaths, CompactSizeWriter(fuzzed_data_provider.ConsumeIntegral<uint8_t>()));
    }

    {
        std::map<CPubKey, KeyOriginInfo> hd_keypaths;
        LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 10000) {
            const std::optional<CPubKey> pub_key = ConsumeDeserializable<CPubKey>(fuzzed_data_provider);
            if (!pub_key) {
                break;
            }
            const std::optional<KeyOriginInfo> key_origin_info = ConsumeDeserializable<KeyOriginInfo>(fuzzed_data_provider);
            if (!key_origin_info) {
                break;
            }
            hd_keypaths[*pub_key] = *key_origin_info;
        }
        DataStream serialized{};
        try {
            SerializeHDKeypaths(serialized, hd_keypaths, CompactSizeWriter(fuzzed_data_provider.ConsumeIntegral<uint8_t>()));
        } catch (const std::ios_base::failure&) {
        }
        std::map<CPubKey, KeyOriginInfo> deserialized_hd_keypaths;
        try {
            DeserializeHDKeypaths(serialized, key, deserialized_hd_keypaths);
        } catch (const std::ios_base::failure&) {
        }
        assert(hd_keypaths.size() >= deserialized_hd_keypaths.size());
    }

    {
        SignatureData signature_data_1{ConsumeScript(fuzzed_data_provider)};
        SignatureData signature_data_2{ConsumeScript(fuzzed_data_provider)};
        signature_data_1.MergeSignatureData(signature_data_2);
    }

    FillableSigningProvider provider;
    CKey k = ConsumePrivateKey(fuzzed_data_provider);
    if (k.IsValid()) {
        provider.AddKey(k);
    }

    {
        const std::optional<CMutableTransaction> mutable_transaction = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
        const std::optional<CTxOut> tx_out = ConsumeDeserializable<CTxOut>(fuzzed_data_provider);
        const unsigned int n_in = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
        if (mutable_transaction && tx_out && mutable_transaction->vin.size() > n_in) {
            SignatureData signature_data_1 = DataFromTransaction(*mutable_transaction, n_in, *tx_out);
            CTxIn input;
            UpdateInput(input, signature_data_1);
            const CScript script = ConsumeScript(fuzzed_data_provider);
            SignatureData signature_data_2{script};
            signature_data_1.MergeSignatureData(signature_data_2);
        }
        if (mutable_transaction) {
            CTransaction tx_from{*mutable_transaction};
            CMutableTransaction tx_to;
            const std::optional<CMutableTransaction> opt_tx_to = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
            if (opt_tx_to) {
                tx_to = *opt_tx_to;
            }
            CMutableTransaction script_tx_to = tx_to;
            CMutableTransaction sign_transaction_tx_to = tx_to;
            if (n_in < tx_to.vin.size() && tx_to.vin[n_in].prevout.n < tx_from.vout.size()) {
                SignatureData empty;
                (void)SignSignature(provider, tx_from, tx_to, n_in, fuzzed_data_provider.ConsumeIntegral<int>(), empty);
            }
            if (n_in < script_tx_to.vin.size()) {
                SignatureData empty;
                auto from_pub_key = ConsumeScript(fuzzed_data_provider);
                auto amount = ConsumeMoney(fuzzed_data_provider);
                auto n_hash_type = fuzzed_data_provider.ConsumeIntegral<int>();
                (void)SignSignature(provider, from_pub_key, script_tx_to, n_in, amount, n_hash_type, empty);
                MutableTransactionSignatureCreator signature_creator{tx_to, n_in, ConsumeMoney(fuzzed_data_provider), {.sighash_type = fuzzed_data_provider.ConsumeIntegral<int>()}};
                std::vector<unsigned char> vch_sig;
                CKeyID address;
                if (fuzzed_data_provider.ConsumeBool()) {
                    if (k.IsValid()) {
                        address = k.GetPubKey().GetID();
                    }
                } else {
                    address = CKeyID{ConsumeUInt160(fuzzed_data_provider)};
                }
                auto script_code = ConsumeScript(fuzzed_data_provider);
                auto sigversion = fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0});
                (void)signature_creator.CreateSig(provider, vch_sig, address, script_code, sigversion);
            }
            std::map<COutPoint, Coin> coins{ConsumeCoins(fuzzed_data_provider)};
            std::map<int, bilingual_str> input_errors;
            (void)SignTransaction(sign_transaction_tx_to, &provider, coins, {.sighash_type = fuzzed_data_provider.ConsumeIntegral<int>()}, input_errors);
        }
    }

    {
        SignatureData signature_data_1;
        (void)ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, ConsumeScript(fuzzed_data_provider), signature_data_1);
        SignatureData signature_data_2;
        (void)ProduceSignature(provider, DUMMY_MAXIMUM_SIGNATURE_CREATOR, ConsumeScript(fuzzed_data_provider), signature_data_2);
    }

    FuzzedDataProvider valid_provider(buffer.data(), buffer.size());
    const CKey valid_key{ConsumePrivateKey(valid_provider, /*compressed=*/true)};
    if (!valid_key.IsValid()) return;

    FillableSigningProvider valid_keys;
    Assert(valid_keys.AddKey(valid_key));
    const CPubKey pubkey{valid_key.GetPubKey()};
    const CScript p2pk{GetScriptForRawPubKey(pubkey)};
    const CScript p2pkh{GetScriptForDestination(PKHash{pubkey})};
    const CScript multisig{GetScriptForMultisig(1, {pubkey})};
    const size_t input_count{valid_provider.ConsumeIntegralInRange<size_t>(1, 4)};

    CMutableTransaction unsigned_tx;
    unsigned_tx.version = valid_provider.ConsumeIntegralInRange<int32_t>(1, 3);
    unsigned_tx.nLockTime = valid_provider.ConsumeIntegral<uint32_t>();
    std::map<COutPoint, Coin> valid_coins;
    std::vector<bool> expect_witness;
    for (size_t i = 0; i < input_count; ++i) {
        const COutPoint prevout{Txid::FromUint256(ConsumeUInt256(valid_provider)), static_cast<uint32_t>(i)};
        unsigned_tx.vin.emplace_back(prevout, CScript{}, valid_provider.ConsumeIntegral<uint32_t>());
        unsigned_tx.vout.emplace_back(0, CScript{} << OP_TRUE);

        const CScript& inner_script{valid_provider.PickValueInArray({&p2pk, &p2pkh, &multisig})[0]};
        CScript script_pubkey;
        bool is_witness{false};
        switch (valid_provider.ConsumeIntegralInRange<unsigned>(0, 5)) {
        case 0:
            script_pubkey = inner_script;
            break;
        case 1:
            Assert(valid_keys.AddCScript(inner_script));
            script_pubkey = GetScriptForDestination(ScriptHash{inner_script});
            break;
        case 2:
            Assert(valid_keys.AddCScript(inner_script));
            script_pubkey = GetScriptForDestination(WitnessV0ScriptHash{inner_script});
            is_witness = true;
            break;
        case 3: {
            Assert(valid_keys.AddCScript(inner_script));
            const CScript witness_program{GetScriptForDestination(WitnessV0ScriptHash{inner_script})};
            Assert(valid_keys.AddCScript(witness_program));
            script_pubkey = GetScriptForDestination(ScriptHash{witness_program});
            is_witness = true;
            break;
        }
        case 4:
            script_pubkey = GetScriptForDestination(WitnessV0KeyHash{pubkey});
            is_witness = true;
            break;
        case 5: {
            const CScript witness_program{GetScriptForDestination(WitnessV0KeyHash{pubkey})};
            Assert(valid_keys.AddCScript(witness_program));
            script_pubkey = GetScriptForDestination(ScriptHash{witness_program});
            is_witness = true;
            break;
        }
        }

        const CAmount amount{ConsumeMoney(valid_provider, /*max=*/MAX_MONEY - 1)};
        Assert(valid_coins.emplace(prevout, Coin{CTxOut{amount, script_pubkey}, /*height=*/1, /*coinbase=*/false}).second);
        expect_witness.push_back(is_witness);
        Assert(IsSegWitOutput(valid_keys, script_pubkey) == is_witness);
    }

    const int sighash_type{valid_provider.PickValueInArray({
        static_cast<int>(SIGHASH_ALL),
        static_cast<int>(SIGHASH_NONE),
        static_cast<int>(SIGHASH_SINGLE),
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    })};
    CMutableTransaction signed_tx{unsigned_tx};
    std::map<int, bilingual_str> signing_errors;
    Assert(SignTransaction(signed_tx, &valid_keys, valid_coins, {.sighash_type = sighash_type}, signing_errors));
    Assert(signing_errors.empty());
    Assert(signed_tx.version == unsigned_tx.version);
    Assert(signed_tx.nLockTime == unsigned_tx.nLockTime);
    Assert(signed_tx.vout == unsigned_tx.vout);
    for (size_t i = 0; i < input_count; ++i) {
        Assert(signed_tx.vin[i].prevout == unsigned_tx.vin[i].prevout);
        Assert(signed_tx.vin[i].nSequence == unsigned_tx.vin[i].nSequence);
    }

    const CTransaction tx{signed_tx};
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (const CTxIn& input : tx.vin) {
        spent_outputs.push_back(valid_coins.at(input.prevout).out);
    }
    txdata.Init(tx, std::move(spent_outputs), /*force=*/true);
    for (size_t i = 0; i < input_count; ++i) {
        const Coin& coin{valid_coins.at(tx.vin[i].prevout)};
        ScriptError error{SCRIPT_ERR_OK};
        Assert(VerifyScript(tx.vin[i].scriptSig, coin.out.scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                            TransactionSignatureChecker{&tx, static_cast<unsigned int>(i), coin.out.nValue, txdata, MissingDataBehavior::FAIL}, &error));
        Assert(tx.vin[i].scriptWitness.IsNull() == !expect_witness[i]);

        const SignatureData extracted{DataFromTransaction(signed_tx, i, coin.out)};
        Assert(extracted.complete);
        CTxIn reconstructed;
        UpdateInput(reconstructed, extracted);
        Assert(reconstructed.scriptSig == tx.vin[i].scriptSig);
        Assert(reconstructed.scriptWitness.stack == tx.vin[i].scriptWitness.stack);
    }

    const CTransaction before_resign{signed_tx};
    Assert(SignTransaction(signed_tx, &valid_keys, valid_coins, {.sighash_type = sighash_type}, signing_errors));
    Assert(signing_errors.empty());
    Assert(CTransaction{signed_tx} == before_resign);

    FillableSigningProvider empty_provider;
    CMutableTransaction missing_key_tx{unsigned_tx};
    std::map<int, bilingual_str> missing_key_errors;
    Assert(!SignTransaction(missing_key_tx, &empty_provider, valid_coins, {.sighash_type = sighash_type}, missing_key_errors));
    Assert(missing_key_errors.size() == input_count);

    FuzzedDataProvider taproot_provider(buffer.data(), buffer.size());
    const CKey taproot_key{ConsumePrivateKey(taproot_provider, /*compressed=*/true)};
    Assert(taproot_key.IsValid());
    const CPubKey taproot_pubkey{taproot_key.GetPubKey()};
    const XOnlyPubKey xonly_pubkey{taproot_pubkey};
    const bool script_path{taproot_provider.ConsumeBool()};

    FlatSigningProvider taproot_keys;
    taproot_keys.keys.emplace(taproot_pubkey.GetID(), taproot_key);
    TaprootBuilder builder;
    CScript tapleaf;
    if (script_path) {
        tapleaf = CScript{} << ToByteVector(xonly_pubkey) << OP_CHECKSIG;
        builder.Add(/*depth=*/0, tapleaf, TAPROOT_LEAF_TAPSCRIPT);
        builder.Finalize(XOnlyPubKey::NUMS_H);
    } else {
        builder.Finalize(xonly_pubkey);
    }
    Assert(builder.IsValid() && builder.IsComplete());
    const WitnessV1Taproot taproot_output{builder.GetOutput()};
    Assert(taproot_keys.tr_trees.emplace(taproot_output, builder).second);
    const CScript taproot_script{GetScriptForDestination(taproot_output)};
    Assert(IsSegWitOutput(taproot_keys, taproot_script));

    const CAmount taproot_amount{ConsumeMoney(taproot_provider, /*max=*/MAX_MONEY - 1)};
    const COutPoint taproot_prevout{Txid::FromUint256(ConsumeUInt256(taproot_provider)), 0};
    const Coin taproot_coin{CTxOut{taproot_amount, taproot_script}, /*height=*/1, /*coinbase=*/false};
    const std::map<COutPoint, Coin> taproot_coins{{taproot_prevout, taproot_coin}};
    CMutableTransaction taproot_unsigned;
    taproot_unsigned.version = taproot_provider.ConsumeIntegralInRange<int32_t>(1, 3);
    taproot_unsigned.nLockTime = taproot_provider.ConsumeIntegral<uint32_t>();
    taproot_unsigned.vin.emplace_back(taproot_prevout, CScript{}, taproot_provider.ConsumeIntegral<uint32_t>());
    taproot_unsigned.vout.emplace_back(0, CScript{} << OP_TRUE);
    const int taproot_sighash{taproot_provider.PickValueInArray({
        static_cast<int>(SIGHASH_DEFAULT),
        static_cast<int>(SIGHASH_ALL),
        static_cast<int>(SIGHASH_NONE),
        static_cast<int>(SIGHASH_SINGLE),
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    })};

    CMutableTransaction taproot_signed{taproot_unsigned};
    std::map<int, bilingual_str> taproot_errors;
    Assert(SignTransaction(taproot_signed, &taproot_keys, taproot_coins, {.sighash_type = taproot_sighash}, taproot_errors));
    Assert(taproot_errors.empty());
    Assert(taproot_signed.version == taproot_unsigned.version);
    Assert(taproot_signed.nLockTime == taproot_unsigned.nLockTime);
    Assert(taproot_signed.vin[0].prevout == taproot_unsigned.vin[0].prevout);
    Assert(taproot_signed.vin[0].nSequence == taproot_unsigned.vin[0].nSequence);
    Assert(taproot_signed.vout == taproot_unsigned.vout);
    Assert(taproot_signed.vin[0].scriptSig.empty());
    Assert(taproot_signed.vin[0].scriptWitness.stack.size() == (script_path ? 3 : 1));
    Assert(taproot_signed.vin[0].scriptWitness.stack[0].size() == (taproot_sighash == SIGHASH_DEFAULT ? 64 : 65));
    if (script_path) {
        Assert(taproot_signed.vin[0].scriptWitness.stack[1] == ToByteVector(tapleaf));
    }

    const CTransaction taproot_tx{taproot_signed};
    PrecomputedTransactionData taproot_txdata;
    taproot_txdata.Init(taproot_tx, {taproot_coin.out}, /*force=*/true);
    ScriptError taproot_error{SCRIPT_ERR_OK};
    Assert(VerifyScript(taproot_tx.vin[0].scriptSig, taproot_coin.out.scriptPubKey, &taproot_tx.vin[0].scriptWitness,
                        STANDARD_SCRIPT_VERIFY_FLAGS,
                        TransactionSignatureChecker{&taproot_tx, 0, taproot_amount, taproot_txdata, MissingDataBehavior::FAIL}, &taproot_error));

    const CTransaction before_taproot_resign{taproot_signed};
    Assert(SignTransaction(taproot_signed, &taproot_keys, taproot_coins, {.sighash_type = taproot_sighash}, taproot_errors));
    Assert(taproot_errors.empty());
    Assert(CTransaction{taproot_signed} == before_taproot_resign);

    CMutableTransaction missing_taproot_key{taproot_unsigned};
    std::map<int, bilingual_str> missing_taproot_errors;
    Assert(!SignTransaction(missing_taproot_key, &empty_provider, taproot_coins, {.sighash_type = taproot_sighash}, missing_taproot_errors));
    Assert(missing_taproot_errors.size() == 1);
}
