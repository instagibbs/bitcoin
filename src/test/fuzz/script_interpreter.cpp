// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

bool CastToBool(const std::vector<unsigned char>& vch);

FUZZ_TARGET(script_interpreter)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    {
        const CScript script_code = ConsumeScript(fuzzed_data_provider);
        const std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
        if (mtx) {
            const CTransaction tx_to{*mtx};
            const unsigned int in = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
            if (in < tx_to.vin.size()) {
                auto n_hash_type = fuzzed_data_provider.ConsumeIntegral<int>();
                auto amount = ConsumeMoney(fuzzed_data_provider);
                auto sigversion = fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0});
                (void)SignatureHash(script_code, tx_to, in, n_hash_type, amount, sigversion, nullptr);
                const std::optional<CMutableTransaction> mtx_precomputed = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
                if (mtx_precomputed) {
                    const CTransaction tx_precomputed{*mtx_precomputed};
                    const PrecomputedTransactionData precomputed_transaction_data{tx_precomputed};
                    n_hash_type = fuzzed_data_provider.ConsumeIntegral<int>();
                    amount = ConsumeMoney(fuzzed_data_provider);
                    sigversion = fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0});
                    (void)SignatureHash(script_code, tx_to, in, n_hash_type, amount, sigversion, &precomputed_transaction_data);
                }
            }
        }
    }
    {
        (void)CastToBool(ConsumeRandomLengthByteVector(fuzzed_data_provider));
    }
}

/** Differential fuzzing for SignatureHash with and without cache. */
FUZZ_TARGET(sighash_cache)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    const auto scriptcode{ConsumeScript(provider)};
    const CMutableTransaction mutable_tx{ConsumeTransaction(provider, std::nullopt)};
    const CTransaction tx{mutable_tx};
    if (tx.vin.empty()) return;
    const auto in_index{provider.ConsumeIntegralInRange<uint32_t>(0, tx.vin.size() - 1)};
    const auto amount{ConsumeMoney(provider)};

    PrecomputedTransactionData precomputed;
    precomputed.Init(tx, {}, /*force=*/true);
    PrecomputedTransactionData mutable_precomputed;
    mutable_precomputed.Init(mutable_tx, {}, /*force=*/true);
    Assert(precomputed.m_bip143_segwit_ready);
    Assert(mutable_precomputed.m_bip143_segwit_ready);

    CScript alternate_script{scriptcode};
    alternate_script << OP_1;
    const std::array<int32_t, 9> fixed_hash_types{
        SIGHASH_ALL,
        SIGHASH_SINGLE,
        SIGHASH_NONE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        0,
        std::numeric_limits<int32_t>::max(),
        std::numeric_limits<int32_t>::min(),
    };
    std::vector<int32_t> hash_types{fixed_hash_types.begin(), fixed_hash_types.end()};
    for (int index{0}; index < 100; ++index) {
        hash_types.push_back((index & 2) == 0 ? provider.ConsumeIntegral<int8_t>() : provider.ConsumeIntegral<int32_t>());
    }

    CMutableTransaction authorization_mutation{tx};
    for (CTxIn& input : authorization_mutation.vin) {
        input.scriptSig << OP_1;
        input.scriptWitness.stack.push_back({0x01});
    }

    for (const SigVersion sigversion : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        SigHashCache cache;
        SigHashCache combined_cache;
        for (size_t index{0}; index < hash_types.size(); ++index) {
            const int32_t hash_type{hash_types[index]};
            const CScript& active_script{index % 2 == 0 ? scriptcode : alternate_script};
            const uint256 expected{SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion)};

            Assert(SignatureHash(active_script, mutable_tx, in_index, hash_type, amount, sigversion) == expected);
            Assert(SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion, &precomputed) == expected);
            Assert(SignatureHash(active_script, mutable_tx, in_index, hash_type, amount, sigversion, &mutable_precomputed) == expected);
            Assert(SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion, nullptr, &cache) == expected);
            Assert(SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion, nullptr, &cache) == expected);
            Assert(SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion, &precomputed, &combined_cache) == expected);
            Assert(SignatureHash(active_script, tx, in_index, hash_type, amount, sigversion, &precomputed, &combined_cache) == expected);

            if (sigversion == SigVersion::BASE) {
                const CAmount alternate_amount{amount == MAX_MONEY ? amount - 1 : amount + 1};
                Assert(SignatureHash(active_script, tx, in_index, hash_type, alternate_amount, sigversion) == expected);
            }
        }

        for (const int32_t hash_type : fixed_hash_types) {
            Assert(SignatureHash(scriptcode, authorization_mutation, in_index, hash_type, amount, sigversion) ==
                   SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion));
        }

        CMutableTransaction no_outputs{tx};
        no_outputs.vout.clear();
        for (const int32_t hash_type : std::array<int32_t, 2>{SIGHASH_NONE, SIGHASH_NONE | SIGHASH_ANYONECANPAY}) {
            Assert(SignatureHash(scriptcode, no_outputs, in_index, hash_type, amount, sigversion) ==
                   SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion));
        }

        CMutableTransaction extra_input{tx};
        extra_input.vin.emplace_back();
        for (const int32_t hash_type : {SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                                       SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
                                       SIGHASH_NONE | SIGHASH_ANYONECANPAY}) {
            Assert(SignatureHash(scriptcode, extra_input, in_index, hash_type, amount, sigversion) ==
                   SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion));
        }

        if (in_index < tx.vout.size()) {
            CMutableTransaction single_output{tx};
            single_output.vout.resize(in_index + 1);
            for (uint32_t index{0}; index < in_index; ++index) {
                single_output.vout[index] = CTxOut{0, CScript{} << OP_RETURN};
            }
            for (const int32_t hash_type : std::array<int32_t, 2>{SIGHASH_SINGLE, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY}) {
                Assert(SignatureHash(scriptcode, single_output, in_index, hash_type, amount, sigversion) ==
                       SignatureHash(scriptcode, tx, in_index, hash_type, amount, sigversion));
            }
        } else if (sigversion == SigVersion::BASE) {
            Assert(SignatureHash(scriptcode, tx, in_index, SIGHASH_SINGLE, amount, sigversion) == uint256::ONE);
            Assert(SignatureHash(scriptcode, tx, in_index, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, amount, sigversion) == uint256::ONE);
        }
    }

    CScript with_separator;
    with_separator << OP_1 << OP_CODESEPARATOR << OP_2;
    CScript without_separator;
    without_separator << OP_1 << OP_2;
    for (const int32_t hash_type : fixed_hash_types) {
        Assert(SignatureHash(with_separator, tx, in_index, hash_type, amount, SigVersion::BASE) ==
               SignatureHash(without_separator, tx, in_index, hash_type, amount, SigVersion::BASE));
    }
}
