// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/sigcache.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>

#include <array>
#include <cstddef>
#include <optional>
#include <vector>

void initialize_script_sigcache()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

FUZZ_TARGET(script_sigcache, .init = initialize_script_sigcache)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const auto max_sigcache_bytes{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, DEFAULT_SIGNATURE_CACHE_BYTES)};
    SignatureCache signature_cache{max_sigcache_bytes};

    const std::optional<CMutableTransaction> mutable_transaction = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
    const CTransaction tx{mutable_transaction ? *mutable_transaction : CMutableTransaction{}};
    const unsigned int n_in = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    const CAmount amount = ConsumeMoney(fuzzed_data_provider);
    const bool store = fuzzed_data_provider.ConsumeBool();
    PrecomputedTransactionData tx_data;
    CachingTransactionSignatureChecker caching_transaction_signature_checker{mutable_transaction ? &tx : nullptr, n_in, amount, store, signature_cache, tx_data};
    if (fuzzed_data_provider.ConsumeBool()) {
        const auto random_bytes = fuzzed_data_provider.ConsumeBytes<unsigned char>(64);
        const XOnlyPubKey pub_key(ConsumeUInt256(fuzzed_data_provider));
        if (random_bytes.size() == 64) {
            (void)caching_transaction_signature_checker.VerifySchnorrSignature(random_bytes, pub_key, ConsumeUInt256(fuzzed_data_provider));
        }
    } else {
        const auto random_bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        const auto pub_key = ConsumeDeserializable<CPubKey>(fuzzed_data_provider);
        if (pub_key) {
            if (!random_bytes.empty()) {
                (void)caching_transaction_signature_checker.VerifyECDSASignature(random_bytes, *pub_key, ConsumeUInt256(fuzzed_data_provider));
            }
        }
    }

    FuzzedDataProvider valid_provider(buffer.data(), buffer.size());
    const CKey key{ConsumePrivateKey(valid_provider, /*compressed=*/true)};
    if (!key.IsValid()) return;

    SignatureCache valid_cache{/*max_size_bytes=*/1024};
    SignatureCache fallback_cache{/*max_size_bytes=*/1024};
    PrecomputedTransactionData valid_tx_data;
    CachingTransactionSignatureChecker storing_checker{nullptr, 0, 0, /*store=*/true, valid_cache, valid_tx_data};
    CachingTransactionSignatureChecker nonstoring_checker{nullptr, 0, 0, /*store=*/false, valid_cache, valid_tx_data};
    CachingTransactionSignatureChecker fallback_checker{nullptr, 0, 0, /*store=*/false, fallback_cache, valid_tx_data};
    const uint256 sighash{ConsumeUInt256(valid_provider)};
    uint256 wrong_sighash{sighash};
    wrong_sighash.begin()[0] ^= 1;

    {
        std::vector<unsigned char> signature;
        Assert(key.Sign(sighash, signature));
        const CPubKey pubkey{key.GetPubKey()};
        uint256 entry;
        valid_cache.ComputeEntryECDSA(entry, sighash, signature, pubkey);
        uint256 fallback_entry;
        fallback_cache.ComputeEntryECDSA(fallback_entry, sighash, signature, pubkey);

        Assert(!fallback_cache.Get(fallback_entry, /*erase=*/false));
        Assert(fallback_checker.VerifyECDSASignature(signature, pubkey, sighash));
        Assert(!fallback_cache.Get(fallback_entry, /*erase=*/false));
        Assert(storing_checker.VerifyECDSASignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(!storing_checker.VerifyECDSASignature(signature, pubkey, wrong_sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(nonstoring_checker.VerifyECDSASignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(nonstoring_checker.VerifyECDSASignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        signature.assign(1, 0);
        Assert(!storing_checker.VerifyECDSASignature(signature, pubkey, sighash));
    }

    {
        std::array<unsigned char, 64> signature;
        Assert(key.SignSchnorr(sighash, signature, /*merkle_root=*/nullptr, ConsumeUInt256(valid_provider)));
        const XOnlyPubKey pubkey{key.GetPubKey()};
        uint256 entry;
        valid_cache.ComputeEntrySchnorr(entry, sighash, signature, pubkey);
        uint256 fallback_entry;
        fallback_cache.ComputeEntrySchnorr(fallback_entry, sighash, signature, pubkey);

        Assert(!fallback_cache.Get(fallback_entry, /*erase=*/false));
        Assert(fallback_checker.VerifySchnorrSignature(signature, pubkey, sighash));
        Assert(!fallback_cache.Get(fallback_entry, /*erase=*/false));
        Assert(storing_checker.VerifySchnorrSignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(!storing_checker.VerifySchnorrSignature(signature, pubkey, wrong_sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(nonstoring_checker.VerifySchnorrSignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        Assert(nonstoring_checker.VerifySchnorrSignature(signature, pubkey, sighash));
        Assert(valid_cache.Get(entry, /*erase=*/false));
        signature.fill(0xff);
        Assert(!storing_checker.VerifySchnorrSignature(signature, pubkey, sighash));
    }
}
