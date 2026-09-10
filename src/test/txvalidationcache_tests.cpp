// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <key.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

struct Dersig100Setup : public TestChain100Setup {
    Dersig100Setup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-testactivationheight=dersig@102"}}} {}
};

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, CachePolicy sig_cache_policy,
                       CachePolicy script_cache_policy, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests)

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, Dersig100Setup)
{
    // Make sure skipping validation of transactions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    const auto ToMemPool = [this](const CMutableTransaction& tx) {
        LOCK(cs_main);

        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID;
    };

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].version = 1;
        spends[i].vin = {CTxIn{m_coinbase_txns[0]->GetHash(), 0}};
        spends[i].vout = {CTxOut{11*CENT, scriptPubKey}};

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[0]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[1]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Final sanity test: first spend in *m_node.mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    }
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

// Run CheckInputScripts (using CoinsTip()) on the given transaction, for all script
// flags.  Test that CheckInputScripts passes for all flags that don't overlap with
// the failing_flags argument, but otherwise fails.
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY (and future NOP codes that may
// get reassigned) have an interaction with DISCOURAGE_UPGRADABLE_NOPS: if
// the script flags used contain DISCOURAGE_UPGRADABLE_NOPS but don't contain
// CHECKLOCKTIMEVERIFY (or CHECKSEQUENCEVERIFY), but the script does contain
// OP_CHECKLOCKTIMEVERIFY (or OP_CHECKSEQUENCEVERIFY), then script execution
// should fail.
static void ValidateCheckInputsForAllFlags(const CTransaction &tx, script_verify_flags failing_flags, bool add_to_cache, CCoinsViewCache& active_coins_tip, ValidationCache& validation_cache) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    PrecomputedTransactionData txdata;

    FastRandomContext insecure_rand(true);

    for (int count = 0; count < 10000; ++count) {
        TxValidationState state;

        // Randomly selects flag combinations
        script_verify_flags test_flags = script_verify_flags::from_int(insecure_rand.randrange(MAX_SCRIPT_VERIFY_FLAGS));

        // Filter out incompatible flag choices
        if ((test_flags & SCRIPT_VERIFY_CLEANSTACK)) {
            // CLEANSTACK requires P2SH and WITNESS, see VerifyScript() in
            // script/interpreter.cpp
            test_flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_TAPROOT)) {
            // TAPROOT requires WITNESS
            test_flags |= SCRIPT_VERIFY_WITNESS;
        }
        if ((test_flags & SCRIPT_VERIFY_WITNESS)) {
            // WITNESS requires P2SH
            test_flags |= SCRIPT_VERIFY_P2SH;
        }
        bool ret = CheckInputScripts(tx, state, &active_coins_tip, test_flags, CachePolicy::STORE, add_to_cache ? CachePolicy::STORE : CachePolicy::CONSUME, txdata, validation_cache, nullptr);
        // CheckInputScripts should succeed iff test_flags doesn't intersect with
        // failing_flags
        bool expected_return_value = !(test_flags & failing_flags);
        BOOST_CHECK_EQUAL(ret, expected_return_value);

        // Test the caching
        if (ret && add_to_cache) {
            // Check that we get a cache hit if the tx was valid
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, CachePolicy::STORE, add_to_cache ? CachePolicy::STORE : CachePolicy::CONSUME, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK(scriptchecks.empty());
        } else {
            // Check that we get script executions to check, if the transaction
            // was invalid, or we didn't add to cache.
            std::vector<CScriptCheck> scriptchecks;
            BOOST_CHECK(CheckInputScripts(tx, state, &active_coins_tip, test_flags, CachePolicy::STORE, add_to_cache ? CachePolicy::STORE : CachePolicy::CONSUME, txdata, validation_cache, &scriptchecks));
            BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
        }
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, Dersig100Setup)
{
    // Test that passing CheckInputScripts with one set of script flags doesn't imply
    // that we would pass again with a different set of flags.
    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CScript p2sh_scriptPubKey = GetScriptForDestination(ScriptHash(p2pk_scriptPubKey));
    CScript p2pkh_scriptPubKey = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CScript p2wpkh_scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CScript p2tr_scriptPubKey = GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey(coinbaseKey.GetPubKey())));

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(coinbaseKey));
    BOOST_CHECK(keystore.AddCScript(p2pk_scriptPubKey));

    // flags to test: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCE_VERIFY, SCRIPT_VERIFY_NULLDUMMY, uncompressed pubkey thing

    // Create 2 outputs that match the three scripts above, spending the first
    // coinbase tx.
    CMutableTransaction spend_tx;

    spend_tx.version = 1;
    spend_tx.vin = {CTxIn{m_coinbase_txns[0]->GetHash(), 0}};
    spend_tx.vout = {
        CTxOut{11*CENT, p2sh_scriptPubKey},
        CTxOut{11*CENT, p2wpkh_scriptPubKey},
        CTxOut{11*CENT, CScript() << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG},
        CTxOut{11*CENT, CScript() << OP_CHECKSEQUENCEVERIFY << OP_DROP << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG},
        CTxOut{11*CENT, p2tr_scriptPubKey},
    };

    // Sign, with a non-DER signature
    {
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(p2pk_scriptPubKey, spend_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char) 0); // padding byte makes this non-DER
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spend_tx.vin[0].scriptSig << vchSig;
    }

    // Test that invalidity under a set of flags doesn't preclude validity
    // under other (eg consensus) flags.
    // spend_tx is invalid according to DERSIG
    {
        LOCK(cs_main);

        TxValidationState state;
        PrecomputedTransactionData ptd_spend_tx;

        BOOST_CHECK(!CheckInputScripts(CTransaction(spend_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, CachePolicy::STORE, CachePolicy::STORE, ptd_spend_tx, m_node.chainman->m_validation_cache, nullptr));

        // If we call again asking for scriptchecks (as happens in
        // ConnectBlock), we should add a script check object for this -- we're
        // not caching invalidity (if that changes, delete this test case).
        std::vector<CScriptCheck> scriptchecks;
        BOOST_CHECK(CheckInputScripts(CTransaction(spend_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, CachePolicy::STORE, CachePolicy::STORE, ptd_spend_tx, m_node.chainman->m_validation_cache, &scriptchecks));
        BOOST_CHECK_EQUAL(scriptchecks.size(), 1U);

        // Test that CheckInputScripts returns true iff DERSIG-enforcing flags are
        // not present.  Don't add these checks to the cache, so that we can
        // test later that block validation works fine in the absence of cached
        // successes.
        ValidateCheckInputsForAllFlags(CTransaction(spend_tx), SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC, false, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // And if we produce a block with this tx, it should be valid (DERSIG not
    // enabled yet), even though there's no cache entry.
    CBlock block;

    block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);
    LOCK(cs_main);
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(m_node.chainman->ActiveChainstate().CoinsTip().GetBestBlock() == block.GetHash());

    // Test P2SH: construct a transaction that is valid without P2SH, and
    // then test validity with P2SH.
    {
        CMutableTransaction invalid_under_p2sh_tx;
        invalid_under_p2sh_tx.version = 1;
        invalid_under_p2sh_tx.vin = {CTxIn{spend_tx.GetHash(), 0}};
        invalid_under_p2sh_tx.vout = {CTxOut{11*CENT, p2pk_scriptPubKey}};
        std::vector<unsigned char> vchSig2(p2pk_scriptPubKey.begin(), p2pk_scriptPubKey.end());
        invalid_under_p2sh_tx.vin[0].scriptSig << vchSig2;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_under_p2sh_tx), SCRIPT_VERIFY_P2SH, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // Test CHECKLOCKTIMEVERIFY
    {
        CMutableTransaction invalid_with_cltv_tx;
        invalid_with_cltv_tx.version = 1;
        invalid_with_cltv_tx.nLockTime = 100;
        invalid_with_cltv_tx.vin = {CTxIn{spend_tx.GetHash(), 2, {}, /*nSequenceIn=*/0}};
        invalid_with_cltv_tx.vout = {CTxOut{11*CENT, p2pk_scriptPubKey}};

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[2].scriptPubKey, invalid_with_cltv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_cltv_tx), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_cltv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_cltv_tx), state, m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, CachePolicy::STORE, CachePolicy::STORE, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TEST CHECKSEQUENCEVERIFY
    {
        CMutableTransaction invalid_with_csv_tx;
        invalid_with_csv_tx.version = 2;
        invalid_with_csv_tx.vin = {CTxIn{spend_tx.GetHash(), 3, {}, /*nSequenceIn=*/100}};
        invalid_with_csv_tx.vout = {CTxOut{11*CENT, p2pk_scriptPubKey}};

        // Sign
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(spend_tx.vout[3].scriptPubKey, invalid_with_csv_tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 101;

        ValidateCheckInputsForAllFlags(CTransaction(invalid_with_csv_tx), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Make it valid, and check again
        invalid_with_csv_tx.vin[0].scriptSig = CScript() << vchSig << 100;
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(CTransaction(invalid_with_csv_tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, CachePolicy::STORE, CachePolicy::STORE, txdata, m_node.chainman->m_validation_cache, nullptr));
    }

    // TODO: add tests for remaining script flags

    // Test that passing CheckInputScripts with a valid witness doesn't imply success
    // for the same tx with a different witness.
    {
        CMutableTransaction valid_with_witness_tx;
        valid_with_witness_tx.version = 1;
        valid_with_witness_tx.vin = {CTxIn{spend_tx.GetHash(), 1}};
        valid_with_witness_tx.vout = {CTxOut{11*CENT, p2pk_scriptPubKey}};

        // Sign
        SignatureData sigdata;
        BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(valid_with_witness_tx, 0, 11 * CENT, {.sighash_type = SIGHASH_DEFAULT}), spend_tx.vout[1].scriptPubKey, sigdata));
        UpdateInput(valid_with_witness_tx.vin[0], sigdata);

        // This should be valid under all script flags.
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Remove the witness, and check that it is now invalid.
        valid_with_witness_tx.vin[0].scriptWitness.SetNull();
        ValidateCheckInputsForAllFlags(CTransaction(valid_with_witness_tx), SCRIPT_VERIFY_WITNESS, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    // Test a Taproot (witness v1) key-path spend, to exercise the Schnorr branch of the signature cache.
    {
        CMutableTransaction tr_tx;
        tr_tx.vin = {CTxIn{spend_tx.GetHash(), 4}};
        tr_tx.vout = {CTxOut{11*CENT, p2pk_scriptPubKey}};

        // Sign P2TR output for key-path spending (i.e. add Schnorr signature to witness stack)
        FlatSigningProvider tr_keystore;
        tr_keystore.keys.emplace(coinbaseKey.GetPubKey().GetID(), coinbaseKey);
        const std::map<COutPoint, Coin> coins{
            {tr_tx.vin[0].prevout, Coin(spend_tx.vout[4], /*nHeightIn=*/0, /*fCoinBaseIn=*/false)}
        };
        std::map<int, bilingual_str> input_errors;
        BOOST_REQUIRE(SignTransaction(tr_tx, &tr_keystore, coins, {.sighash_type = SIGHASH_DEFAULT}, input_errors));
        auto& witness_stack = tr_tx.vin[0].scriptWitness.stack;
        BOOST_REQUIRE(witness_stack.size() == 1 && witness_stack[0].size() == 64);

        // Invalidate signature; an invalid Taproot key-path spend is only invalid if SCRIPT_VERIFY_TAPROOT is set
        witness_stack[0][63] ^= 0x01; // damage signature
        ValidateCheckInputsForAllFlags(CTransaction(tr_tx), SCRIPT_VERIFY_TAPROOT, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
        witness_stack[0][63] ^= 0x01; // repair signature

        // A valid Taproot key-path spend is valid under all flags
        ValidateCheckInputsForAllFlags(CTransaction(tr_tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    {
        // Test a transaction with multiple inputs.
        CMutableTransaction tx;

        tx.version = 1;
        tx.vin = {
            CTxIn{spend_tx.GetHash(), 0},
            CTxIn{spend_tx.GetHash(), 1},
        };
        tx.vout = {CTxOut{22*CENT, p2pk_scriptPubKey}};

        // Sign
        for (int i = 0; i < 2; ++i) {
            SignatureData sigdata;
            BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(tx, i, 11 * CENT, {.sighash_type = SIGHASH_DEFAULT}), spend_tx.vout[i].scriptPubKey, sigdata));
            UpdateInput(tx.vin[i], sigdata);
        }

        // This should be valid under all script flags
        ValidateCheckInputsForAllFlags(CTransaction(tx), 0, true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

        // Check that if the second input is invalid, but the first input is
        // valid, the transaction is not cached.
        // Invalidate vin[1]
        tx.vin[1].scriptWitness.SetNull();

        TxValidationState state;
        PrecomputedTransactionData txdata;
        // This transaction is now invalid under segwit, because of the second input.
        BOOST_CHECK(!CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, CachePolicy::STORE, CachePolicy::STORE, txdata, m_node.chainman->m_validation_cache, nullptr));

        std::vector<CScriptCheck> scriptchecks;
        // Make sure this transaction was not cached (ie because the first
        // input was valid)
        BOOST_CHECK(CheckInputScripts(CTransaction(tx), state, &m_node.chainman->ActiveChainstate().CoinsTip(), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, CachePolicy::STORE, CachePolicy::STORE, txdata, m_node.chainman->m_validation_cache, &scriptchecks));
        // Should get 2 script checks back -- caching is on a whole-transaction basis.
        BOOST_CHECK_EQUAL(scriptchecks.size(), 2U);
    }
}

BOOST_FIXTURE_TEST_CASE(test_accept_leaves_no_cache_footprint, TestChain100Setup)
{
    // A test_accept must not leave the transaction's inputs in the coins cache, nor its
    // signatures and scripts in the validation caches: that state would record that this node
    // validated the transaction before it was broadcast.
    const CScript p2wpkh{GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()))};
    const CTransactionRef tx{MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/1, coinbaseKey, p2wpkh, /*output_amount=*/1 * COIN, /*submit=*/false))};
    const COutPoint prevout{tx->vin[0].prevout};
    const CTxOut& spent{m_coinbase_txns[0]->vout[0]};

    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    ValidationCache& vcache{m_node.chainman->m_validation_cache};

    // Cache keys as computed by CheckInputScripts() and CachingTransactionSignatureChecker.
    const auto script_entry = [&](script_verify_flags flags) {
        uint256 entry;
        CSHA256 hasher{vcache.ScriptExecutionCacheHasher()};
        hasher.Write(UCharCast(tx->GetWitnessHash().begin()), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(entry.begin());
        return entry;
    };
    const uint256 policy_entry{script_entry(STANDARD_SCRIPT_VERIFY_FLAGS)};
    const uint256 consensus_entry{WITH_LOCK(cs_main, return script_entry(GetBlockScriptFlags(*chainstate.m_chain.Tip(), *m_node.chainman)))};
    uint256 sig_entry;
    {
        std::vector<unsigned char> sig;
        opcodetype opcode;
        CScript::const_iterator pc{tx->vin[0].scriptSig.begin()};
        BOOST_REQUIRE(tx->vin[0].scriptSig.GetOp(pc, opcode, sig));
        const int hash_type{sig.back()};
        sig.pop_back();
        const uint256 sighash{SignatureHash(spent.scriptPubKey, *tx, /*nIn=*/0, hash_type, spent.nValue, SigVersion::BASE)};
        vcache.m_signature_cache.ComputeEntryECDSA(sig_entry, sighash, sig, coinbaseKey.GetPubKey());
    }

    // Inputs that were already cached stay cached: only coins fetched by the test_accept are uncached.
    (void)WITH_LOCK(cs_main, return chainstate.CoinsTip().AccessCoin(prevout));
    BOOST_REQUIRE(chainstate.CoinsTip().HaveCoinInCache(prevout));
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(tx, /*test_accept=*/true)};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK(chainstate.CoinsTip().HaveCoinInCache(prevout));

    // Make the input cold so that validation has to fetch it.
    chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true);
    BOOST_REQUIRE(!chainstate.CoinsTip().HaveCoinInCache(prevout));
    BOOST_REQUIRE(!vcache.m_signature_cache.Get(sig_entry, /*erase=*/false));
    BOOST_REQUIRE(!vcache.m_script_execution_cache.contains(policy_entry, /*erase=*/false));
    BOOST_REQUIRE(!vcache.m_script_execution_cache.contains(consensus_entry, /*erase=*/false));

    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(tx, /*test_accept=*/true)};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoinInCache(prevout));
    BOOST_CHECK(!vcache.m_signature_cache.Get(sig_entry, /*erase=*/false));
    BOOST_CHECK(!vcache.m_script_execution_cache.contains(policy_entry, /*erase=*/false));
    BOOST_CHECK(!vcache.m_script_execution_cache.contains(consensus_entry, /*erase=*/false));

    // Real acceptance does populate the caches, so the checks above are not vacuous.
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(tx, /*test_accept=*/false)};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK(chainstate.CoinsTip().HaveCoinInCache(prevout));
    BOOST_CHECK(vcache.m_signature_cache.Get(sig_entry, /*erase=*/false));
    BOOST_CHECK(vcache.m_script_execution_cache.contains(consensus_entry, /*erase=*/false));
}

BOOST_FIXTURE_TEST_CASE(test_accept_leaves_no_cache_footprint_schnorr_and_package, TestChain100Setup)
{
    // The same guarantee for the other cache-writing paths: a Schnorr (taproot key-path)
    // signature, and the package form of testmempoolaccept.
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    ValidationCache& vcache{m_node.chainman->m_validation_cache};
    const CScript p2wpkh{GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()))};

    const auto script_entry = [&](const CTransaction& tx, script_verify_flags flags) {
        uint256 entry;
        CSHA256 hasher{vcache.ScriptExecutionCacheHasher()};
        hasher.Write(UCharCast(tx.GetWitnessHash().begin()), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(entry.begin());
        return entry;
    };
    const auto consensus_flags = [&] { return WITH_LOCK(cs_main, return GetBlockScriptFlags(*chainstate.m_chain.Tip(), *m_node.chainman)); };
    const auto script_cached = [&](const CTransaction& tx) {
        return vcache.m_script_execution_cache.contains(script_entry(tx, STANDARD_SCRIPT_VERIFY_FLAGS), /*erase=*/false) ||
               vcache.m_script_execution_cache.contains(script_entry(tx, consensus_flags()), /*erase=*/false);
    };
    const auto sig_cached = [&](const uint256& entry) { return vcache.m_signature_cache.Get(entry, /*erase=*/false); };
    const auto make_cold = [&] { chainstate.ForceFlushStateToDisk(/*wipe_cache=*/true); };

    // --- Taproot key-path spend of a confirmed P2TR output.
    mineBlocks(2); // coinbases 1 and 2 (heights 2 and 3) must be mature when spent below
    const int height_before{WITH_LOCK(cs_main, return chainstate.m_chain.Height())};
    const XOnlyPubKey internal_key{coinbaseKey.GetPubKey()};
    const auto output_key{internal_key.CreateTapTweak(/*merkle_root=*/nullptr)};
    BOOST_REQUIRE(output_key.has_value());
    const CMutableTransaction fund{CreateValidMempoolTransaction(m_coinbase_txns[1], /*input_vout=*/0, /*input_height=*/2, coinbaseKey,
                                                                 GetScriptForDestination(WitnessV1Taproot(output_key->first)), 10 * COIN, /*submit=*/false)};
    CreateAndProcessBlock({fund}, p2wpkh);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return chainstate.m_chain.Height()), height_before + 1);
    CMutableTransaction spend_mtx;
    spend_mtx.vin.emplace_back(COutPoint{fund.GetHash(), 0});
    spend_mtx.vout.emplace_back(9 * COIN, p2wpkh);
    uint256 schnorr_sighash;
    {
        PrecomputedTransactionData txdata;
        txdata.Init(spend_mtx, {fund.vout[0]}, /*force=*/true); // the witness is not in place yet
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        BOOST_REQUIRE(SignatureHashSchnorr(schnorr_sighash, execdata, spend_mtx, /*in_pos=*/0, SIGHASH_DEFAULT, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
    }
    std::vector<unsigned char> schnorr_sig(64);
    const uint256 no_scripts{};
    BOOST_REQUIRE(coinbaseKey.SignSchnorr(schnorr_sighash, schnorr_sig, &no_scripts, uint256{}));
    spend_mtx.vin[0].scriptWitness.stack.push_back(schnorr_sig);
    const CTransactionRef spend{MakeTransactionRef(spend_mtx)};
    const COutPoint spend_prevout{spend->vin[0].prevout};
    uint256 schnorr_entry;
    vcache.m_signature_cache.ComputeEntrySchnorr(schnorr_entry, schnorr_sighash, schnorr_sig, output_key->first);

    make_cold();
    BOOST_REQUIRE(!chainstate.CoinsTip().HaveCoinInCache(spend_prevout));
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(spend, /*test_accept=*/true)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
    }
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoinInCache(spend_prevout));
    BOOST_CHECK(!sig_cached(schnorr_entry));
    BOOST_CHECK(!script_cached(*spend));
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(spend, /*test_accept=*/false)};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK(chainstate.CoinsTip().HaveCoinInCache(spend_prevout));
    BOOST_CHECK(sig_cached(schnorr_entry));
    BOOST_CHECK(script_cached(*spend));

    // --- Package test_accept: a parent spending a coinbase and a child spending the parent.
    const CTransactionRef parent{MakeTransactionRef(CreateValidMempoolTransaction(m_coinbase_txns[2], /*input_vout=*/0, /*input_height=*/3, coinbaseKey, p2wpkh, 10 * COIN, /*submit=*/false))};
    const CTransactionRef child{MakeTransactionRef(CreateValidMempoolTransaction(parent, /*input_vout=*/0, /*input_height=*/102, coinbaseKey, p2wpkh, 9 * COIN, /*submit=*/false))};
    const COutPoint parent_prevout{parent->vin[0].prevout};
    uint256 parent_sig_entry, child_sig_entry;
    {
        // Parent: P2PK scriptSig, base sighash.
        std::vector<unsigned char> sig;
        opcodetype opcode;
        CScript::const_iterator pc{parent->vin[0].scriptSig.begin()};
        BOOST_REQUIRE(parent->vin[0].scriptSig.GetOp(pc, opcode, sig));
        const int hash_type{sig.back()};
        sig.pop_back();
        const CTxOut& spent{m_coinbase_txns[2]->vout[0]};
        const uint256 sighash{SignatureHash(spent.scriptPubKey, *parent, /*nIn=*/0, hash_type, spent.nValue, SigVersion::BASE)};
        vcache.m_signature_cache.ComputeEntryECDSA(parent_sig_entry, sighash, sig, coinbaseKey.GetPubKey());
    }
    {
        // Child: P2WPKH witness, segwit v0 sighash over the implied scriptCode.
        const auto& stack{child->vin[0].scriptWitness.stack};
        BOOST_REQUIRE_EQUAL(stack.size(), 2U);
        std::vector<unsigned char> sig{stack[0]};
        const int hash_type{sig.back()};
        sig.pop_back();
        const CPubKey pubkey{stack[1]};
        const CScript script_code{CScript{} << OP_DUP << OP_HASH160 << ToByteVector(WitnessV0KeyHash(pubkey)) << OP_EQUALVERIFY << OP_CHECKSIG};
        const uint256 sighash{SignatureHash(script_code, *child, /*nIn=*/0, hash_type, parent->vout[0].nValue, SigVersion::WITNESS_V0)};
        vcache.m_signature_cache.ComputeEntryECDSA(child_sig_entry, sighash, sig, pubkey);
    }
    const Package package{parent, child};

    make_cold();
    BOOST_REQUIRE(!chainstate.CoinsTip().HaveCoinInCache(parent_prevout));
    {
        LOCK(cs_main);
        const auto result{ProcessNewPackage(chainstate, *m_node.mempool, package, /*test_accept=*/true, /*client_maxfeerate=*/std::nullopt)};
        BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
        for (const auto& tx : package) {
            BOOST_REQUIRE(result.m_tx_results.at(tx->GetWitnessHash()).m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
    }
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoinInCache(parent_prevout));
    BOOST_CHECK(!sig_cached(parent_sig_entry));
    BOOST_CHECK(!sig_cached(child_sig_entry));
    BOOST_CHECK(!script_cached(*parent));
    BOOST_CHECK(!script_cached(*child));
    {
        LOCK(cs_main);
        const auto result{ProcessNewPackage(chainstate, *m_node.mempool, package, /*test_accept=*/false, /*client_maxfeerate=*/std::nullopt)};
        BOOST_REQUIRE_MESSAGE(result.m_state.IsValid(), result.m_state.ToString());
    }
    BOOST_CHECK(chainstate.CoinsTip().HaveCoinInCache(parent_prevout));
    BOOST_CHECK(sig_cached(parent_sig_entry));
    BOOST_CHECK(sig_cached(child_sig_entry));
    BOOST_CHECK(script_cached(*parent));
    BOOST_CHECK(script_cached(*child));
}

BOOST_FIXTURE_TEST_CASE(test_accept_does_not_mark_cached_signatures, TestChain100Setup)
{
    // Not inserting is not enough: a signature already in the cache before the test_accept must
    // not be marked for eviction by it either, because the mark changes what survives later
    // insertions, which is observable state. Eviction is lazy, so the test forces it with an
    // insertion that collides with the entry's first bucket.
    mineBlocks(1); // coinbase 1 (height 2) must be mature
    const CTransactionRef tx{MakeTransactionRef(CreateValidMempoolTransaction(
        {m_coinbase_txns[0], m_coinbase_txns[1]},
        {COutPoint{m_coinbase_txns[0]->GetHash(), 0}, COutPoint{m_coinbase_txns[1]->GetHash(), 0}},
        /*input_height=*/2, {coinbaseKey, coinbaseKey},
        {CTxOut{COIN, GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()))}}, /*submit=*/false))};
    SignatureCache& cache{m_node.chainman->m_validation_cache.m_signature_cache};

    // The cache entry of input 0's signature. Other inputs' scriptSigs are not covered by this
    // signature's hash, so the same entry serves any transaction differing only there.
    uint256 entry;
    {
        std::vector<unsigned char> sig;
        opcodetype opcode;
        CScript::const_iterator pc{tx->vin[0].scriptSig.begin()};
        BOOST_REQUIRE(tx->vin[0].scriptSig.GetOp(pc, opcode, sig));
        const int hash_type{sig.back()};
        sig.pop_back();
        const CTxOut& spent{m_coinbase_txns[0]->vout[0]};
        const uint256 sighash{SignatureHash(spent.scriptPubKey, *tx, /*nIn=*/0, hash_type, spent.nValue, SigVersion::BASE)};
        cache.ComputeEntryECDSA(entry, sighash, sig, coinbaseKey.GetPubKey());
    }
    // Entries that share the entry's first bucket (the buckets are read from consecutive 32-bit
    // windows of the entry) and nothing else: inserting one evicts the entry only if it was marked.
    const auto colliding = [&](int byte) {
        uint256 c{entry};
        c.begin()[byte] ^= 0xff;
        return c;
    };

    // An ordinary, invalid submission primes the signature: input 0 verifies and is stored before
    // input 1 fails.
    CMutableTransaction partial{*tx};
    partial.vin[1].scriptSig.clear();
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(MakeTransactionRef(partial), /*test_accept=*/false)};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    }
    BOOST_REQUIRE(cache.Get(entry, /*erase=*/false));

    // Control: an unmarked entry survives a colliding insertion.
    cache.Set(colliding(4));
    BOOST_REQUIRE(cache.Get(entry, /*erase=*/false));

    // A test_accept of the complete transaction hits the entry and must leave it unmarked.
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(tx, /*test_accept=*/true)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID, result.m_state.ToString());
    }
    BOOST_REQUIRE(cache.Get(entry, /*erase=*/false)); // lazy: present either way
    cache.Set(colliding(5));
    BOOST_CHECK(cache.Get(entry, /*erase=*/false)); // still present: the test_accept did not mark it

    // The mechanism is real: a consuming lookup marks the entry and the next collision evicts it.
    BOOST_REQUIRE(cache.Get(entry, /*erase=*/true));
    cache.Set(colliding(6));
    BOOST_CHECK(!cache.Get(entry, /*erase=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
