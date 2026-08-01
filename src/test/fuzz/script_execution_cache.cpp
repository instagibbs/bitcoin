// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <span.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

namespace {
struct InputScripts {
    CScript script_sig;
    CScript script_pubkey;
    CScriptWitness witness;
};

struct InlineResult {
    bool valid;
    TxValidationResult result;
};

struct DeferredResult {
    bool valid;
    size_t check_count;
    size_t failure_count;
};

void initialize_script_execution_cache()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

InputScripts P2SHSpend(const CScript& redeem_script)
{
    InputScripts scripts;
    scripts.script_sig = CScript{} << ToByteVector(redeem_script);
    scripts.script_pubkey = GetScriptForDestination(ScriptHash{redeem_script});
    return scripts;
}

InputScripts P2WSHSpend(const CScript& witness_script)
{
    InputScripts scripts;
    scripts.script_pubkey = GetScriptForDestination(WitnessV0ScriptHash{witness_script});
    scripts.witness.stack = {ToByteVector(witness_script)};
    return scripts;
}

InputScripts NestedP2WSHSpend(const CScript& witness_script)
{
    const CScript witness_program{GetScriptForDestination(WitnessV0ScriptHash{witness_script})};
    InputScripts scripts;
    scripts.script_sig = CScript{} << ToByteVector(witness_program);
    scripts.script_pubkey = GetScriptForDestination(ScriptHash{witness_program});
    scripts.witness.stack = {ToByteVector(witness_script)};
    return scripts;
}

script_verify_flags ConsumeValidFlags(FuzzedDataProvider& provider)
{
    script_verify_flags flags{script_verify_flags::from_int(
        provider.ConsumeIntegral<script_verify_flags::value_type>() & MAX_SCRIPT_VERIFY_FLAGS)};
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    Assert(IsValidFlagCombination(flags));
    return flags;
}

uint256 ScriptExecutionCacheEntry(const CTransaction& tx, script_verify_flags flags, const ValidationCache& cache)
{
    uint256 entry;
    CSHA256 hasher{cache.ScriptExecutionCacheHasher()};
    hasher.Write(UCharCast(tx.GetWitnessHash().begin()), 32)
        .Write(reinterpret_cast<const unsigned char*>(&flags), sizeof(flags))
        .Finalize(entry.begin());
    return entry;
}

InlineResult RunInline(const CTransaction& tx, const CCoinsViewCache& coins, script_verify_flags flags,
                       bool cache_sig_store, bool cache_script_store, ValidationCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    TxValidationState state;
    PrecomputedTransactionData txdata;
    const bool valid{CheckInputScripts(tx, state, coins, flags, cache_sig_store, cache_script_store,
                                       txdata, cache, nullptr)};
    Assert(valid == state.IsValid());
    Assert(!state.IsError());
    return {valid, state.GetResult()};
}

DeferredResult RunDeferred(const CTransaction& tx, const CCoinsViewCache& coins, script_verify_flags flags,
                           bool cache_sig_store, bool cache_script_store, ValidationCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    TxValidationState state;
    PrecomputedTransactionData txdata;
    std::vector<CScriptCheck> checks;
    Assert(CheckInputScripts(tx, state, coins, flags, cache_sig_store, cache_script_store, txdata, cache, &checks));
    Assert(state.IsValid());

    size_t failure_count{0};
    for (CScriptCheck& check : checks) {
        if (check().has_value()) ++failure_count;
    }
    return {
        .valid = failure_count == 0,
        .check_count = checks.size(),
        .failure_count = failure_count,
    };
}
} // namespace

FUZZ_TARGET(script_execution_cache, .init = initialize_script_execution_cache)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    const size_t input_count{provider.ConsumeIntegralInRange<size_t>(1, 4)};
    const size_t special_input{provider.ConsumeIntegralInRange<size_t>(0, input_count - 1)};
    const uint8_t special_type{provider.ConsumeIntegralInRange<uint8_t>(0, 3)};
    const bool cache_sig_store{provider.ConsumeBool()};

    script_verify_flags passing_flags{0};
    script_verify_flags failing_flags{0};
    InputScripts special_scripts;
    switch (special_type) {
    case 0:
        special_scripts = P2SHSpend(CScript{} << OP_FALSE);
        failing_flags = SCRIPT_VERIFY_P2SH;
        break;
    case 1:
        special_scripts = P2WSHSpend(CScript{} << OP_FALSE);
        passing_flags = SCRIPT_VERIFY_P2SH;
        failing_flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        break;
    case 2:
        special_scripts.script_pubkey = CScript{} << OP_1 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;
        failing_flags = SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        break;
    case 3:
        special_scripts.script_pubkey = CScript{} << OP_1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;
        failing_flags = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        break;
    }
    Assert(IsValidFlagCombination(passing_flags));
    Assert(IsValidFlagCombination(failing_flags));
    Assert(passing_flags != failing_flags);

    CMutableTransaction mutable_tx;
    mutable_tx.version = 2;
    mutable_tx.nLockTime = 0;
    mutable_tx.vout.emplace_back(0, CScript{} << OP_TRUE);
    CCoinsViewCache coins{&CoinsViewEmpty::Get(), /*deterministic=*/true};
    for (size_t index = 0; index < input_count; ++index) {
        const COutPoint prevout{Txid::FromUint256(ConsumeUInt256(provider)), static_cast<uint32_t>(index)};
        InputScripts scripts;
        if (index == special_input) {
            scripts = special_scripts;
        } else {
            const CScript true_script{CScript{} << OP_TRUE};
            switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
            case 0:
                scripts.script_pubkey = true_script;
                break;
            case 1:
                scripts = P2SHSpend(true_script);
                break;
            case 2:
                scripts = P2WSHSpend(true_script);
                break;
            case 3:
                scripts = NestedP2WSHSpend(true_script);
                break;
            }
        }

        mutable_tx.vin.emplace_back(prevout, std::move(scripts.script_sig), /*sequence=*/0);
        mutable_tx.vin.back().scriptWitness = std::move(scripts.witness);
        Coin coin{CTxOut{ConsumeMoney(provider), std::move(scripts.script_pubkey)}, /*height=*/1, /*coinbase=*/false};
        coins.AddCoin(prevout, std::move(coin), /*possible_overwrite=*/false);
    }
    coins.SanityCheck();
    const CTransaction tx{mutable_tx};

    LOCK(cs_main);
    ValidationCache reference_cache{/*script_execution_cache_bytes=*/32 * 1024, /*signature_cache_bytes=*/0};

    CMutableTransaction coinbase_mutable;
    coinbase_mutable.vin.resize(1);
    Assert(coinbase_mutable.vin[0].prevout.IsNull());
    const CTransaction coinbase{coinbase_mutable};
    TxValidationState coinbase_state;
    PrecomputedTransactionData coinbase_txdata;
    std::vector<CScriptCheck> coinbase_checks;
    Assert(CheckInputScripts(coinbase, coinbase_state, coins, failing_flags, cache_sig_store,
                             /*cache_script_store=*/true, coinbase_txdata, reference_cache, &coinbase_checks));
    Assert(coinbase_state.IsValid());
    Assert(coinbase_checks.empty());

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(input_count);
    for (const CTxIn& input : tx.vin) {
        const Coin& coin{coins.AccessCoin(input.prevout)};
        Assert(!coin.IsSpent());
        spent_outputs.push_back(coin.out);
    }
    PrecomputedTransactionData ready_txdata;
    ready_txdata.Init(tx, std::move(spent_outputs), /*force=*/true);
    Assert(ready_txdata.m_spent_outputs_ready);
    TxValidationState ready_state;
    Assert(CheckInputScripts(tx, ready_state, coins, passing_flags, cache_sig_store, /*cache_script_store=*/false,
                             ready_txdata, reference_cache, nullptr));
    Assert(ready_state.IsValid());

    const InlineResult passing_reference{
        RunInline(tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/false, reference_cache)};
    const InlineResult failing_reference{
        RunInline(tx, coins, failing_flags, cache_sig_store, /*cache_script_store=*/false, reference_cache)};
    Assert(passing_reference.valid);
    Assert(!failing_reference.valid);
    Assert(failing_reference.result == TxValidationResult::TX_CONSENSUS);

    const DeferredResult passing_deferred{
        RunDeferred(tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/false, reference_cache)};
    Assert(passing_deferred.valid);
    Assert(passing_deferred.check_count == input_count);
    Assert(passing_deferred.failure_count == 0);
    const DeferredResult failing_deferred{
        RunDeferred(tx, coins, failing_flags, cache_sig_store, /*cache_script_store=*/false, reference_cache)};
    Assert(!failing_deferred.valid);
    Assert(failing_deferred.check_count == input_count);
    Assert(failing_deferred.failure_count == 1);

    ValidationCache cache{/*script_execution_cache_bytes=*/32 * 1024, /*signature_cache_bytes=*/0};
    const uint256 passing_entry{ScriptExecutionCacheEntry(tx, passing_flags, cache)};
    const uint256 failing_entry{ScriptExecutionCacheEntry(tx, failing_flags, cache)};
    Assert(passing_entry != failing_entry);
    Assert(!cache.m_script_execution_cache.contains(passing_entry, /*erase=*/false));
    Assert(!cache.m_script_execution_cache.contains(failing_entry, /*erase=*/false));

    Assert(RunInline(tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/true, cache).valid);
    Assert(cache.m_script_execution_cache.contains(passing_entry, /*erase=*/false));
    const DeferredResult passing_hit{
        RunDeferred(tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(passing_hit.valid && passing_hit.check_count == 0);

    const DeferredResult isolated_failure{
        RunDeferred(tx, coins, failing_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(!isolated_failure.valid);
    Assert(isolated_failure.check_count == input_count);
    Assert(isolated_failure.failure_count == 1);
    const InlineResult failing_store{
        RunInline(tx, coins, failing_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(!failing_store.valid);
    Assert(failing_store.result == failing_reference.result);
    Assert(!cache.m_script_execution_cache.contains(failing_entry, /*erase=*/false));
    Assert(cache.m_script_execution_cache.contains(passing_entry, /*erase=*/false));

    const script_verify_flags random_flags{ConsumeValidFlags(provider)};
    const InlineResult random_reference{
        RunInline(tx, coins, random_flags, cache_sig_store, /*cache_script_store=*/false, reference_cache)};
    const uint256 random_entry{ScriptExecutionCacheEntry(tx, random_flags, cache)};
    const bool random_already_cached{random_flags == passing_flags};
    Assert(cache.m_script_execution_cache.contains(random_entry, /*erase=*/false) == random_already_cached);
    const DeferredResult random_deferred{
        RunDeferred(tx, coins, random_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(random_deferred.check_count == (random_already_cached ? 0 : input_count));
    Assert(random_deferred.valid == random_reference.valid);
    const InlineResult random_store{
        RunInline(tx, coins, random_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(random_store.valid == random_reference.valid);
    Assert(random_store.result == random_reference.result);
    Assert(cache.m_script_execution_cache.contains(random_entry, /*erase=*/false) == random_reference.valid);

    CMutableTransaction changed_mutable{mutable_tx};
    changed_mutable.vout[0].nValue = 1;
    const CTransaction changed_tx{changed_mutable};
    Assert(changed_tx.GetWitnessHash() != tx.GetWitnessHash());
    const uint256 changed_entry{ScriptExecutionCacheEntry(changed_tx, passing_flags, cache)};
    Assert(changed_entry != passing_entry);
    Assert(!cache.m_script_execution_cache.contains(changed_entry, /*erase=*/false));
    const DeferredResult changed_deferred{
        RunDeferred(changed_tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/true, cache)};
    Assert(changed_deferred.valid);
    Assert(changed_deferred.check_count == input_count);
    Assert(changed_deferred.failure_count == 0);
    Assert(RunInline(changed_tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/true, cache).valid);
    Assert(cache.m_script_execution_cache.contains(changed_entry, /*erase=*/false));
    Assert(cache.m_script_execution_cache.contains(passing_entry, /*erase=*/false));

    const DeferredResult erase_hit{
        RunDeferred(tx, coins, passing_flags, cache_sig_store, /*cache_script_store=*/false, cache)};
    Assert(erase_hit.valid && erase_hit.check_count == 0);
    Assert(cache.m_script_execution_cache.contains(passing_entry, /*erase=*/false));
}
