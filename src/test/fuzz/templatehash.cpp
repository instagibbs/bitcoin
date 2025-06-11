// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/script.h>

//! Maximum number of inputs and outputs in transactions consumed from fuzzer.
static constexpr int MAX_TX_IN_OUT{10'000};
//! Verification flags to set for script validation.
static constexpr unsigned VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_TEMPLATEHASH};

static bool VerifyTemplateCheck(const CMutableTransaction& tx, unsigned int in_index,
                                std::vector<CTxOut> spent_outputs, const CScript& spent_spk)
{
    constexpr auto mdb{MissingDataBehavior::ASSERT_FAIL};
    constexpr CAmount dummy_am{0}; // We never check signatures.
    PrecomputedTransactionData precomp;
    precomp.Init(tx, std::move(spent_outputs));
    const auto checker{GenericTransactionSignatureChecker(&tx, in_index, dummy_am, precomp, mdb)};
    return VerifyScript(tx.vin[in_index].scriptSig, spent_spk, &tx.vin[in_index].scriptWitness, VERIFY_FLAGS, checker);
}

/** Target specialized on the new logic introduced for OP_TEMPLATEHASH. */
FUZZ_TARGET(gettemplatehash)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // First get the transaction for which to generate the template hash. It's unnecessary to
    // get the fuzzer to try to find a valid deserialization, as only the version+locktime is
    // used by GetTemplateHash().
    CMutableTransaction tx;
    tx.version = provider.ConsumeIntegral<uint32_t>();
    tx.nLockTime = provider.ConsumeIntegral<uint32_t>();

    // Manually set the precomputed values used in the template hash.
    PrecomputedTransactionData precomp{tx};
    precomp.m_sequences_single_hash = ConsumeUInt256(provider);
    precomp.m_outputs_single_hash = ConsumeUInt256(provider);
    precomp.m_bip341_taproot_ready = true;

    // Sometimes commit to the annex too.
    ScriptExecutionData execdata;
    execdata.m_annex_present = provider.ConsumeBool();
    if (execdata.m_annex_present) {
        execdata.m_annex_hash = ConsumeUInt256(provider);
    }
    execdata.m_annex_init = true;

    // Finally, exercise the GetTemplateHash() function.
    const auto in_index{provider.ConsumeIntegral<unsigned>()};
    const CAmount dummy_am{0};
    const auto dummy_mdb{MissingDataBehavior::ASSERT_FAIL};
    const auto checker{GenericTransactionSignatureChecker(&tx, in_index, dummy_am, precomp, dummy_mdb)};
    (void)checker.GetTemplateHash(execdata);
}

/** Broader target which exercises the commit-to-spending transaction use case of OP_TEMPLATEHASH for
 * various fuzzer-provided transactions and asserts invariants. */
FUZZ_TARGET(spendtemplatehash)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Compute the template hash for a fuzzer-provided transaction and input index.
    std::vector<uint8_t> annex;
    auto tx{ConsumeTransaction(provider, {}, MAX_TX_IN_OUT, MAX_TX_IN_OUT)};
    if (tx.vin.empty()) return;
    const auto in_index{provider.ConsumeIntegralInRange<unsigned int>(0, tx.vin.size() - 1)};
    const auto template_hash{GetTemplateHash(tx, in_index, &annex)};

    // Construct the output script committing to this template hash.
    const auto leaf_script{CScript() << template_hash << OP_TEMPLATEHASH << OP_EQUAL};
    TaprootBuilder builder;
    builder.Add(0, leaf_script, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    const CScript spent_spk{GetScriptForDestination(builder.GetOutput())};

    // Set the witness for this transaction input.
    const auto spend_data{builder.GetSpendData()};
    const auto control_blocks{spend_data.scripts.begin()->second};
    const auto& cb{*control_blocks.begin()};
    tx.vin[in_index].scriptWitness.stack.clear();
    tx.vin[in_index].scriptWitness.stack.emplace_back(leaf_script.begin(), leaf_script.end());
    tx.vin[in_index].scriptWitness.stack.emplace_back(cb.begin(), cb.end());
    if (!annex.empty()) {
        tx.vin[in_index].scriptWitness.stack.push_back(std::move(annex));  // TODO: a good way to test the target is to comment out this line
    }

    // Get the vector of spent outputs from the fuzzer. No spent output are taken into account in
    // computing the template hash. Therefore the specific values of the other spent outputs can
    // be set freely. However the spent output referred to by the input being verified must be
    // correctly set to a Taproot scriptpubkey for bip341 subfields to be precomputed.
    std::vector<CTxOut> spent_outputs(tx.vin.size());
    for (unsigned i{0}; i < spent_outputs.size(); ++i) {
        spent_outputs[i].scriptPubKey = i == in_index ? spent_spk : ConsumeScript(provider);
        spent_outputs[i].nValue = ConsumeMoney(provider);
    }

    // Run script validation for this transaction input. It must pass.
    tx.vin[in_index].scriptSig.clear(); // witness requires empty scriptSig
    Assert(VerifyTemplateCheck(tx, in_index, std::vector<CTxOut>(spent_outputs), spent_spk));

    // Malleate a field of the spending transaction and assert whether it invalidates the spend.
    CallOneOf(
        provider,
        // Changing version will invalidate template hash.
        [&] {
            const auto prev_version{tx.version};
            tx.version = provider.ConsumeIntegral<uint32_t>();
            const bool version_changed{tx.version != prev_version};
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !version_changed);
        },
        // Changing locktime will invalidate template hash.
        [&] {
            const auto prev_locktime{tx.nLockTime};
            tx.nLockTime = provider.ConsumeIntegral<uint32_t>();
            const bool locktime_changed{tx.nLockTime != prev_locktime};
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !locktime_changed);
        },
        // Changing the sequence of any input will invalidate template hash.
        [&] {
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vin.size() - 1)};
            const auto prev_sequence{tx.vin[i].nSequence};
            tx.vin[i].nSequence = provider.ConsumeIntegral<uint32_t>();
            const bool seq_changed{tx.vin[i].nSequence != prev_sequence};
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !seq_changed);
        },
        // Changing the prevout of any input will not invalidate template hash.
        [&] {
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vin.size() - 1)};
            tx.vin[i].prevout.hash = Txid::FromUint256(ConsumeUInt256(provider));
            tx.vin[i].prevout.n = provider.ConsumeIntegral<uint32_t>();
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk));
        },
        // Changing the scriptSig of an input will only make Script validation fail if it malleates
        // that of the input being validated (because Segwit mandates empty scriptSig).
        [&] {
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vin.size() - 1)};
            tx.vin[i].scriptSig = ConsumeScript(provider);
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == tx.vin[in_index].scriptSig.empty());
        },
        // Changing the annex of the spending input will invalidate template hash. Changing the
        // witness of any other input will not invalidate template hash.
        [&] {
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vin.size() - 1)};
            if (i == in_index) {
                // Don't necessarily create a well-formatted annex.
                auto new_annex{ConsumeRandomLengthByteVector(provider)};
                const bool expect_failure{annex.empty() || annex != new_annex};
                if (annex.empty()) {
                    tx.vin[i].scriptWitness.stack.emplace_back();
                }
                tx.vin[i].scriptWitness.stack.back() = std::move(new_annex);
                Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !expect_failure);
            } else {
                tx.vin[i].scriptWitness = ConsumeScriptWitness(provider);
                Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk));
            }
        },
        // Changing the value of any output will invalidate template hash.
        [&] {
            if (tx.vout.empty()) return;
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vout.size() - 1)};
            const auto prev_value{tx.vout[i].nValue};
            tx.vout[i].nValue = provider.ConsumeIntegral<CAmount>();
            const bool value_changed{tx.vout[i].nValue != prev_value};
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !value_changed);
        },
        // Changing the scriptPubKey of any output will invalidate template hash.
        [&] {
            if (tx.vout.empty()) return;
            const auto i{provider.ConsumeIntegralInRange<size_t>(0, tx.vout.size() - 1)};
            const auto prev_spk{tx.vout[i].scriptPubKey};
            tx.vout[i].scriptPubKey = ConsumeScript(provider);
            const bool spk_changed{tx.vout[i].scriptPubKey != prev_spk};
            Assert(VerifyTemplateCheck(tx, in_index, std::move(spent_outputs), spent_spk) == !spk_changed);
        }
        // TODO: check that adding/removing inputs/outputs invalidates template hash.
    );
}
