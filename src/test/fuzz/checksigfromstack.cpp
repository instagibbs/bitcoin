// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <vector>

//! Verification flags with OP_CHECKSIGFROMSTACK (BIP-348) active.
static constexpr script_verify_flags VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_TEMPLATEHASH};

//! Spend a Taproot output whose only leaf is `<sig> <msg> <pubkey> OP_CHECKSIGFROMSTACK` and return
//! the resulting ScriptError (SCRIPT_ERR_OK iff the spend is valid).
static ScriptError EvalCsfsLeaf(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& msg, const std::vector<unsigned char>& pubkey)
{
    const CScript leaf{CScript() << sig << msg << pubkey << OP_CHECKSIGFROMSTACK};
    TaprootBuilder builder;
    builder.Add(0, leaf, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    const CScript spk{GetScriptForDestination(builder.GetOutput())};

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(1000, CScript() << OP_RETURN);
    const std::vector<CTxOut> spent_outputs{CTxOut{1000, spk}};

    const auto spend_data{builder.GetSpendData()};
    const auto& cb{*spend_data.scripts.begin()->second.begin()};
    tx.vin[0].scriptWitness.stack.emplace_back(leaf.begin(), leaf.end());
    tx.vin[0].scriptWitness.stack.emplace_back(cb.begin(), cb.end());

    PrecomputedTransactionData precomp;
    precomp.Init(tx, std::vector<CTxOut>{spent_outputs});
    const auto checker{GenericTransactionSignatureChecker(&tx, 0, CAmount{1000}, precomp, MissingDataBehavior::ASSERT_FAIL)};
    ScriptError err{SCRIPT_ERR_OK};
    VerifyScript(tx.vin[0].scriptSig, spk, &tx.vin[0].scriptWitness, VERIFY_FLAGS, checker, &err);
    return err;
}

static void initialize_checksigfromstack()
{
    static ECC_Context ecc_context{};
}

/** Exercise OP_CHECKSIGFROMSTACK (BIP-348) and assert its consensus-relevant invariants. */
FUZZ_TARGET(checksigfromstack, .init = initialize_checksigfromstack)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // A signing key derived from fuzzer entropy.
    auto sk_bytes{provider.ConsumeBytes<unsigned char>(32)};
    sk_bytes.resize(32);
    CKey key;
    key.Set(sk_bytes.begin(), sk_bytes.end(), /*fCompressedIn=*/true);
    if (!key.IsValid()) return;
    const XOnlyPubKey xpk{key.GetPubKey()};
    const std::vector<unsigned char> real_pk{xpk.begin(), xpk.end()};

    // A fuzzer-chosen message and a correct BIP-340 signature over it.
    const uint256 msg{ConsumeUInt256(provider)};
    const std::vector<unsigned char> msg_vec{msg.begin(), msg.end()};
    std::vector<unsigned char> good_sig(64);
    if (!key.SignSchnorr(msg, good_sig, /*merkle_root=*/nullptr, /*aux=*/uint256{})) return;

    // A correct (sig, msg, pubkey) triple is accepted.
    Assert(EvalCsfsLeaf(good_sig, msg_vec, real_pk) == SCRIPT_ERR_OK);

    CallOneOf(
        provider,
        [&] {
            // An empty signature pushes false; the bare CSFS leaf then fails the final true check.
            Assert(EvalCsfsLeaf({}, msg_vec, real_pk) == SCRIPT_ERR_EVAL_FALSE);
        },
        [&] {
            // Any signature other than the correct one makes the spend fail (never validates).
            const auto other{ConsumeRandomLengthByteVector(provider)};
            if (other == good_sig) return;
            Assert(EvalCsfsLeaf(other, msg_vec, real_pk) != SCRIPT_ERR_OK);
        },
        [&] {
            // Verifying the signature against any other message makes the spend fail.
            const auto other_msg{ConsumeRandomLengthByteVector(provider)};
            if (other_msg == msg_vec) return;
            Assert(EvalCsfsLeaf(good_sig, other_msg, real_pk) != SCRIPT_ERR_OK);
        },
        [&] {
            // A zero-length public key fails.
            Assert(EvalCsfsLeaf(good_sig, msg_vec, {}) == SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
        },
        [&] {
            // Arbitrary signature/message/pubkey inputs must never crash.
            (void)EvalCsfsLeaf(ConsumeRandomLengthByteVector(provider), ConsumeRandomLengthByteVector(provider), ConsumeRandomLengthByteVector(provider));
        }
    );
}
