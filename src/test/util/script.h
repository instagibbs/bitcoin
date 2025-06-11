// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SCRIPT_H
#define BITCOIN_TEST_UTIL_SCRIPT_H

#include <crypto/sha256.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/check.h>

static const std::vector<uint8_t> WITNESS_STACK_ELEM_OP_TRUE{uint8_t{OP_TRUE}};
static const CScript P2WSH_OP_TRUE{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(WITNESS_STACK_ELEM_OP_TRUE.data(), WITNESS_STACK_ELEM_OP_TRUE.size()).Finalize(hash.begin());
           return hash;
       }())};

static const std::vector<uint8_t> EMPTY{};
static const CScript P2WSH_EMPTY{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           CSHA256().Write(EMPTY.data(), EMPTY.size()).Finalize(hash.begin());
           return hash;
       }())};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TRUE_STACK{{static_cast<uint8_t>(OP_TRUE)}, {}};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TWO_STACK{{static_cast<uint8_t>(OP_2)}, {}};

/** Flags that are not forbidden by an assert in script validation */
bool IsValidFlagCombination(unsigned flags);

/** Helper to compute the template hash of a transaction as computed by OP_TEMPLATEHASH. */
template<class T>
uint256 GetTemplateHash(const T& tx, unsigned int in_index, std::vector<uint8_t>* out_annex = nullptr)
{
    Assert(in_index < tx.vin.size());

    // Initialize the precomputed fields used in computing the template hash.
    PrecomputedTransactionData precomp;
    {
        std::vector<CTxOut> dummy_spent(tx.vin.size());
        precomp.Init(tx, std::move(dummy_spent), /*force=*/true);
    }
    assert(precomp.m_bip341_taproot_ready);

    // Detect the presence of an annex at the specified input.
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    const auto& stack{tx.vin[in_index].scriptWitness.stack};
    if (!stack.empty()) {
        const auto& top_elem{tx.vin[in_index].scriptWitness.stack.back()};
        execdata.m_annex_present = !top_elem.empty() && top_elem[0] == ANNEX_TAG;
        if (execdata.m_annex_present) {
            execdata.m_annex_hash = (HashWriter{} << top_elem).GetSHA256();
            if (out_annex) {
                *out_annex = top_elem;
            }
        }
    }
    execdata.m_annex_init = true;

    // Compute the template hash.
    const CAmount dummy_am{0};
    const auto dummy_mdb{MissingDataBehavior::ASSERT_FAIL};
    const auto checker{GenericTransactionSignatureChecker(&tx, in_index, dummy_am, precomp, dummy_mdb)};
    return checker.GetTemplateHash(execdata);
}

#endif // BITCOIN_TEST_UTIL_SCRIPT_H
