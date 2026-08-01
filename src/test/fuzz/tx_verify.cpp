// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {
constexpr size_t CHAIN_SIZE{33};

CTransaction MakeSpend(const std::vector<COutPoint>& prevouts, CAmount value_out)
{
    CMutableTransaction tx;
    tx.version = 2;
    for (const auto& prevout : prevouts) tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(value_out, CScript{} << OP_TRUE);
    return CTransaction{tx};
}

void AssertCoinEqual(const Coin& actual, const Coin& expected)
{
    assert(!actual.IsSpent());
    assert(actual.out == expected.out);
    assert(actual.nHeight == expected.nHeight);
    assert(actual.IsCoinBase() == expected.IsCoinBase());
}

void AssertViewUnchanged(
    const CCoinsViewCache& view,
    const std::vector<COutPoint>& outpoints,
    const std::vector<Coin>& expected)
{
    assert(outpoints.size() == expected.size());
    for (size_t i{0}; i < outpoints.size(); ++i) {
        const auto coin{view.PeekCoin(outpoints[i])};
        assert(coin.has_value());
        AssertCoinEqual(*coin, expected[i]);
    }
}

void AssertInputPreconditions(const CTransaction& tx)
{
    assert(!tx.IsCoinBase());
    TxValidationState state;
    assert(CheckTransaction(tx, state));
    assert(state.IsValid());
}

void AssertInputSuccess(const CTransaction& tx, const CCoinsViewCache& view, int spend_height, CAmount expected_fee)
{
    AssertInputPreconditions(tx);
    TxValidationState state;
    CAmount fee{-1};
    assert(Consensus::CheckTxInputs(tx, state, view, spend_height, fee));
    assert(state.IsValid());
    assert(state.GetResult() == TxValidationResult::TX_RESULT_UNSET);
    assert(state.GetRejectReason().empty());
    assert(fee == expected_fee);
}

void AssertInputFailure(
    const CTransaction& tx,
    const CCoinsViewCache& view,
    int spend_height,
    TxValidationResult result,
    const char* reason)
{
    AssertInputPreconditions(tx);
    TxValidationState state;
    CAmount fee{-1};
    assert(!Consensus::CheckTxInputs(tx, state, view, spend_height, fee));
    assert(state.IsInvalid());
    assert(!state.IsError());
    assert(state.GetResult() == result);
    assert(state.GetRejectReason() == reason);
}

bool InputValuesOutOfRange(const std::vector<CAmount>& values)
{
    CAmount sum{0};
    for (const CAmount value : values) {
        if (value < 0 || value > MAX_MONEY || sum > MAX_MONEY - value) return true;
        sum += value;
    }
    return false;
}

void CheckInputBoundaries(FuzzedDataProvider& provider)
{
    const size_t input_count{provider.ConsumeIntegralInRange<size_t>(1, 4)};
    std::vector<COutPoint> outpoints;
    std::vector<Coin> expected;
    outpoints.reserve(input_count);
    expected.reserve(input_count);

    CAmount remaining{MAX_MONEY};
    CAmount value_in{0};
    int max_coinbase_height{0};
    CCoinsViewCache view{&CoinsViewEmpty::Get(), /*deterministic=*/true};
    for (size_t i{0}; i < input_count; ++i) {
        const CAmount value{provider.ConsumeIntegralInRange<CAmount>(0, remaining)};
        remaining -= value;
        value_in += value;
        const bool coinbase{provider.ConsumeBool()};
        const int height{provider.ConsumeIntegralInRange<int>(0, 1'000)};
        if (coinbase) max_coinbase_height = std::max(max_coinbase_height, height);
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(i)};
        Coin coin{CTxOut{value, CScript{} << OP_TRUE}, height, coinbase};
        outpoints.push_back(outpoint);
        expected.push_back(coin);
        view.AddCoin(outpoint, std::move(coin), /*possible_overwrite=*/false);
    }

    const int spend_height{max_coinbase_height + COINBASE_MATURITY + provider.ConsumeIntegralInRange<int>(0, 20)};
    const CAmount value_out{provider.ConsumeIntegralInRange<CAmount>(0, value_in)};
    const CTransaction tx{MakeSpend(outpoints, value_out)};

    AssertInputSuccess(tx, view, spend_height, value_in - value_out);
    AssertInputSuccess(tx, view, spend_height, value_in - value_out);
    AssertViewUnchanged(view, outpoints, expected);

    std::reverse(outpoints.begin(), outpoints.end());
    std::reverse(expected.begin(), expected.end());
    const CTransaction reversed{MakeSpend(outpoints, value_out)};
    AssertInputSuccess(reversed, view, spend_height, value_in - value_out);
    AssertViewUnchanged(view, outpoints, expected);

    CCoinsViewCache empty_view{&CoinsViewEmpty::Get(), /*deterministic=*/true};
    AssertInputFailure(
        tx,
        empty_view,
        spend_height,
        TxValidationResult::TX_MISSING_INPUTS,
        "bad-txns-inputs-missingorspent");

    {
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), 10};
        const CTransaction spend{MakeSpend({outpoint}, /*value_out=*/0)};
        CCoinsViewCache maturity_view{&CoinsViewEmpty::Get(), /*deterministic=*/true};
        const Coin coin{CTxOut{1, CScript{} << OP_TRUE}, /*height=*/50, /*coinbase=*/true};
        maturity_view.AddCoin(outpoint, Coin{coin}, /*possible_overwrite=*/false);
        AssertInputFailure(
            spend,
            maturity_view,
            50 + COINBASE_MATURITY - 1,
            TxValidationResult::TX_PREMATURE_SPEND,
            "bad-txns-premature-spend-of-coinbase");
        AssertInputSuccess(spend, maturity_view, 50 + COINBASE_MATURITY, /*expected_fee=*/1);
        AssertViewUnchanged(maturity_view, {outpoint}, {coin});
    }

    const auto check_values = [](const std::vector<CAmount>& values, CAmount value_out, bool success) {
        CCoinsViewCache value_view{&CoinsViewEmpty::Get(), /*deterministic=*/true};
        std::vector<COutPoint> points;
        std::vector<Coin> coins;
        for (size_t i{0}; i < values.size(); ++i) {
            const COutPoint point{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(20 + i)};
            Coin coin{CTxOut{values[i], CScript{} << OP_TRUE}, /*height=*/0, /*coinbase=*/false};
            points.push_back(point);
            coins.push_back(coin);
            value_view.AddCoin(point, std::move(coin), /*possible_overwrite=*/false);
        }
        const CTransaction spend{MakeSpend(points, value_out)};
        if (success) {
            CAmount value_in{0};
            for (const CAmount value : values) value_in += value;
            AssertInputSuccess(spend, value_view, /*spend_height=*/0, value_in - value_out);
        } else if (InputValuesOutOfRange(values)) {
            AssertInputFailure(
                spend,
                value_view,
                /*spend_height=*/0,
                TxValidationResult::TX_CONSENSUS,
                "bad-txns-inputvalues-outofrange");
        } else {
            AssertInputFailure(
                spend,
                value_view,
                /*spend_height=*/0,
                TxValidationResult::TX_CONSENSUS,
                "bad-txns-in-belowout");
        }
        AssertViewUnchanged(value_view, points, coins);
    };

    check_values({-2}, /*value_out=*/0, /*success=*/false);
    check_values({MAX_MONEY + 1}, /*value_out=*/0, /*success=*/false);
    check_values({MAX_MONEY, 1}, /*value_out=*/0, /*success=*/false);
    check_values({0}, /*value_out=*/1, /*success=*/false);
    check_values({MAX_MONEY}, /*value_out=*/0, /*success=*/true);
}

int64_t MedianTime(const std::array<uint32_t, CHAIN_SIZE>& times, int height)
{
    std::vector<int64_t> window;
    for (int i{height}; i >= 0 && window.size() < CBlockIndex::nMedianTimeSpan; --i) {
        window.push_back(times[i]);
    }
    std::sort(window.begin(), window.end());
    return window[window.size() / 2];
}

void CheckLockBoundaries(FuzzedDataProvider& provider)
{
    std::array<CBlockIndex, CHAIN_SIZE> blocks{};
    std::array<uint32_t, CHAIN_SIZE> times{};
    times[0] = provider.ConsumeIntegralInRange<uint32_t>(1, 1'000'000'000);
    for (size_t i{0}; i < blocks.size(); ++i) {
        if (i > 0) times[i] = times[i - 1] + provider.ConsumeIntegralInRange<uint32_t>(1, 1'200);
        blocks[i].nTime = times[i];
        blocks[i].nHeight = static_cast<int>(i);
        blocks[i].pprev = i == 0 ? nullptr : &blocks[i - 1];
        blocks[i].BuildSkip();
    }
    const CBlockIndex& candidate{blocks.back()};

    CMutableTransaction mutable_tx;
    mutable_tx.version = provider.ConsumeIntegralInRange<int32_t>(1, 3);
    const int flags{provider.ConsumeBool() ? static_cast<int>(LOCKTIME_VERIFY_SEQUENCE) : 0};
    const size_t input_count{provider.ConsumeIntegralInRange<size_t>(1, 4)};
    std::vector<int> prev_heights;
    for (size_t i{0}; i < input_count; ++i) {
        const int height{provider.ConsumeIntegralInRange<int>(0, static_cast<int>(CHAIN_SIZE) - 2)};
        prev_heights.push_back(height);
        constexpr uint32_t SEQUENCE_FIELDS{CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG |
                                           CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
                                           CTxIn::SEQUENCE_LOCKTIME_MASK};
        const uint32_t reserved{provider.ConsumeIntegral<uint32_t>() & ~SEQUENCE_FIELDS};
        const uint32_t value{provider.ConsumeIntegral<uint16_t>()};
        uint32_t sequence;
        switch (provider.ConsumeIntegralInRange<uint8_t>(0, 2)) {
        case 0:
            sequence = reserved | value;
            break;
        case 1:
            sequence = reserved | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | value;
            break;
        default:
            sequence = reserved | CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | value;
            break;
        }
        mutable_tx.vin.emplace_back(
            COutPoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(i)},
            CScript{},
            sequence);
    }
    mutable_tx.vout.emplace_back(0, CScript{} << OP_TRUE);
    const CTransaction tx{mutable_tx};

    std::pair<int, int64_t> expected{-1, -1};
    std::vector<int> expected_heights{prev_heights};
    const bool enforce{tx.version >= 2 && (flags & LOCKTIME_VERIFY_SEQUENCE)};
    if (enforce) {
        for (size_t i{0}; i < tx.vin.size(); ++i) {
            const uint32_t sequence{tx.vin[i].nSequence};
            if (sequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
                expected_heights[i] = 0;
            } else if (sequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
                const int ancestor_height{std::max(prev_heights[i] - 1, 0)};
                const int64_t relative{
                    static_cast<int64_t>(sequence & CTxIn::SEQUENCE_LOCKTIME_MASK)
                    << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY};
                expected.second = std::max(expected.second, MedianTime(times, ancestor_height) + relative - 1);
            } else {
                const int relative{static_cast<int>(sequence & CTxIn::SEQUENCE_LOCKTIME_MASK)};
                expected.first = std::max(expected.first, prev_heights[i] + relative - 1);
            }
        }
    }

    std::vector<int> calculated_heights{prev_heights};
    assert(CalculateSequenceLocks(tx, flags, calculated_heights, candidate) == expected);
    assert(calculated_heights == expected_heights);
    const bool expected_evaluation{
        expected.first < candidate.nHeight &&
        expected.second < MedianTime(times, candidate.nHeight - 1)};
    assert(EvaluateSequenceLocks(candidate, expected) == expected_evaluation);

    std::vector<int> sequence_heights{prev_heights};
    assert(SequenceLocks(tx, flags, sequence_heights, candidate) == expected_evaluation);
    assert(sequence_heights == expected_heights);

    const int64_t previous_mtp{MedianTime(times, candidate.nHeight - 1)};
    assert(EvaluateSequenceLocks(candidate, {candidate.nHeight - 1, previous_mtp - 1}));
    assert(!EvaluateSequenceLocks(candidate, {candidate.nHeight, -1}));
    assert(!EvaluateSequenceLocks(candidate, {-1, previous_mtp}));

    CMutableTransaction finality_tx{mutable_tx};
    finality_tx.nLockTime = provider.ConsumeIntegral<uint32_t>();
    for (auto& input : finality_tx.vin) {
        if (provider.ConsumeBool()) {
            input.nSequence = CTxIn::SEQUENCE_FINAL;
        } else {
            input.nSequence = provider.ConsumeIntegral<uint32_t>();
            if (input.nSequence == CTxIn::SEQUENCE_FINAL) --input.nSequence;
        }
    }
    const int block_height{provider.ConsumeIntegralInRange<int>(0, 600'000'000)};
    const int64_t block_time{provider.ConsumeIntegralInRange<int64_t>(0, 10'000'000'000)};
    const bool all_final{std::all_of(finality_tx.vin.begin(), finality_tx.vin.end(), [](const CTxIn& input) {
        return input.nSequence == CTxIn::SEQUENCE_FINAL;
    })};
    const int64_t comparison{finality_tx.nLockTime < LOCKTIME_THRESHOLD ? block_height : block_time};
    const bool expected_final{
        finality_tx.nLockTime == 0 ||
        static_cast<int64_t>(finality_tx.nLockTime) < comparison ||
        all_final};
    assert(IsFinalTx(CTransaction{finality_tx}, block_height, block_time) == expected_final);

    CMutableTransaction boundary{MakeSpend({COutPoint{Txid::FromUint256(uint256::ONE), 100}}, 0)};
    boundary.vin[0].nSequence = 0;
    boundary.nLockTime = 100;
    assert(!IsFinalTx(CTransaction{boundary}, /*nBlockHeight=*/100, /*nBlockTime=*/0));
    assert(IsFinalTx(CTransaction{boundary}, /*nBlockHeight=*/101, /*nBlockTime=*/0));
    boundary.nLockTime = LOCKTIME_THRESHOLD;
    assert(!IsFinalTx(CTransaction{boundary}, /*nBlockHeight=*/0, LOCKTIME_THRESHOLD));
    assert(IsFinalTx(CTransaction{boundary}, /*nBlockHeight=*/0, LOCKTIME_THRESHOLD + 1));
    boundary.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    assert(IsFinalTx(CTransaction{boundary}, /*nBlockHeight=*/0, LOCKTIME_THRESHOLD));
}

void CheckSigOpBoundaries(FuzzedDataProvider& provider)
{
    const CScript p2sh_redeem{CScript{} << OP_1 << OP_1 << OP_CHECKMULTISIG};
    const CScript witness_script{CScript{} << OP_CHECKSIG << OP_CHECKSIG};
    const CScript witness_keyhash{GetScriptForDestination(WitnessV0KeyHash{uint160{}})};
    const CScript nested_witness{GetScriptForDestination(ScriptHash{witness_keyhash})};

    std::array<CScript, 4> scripts{
        GetScriptForDestination(ScriptHash{p2sh_redeem}),
        witness_keyhash,
        GetScriptForDestination(WitnessV0ScriptHash{witness_script}),
        nested_witness,
    };

    CCoinsViewCache view{&CoinsViewEmpty::Get(), /*deterministic=*/true};
    CMutableTransaction mutable_tx;
    std::vector<COutPoint> outpoints;
    std::vector<Coin> coins;
    for (size_t i{0}; i < scripts.size(); ++i) {
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), static_cast<uint32_t>(200 + i)};
        Coin coin{CTxOut{1, scripts[i]}, /*height=*/0, /*coinbase=*/false};
        outpoints.push_back(outpoint);
        coins.push_back(coin);
        view.AddCoin(outpoint, std::move(coin), /*possible_overwrite=*/false);
        mutable_tx.vin.emplace_back(outpoint);
    }
    mutable_tx.vin[0].scriptSig = CScript{} << ToByteVector(p2sh_redeem);
    mutable_tx.vin[1].scriptWitness.stack.resize(2);
    mutable_tx.vin[2].scriptWitness.stack.resize(2);
    mutable_tx.vin[2].scriptWitness.stack.push_back(ToByteVector(witness_script));
    mutable_tx.vin[3].scriptSig = CScript{} << ToByteVector(witness_keyhash);
    mutable_tx.vin[3].scriptWitness.stack.resize(2);

    const unsigned int checksigs{provider.ConsumeIntegralInRange<unsigned int>(0, 4)};
    const unsigned int multisigs{provider.ConsumeIntegralInRange<unsigned int>(0, 3)};
    CScript legacy_script;
    for (unsigned int i{0}; i < checksigs; ++i) legacy_script << OP_CHECKSIG;
    for (unsigned int i{0}; i < multisigs; ++i) legacy_script << OP_CHECKMULTISIG;
    mutable_tx.vout.emplace_back(0, legacy_script);
    const CTransaction tx{mutable_tx};

    const unsigned int expected_legacy{checksigs + multisigs * MAX_PUBKEYS_PER_MULTISIG};
    const script_verify_flags p2sh{SCRIPT_VERIFY_P2SH};
    const script_verify_flags witness{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
    assert(GetLegacySigOpCount(tx) == expected_legacy);
    assert(GetP2SHSigOpCount(tx, view) == 1);
    assert(GetTransactionSigOpCost(tx, view, /*flags=*/0) == expected_legacy * WITNESS_SCALE_FACTOR);
    assert(GetTransactionSigOpCost(tx, view, p2sh) == (expected_legacy + 1) * WITNESS_SCALE_FACTOR);
    assert(GetTransactionSigOpCost(tx, view, witness) == (expected_legacy + 1) * WITNESS_SCALE_FACTOR + 4);
    AssertViewUnchanged(view, outpoints, coins);

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptWitness.stack.push_back(ToByteVector(witness_script));
    coinbase.vout.emplace_back(0, legacy_script);
    const CTransaction coinbase_tx{coinbase};
    assert(coinbase_tx.IsCoinBase());
    assert(GetLegacySigOpCount(coinbase_tx) == expected_legacy);
    assert(GetP2SHSigOpCount(coinbase_tx, view) == 0);
    assert(GetTransactionSigOpCost(coinbase_tx, view, witness) == expected_legacy * WITNESS_SCALE_FACTOR);
}
} // namespace

FUZZ_TARGET(tx_verify)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    CheckInputBoundaries(provider);
    CheckLockBoundaries(provider);
    CheckSigOpBoundaries(provider);
}
