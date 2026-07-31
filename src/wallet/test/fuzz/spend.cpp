// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/wallet.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <map>
#include <set>

using util::ToString;

namespace wallet {
namespace {
const TestingSetup* g_setup;

void initialize_setup()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(wallet_create_transaction, .init = initialize_setup)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};
    const auto& node = g_setup->m_node;
    Chainstate& chainstate{node.chainman->ActiveChainstate()};
    ArgsManager& args = *node.args;
    args.ForceSetArg("-dustrelayfee", ToString(fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY)));
    FuzzedWallet fuzzed_wallet{
        *g_setup->m_node.chain,
        "fuzzed_wallet_a",
        "tprv8ZgxMBicQKsPd1QwsGgzfu2pcPYbBosZhJknqreRHgsWx32nNEhMjGQX2cgFL8n6wz9xdDYwLcs78N4nsCo32cxEX8RBtwGsEGgybLiQJfk",
    };

    CCoinControl coin_control;
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_version = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    coin_control.m_avoid_partial_spends = fuzzed_data_provider.ConsumeBool();
    coin_control.m_include_unsafe_inputs = fuzzed_data_provider.ConsumeBool();
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_confirm_target = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 999'000);
    coin_control.destChange = fuzzed_data_provider.ConsumeBool() ? fuzzed_wallet.GetDestination(fuzzed_data_provider) : ConsumeTxDestination(fuzzed_data_provider);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_change_type = fuzzed_data_provider.PickValueInArray(OUTPUT_TYPES);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_feerate = CFeeRate(ConsumeMoney(fuzzed_data_provider, /*max=*/COIN));
    coin_control.m_allow_other_inputs = fuzzed_data_provider.ConsumeBool();
    coin_control.m_locktime = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    coin_control.fOverrideFeeRate = fuzzed_data_provider.ConsumeBool();

    int next_locktime{0};
    CAmount all_values{0};
    std::map<COutPoint, CTxOut> wallet_coins;
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 10000) {
        CMutableTransaction tx;
        tx.nLockTime = next_locktime++;
        tx.vout.resize(1);
        CAmount n_value{ConsumeMoney(fuzzed_data_provider)};
        all_values += n_value;
        if (all_values > MAX_MONEY) return;
        tx.vout[0].nValue = n_value;
        tx.vout[0].scriptPubKey = GetScriptForDestination(fuzzed_wallet.GetDestination(fuzzed_data_provider));
        LOCK(fuzzed_wallet.wallet->cs_wallet);
        auto txid{tx.GetHash()};
        auto ret{fuzzed_wallet.wallet->mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(MakeTransactionRef(std::move(tx)), TxStateConfirmed{chainstate.m_chain.Tip()->GetBlockHash(), chainstate.m_chain.Height(), /*index=*/0}))};
        assert(ret.second);
        fuzzed_wallet.wallet->RefreshTXOsFromTx(ret.first->second);
        assert(wallet_coins.emplace(COutPoint{txid, 0}, ret.first->second.tx->vout[0]).second);
    }

    std::vector<CRecipient> recipients;
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 100) {
        CTxDestination destination;
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                destination = fuzzed_wallet.GetDestination(fuzzed_data_provider);
            },
            [&] {
                CScript script;
                script << OP_RETURN;
                destination = CNoDestination{script};
            },
            [&] {
                destination = ConsumeTxDestination(fuzzed_data_provider);
            }
        );
        recipients.push_back({destination,
                              /*nAmount=*/ConsumeMoney(fuzzed_data_provider),
                              /*fSubtractFeeFromAmount=*/fuzzed_data_provider.ConsumeBool()});
    }

    std::optional<unsigned int> change_pos;
    if (fuzzed_data_provider.ConsumeBool()) change_pos = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    auto result{CreateTransaction(*fuzzed_wallet.wallet, recipients, change_pos, coin_control)};
    if (!result) return;

    assert(MoneyRange(result->fee));
    assert(!result->tx->vin.empty());
    assert(!result->change_pos || *result->change_pos < result->tx->vout.size());

    CAmount input_value{0};
    std::set<COutPoint> spent_outpoints;
    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(result->tx->vin.size());
    for (const CTxIn& input : result->tx->vin) {
        assert(spent_outpoints.insert(input.prevout).second);
        const auto coin{wallet_coins.find(input.prevout)};
        assert(coin != wallet_coins.end());
        input_value += coin->second.nValue;
        assert(MoneyRange(input_value));
        spent_outputs.push_back(coin->second);
    }
    assert(input_value == CalculateOutputValue(*result->tx) + result->fee);

    PrecomputedTransactionData txdata;
    txdata.Init(*result->tx, std::move(spent_outputs));
    for (unsigned int input_index{0}; input_index < result->tx->vin.size(); ++input_index) {
        const CTxIn& input{result->tx->vin[input_index]};
        const CTxOut& spent_output{txdata.m_spent_outputs[input_index]};
        const TransactionSignatureChecker checker{result->tx.get(), input_index, spent_output.nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        assert(VerifyScript(input.scriptSig, spent_output.scriptPubKey, &input.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker));
    }
}

FUZZ_TARGET(wallet_fund_transaction, .init = initialize_setup)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};
    const auto& node = g_setup->m_node;
    Chainstate& chainstate{node.chainman->ActiveChainstate()};
    ArgsManager& args{*node.args};
    args.ForceSetArg("-dustrelayfee", ToString(fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY)));
    FuzzedWallet fuzzed_wallet{
        *node.chain,
        "fuzzed_wallet_fund",
        "tprv8ZgxMBicQKsPd1QwsGgzfu2pcPYbBosZhJknqreRHgsWx32nNEhMjGQX2cgFL8n6wz9xdDYwLcs78N4nsCo32cxEX8RBtwGsEGgybLiQJfk",
    };

    CCoinControl coin_control;
    coin_control.m_avoid_partial_spends = fuzzed_data_provider.ConsumeBool();
    coin_control.m_include_unsafe_inputs = fuzzed_data_provider.ConsumeBool();
    coin_control.m_allow_other_inputs = fuzzed_data_provider.ConsumeBool();
    coin_control.fOverrideFeeRate = fuzzed_data_provider.ConsumeBool();
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_signal_bip125_rbf = fuzzed_data_provider.ConsumeBool();
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_confirm_target = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 999'000);
    coin_control.destChange = fuzzed_data_provider.ConsumeBool() ? fuzzed_wallet.GetDestination(fuzzed_data_provider) : ConsumeTxDestination(fuzzed_data_provider);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_change_type = fuzzed_data_provider.PickValueInArray(OUTPUT_TYPES);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_feerate = CFeeRate(ConsumeMoney(fuzzed_data_provider, /*max=*/COIN));
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_max_tx_weight = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 2 * MAX_STANDARD_TX_WEIGHT);

    CMutableTransaction tx;
    tx.version = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    tx.nLockTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const bool lock_unspents{fuzzed_data_provider.ConsumeBool()};

    int next_locktime{0};
    CAmount all_values{0};
    std::map<COutPoint, CTxOut> wallet_coins;
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 2500) {
        CMutableTransaction funding_tx;
        funding_tx.nLockTime = next_locktime++;
        funding_tx.vout.resize(1);
        CAmount value{ConsumeMoney(fuzzed_data_provider)};
        all_values += value;
        if (all_values > MAX_MONEY) return;
        funding_tx.vout[0].nValue = value;
        funding_tx.vout[0].scriptPubKey = fuzzed_wallet.GetScriptPubKey(fuzzed_data_provider);

        LOCK(fuzzed_wallet.wallet->cs_wallet);
        const Txid txid{funding_tx.GetHash()};
        auto inserted{fuzzed_wallet.wallet->mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(txid), std::forward_as_tuple(MakeTransactionRef(std::move(funding_tx)), TxStateConfirmed{chainstate.m_chain.Tip()->GetBlockHash(), chainstate.m_chain.Height(), /*index=*/0}))};
        assert(inserted.second);
        fuzzed_wallet.wallet->RefreshTXOsFromTx(inserted.first->second);
        const COutPoint outpoint{txid, 0};
        assert(wallet_coins.emplace(outpoint, inserted.first->second.tx->vout[0]).second);

        if (fuzzed_data_provider.ConsumeBool()) {
            CTxIn input{outpoint};
            input.nSequence = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            if (fuzzed_data_provider.ConsumeBool()) input.scriptSig = ConsumeScript(fuzzed_data_provider);
            if (fuzzed_data_provider.ConsumeBool()) input.scriptWitness = ConsumeScriptWitness(fuzzed_data_provider);
            tx.vin.push_back(std::move(input));
            if (fuzzed_data_provider.ConsumeBool()) {
                coin_control.SetInputWeight(outpoint, fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(GetTransactionInputWeight(CTxIn{}), MAX_STANDARD_TX_WEIGHT));
            }
        }
    }

    std::vector<CRecipient> recipients;
    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 100) {
        CTxDestination destination;
        CallOneOf(
            fuzzed_data_provider,
            [&] { destination = fuzzed_wallet.GetDestination(fuzzed_data_provider); },
            [&] {
                CScript script;
                script << OP_RETURN;
                destination = CNoDestination{script};
            },
            [&] { destination = ConsumeTxDestination(fuzzed_data_provider); });
        recipients.push_back({destination,
                              /*nAmount=*/ConsumeMoney(fuzzed_data_provider),
                              /*fSubtractFeeFromAmount=*/fuzzed_data_provider.ConsumeBool()});
    }

    std::optional<unsigned int> change_pos;
    if (fuzzed_data_provider.ConsumeBool()) change_pos = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    auto result{FundTransaction(*fuzzed_wallet.wallet, tx, recipients, change_pos, lock_unspents, coin_control)};
    if (!result) return;

    assert(result->tx->version == tx.version);
    assert(result->tx->nLockTime == tx.nLockTime);
    assert(result->tx->vin.size() >= tx.vin.size());
    assert(MoneyRange(result->fee));
    assert(!result->change_pos || *result->change_pos < result->tx->vout.size());
    for (size_t input_index{0}; input_index < tx.vin.size(); ++input_index) {
        assert(result->tx->vin[input_index].prevout == tx.vin[input_index].prevout);
        assert(result->tx->vin[input_index].nSequence == tx.vin[input_index].nSequence);
        assert(result->tx->vin[input_index].scriptSig == tx.vin[input_index].scriptSig);
        assert(result->tx->vin[input_index].scriptWitness == tx.vin[input_index].scriptWitness);
    }

    CAmount input_value{0};
    std::set<COutPoint> spent_outpoints;
    for (const CTxIn& input : result->tx->vin) {
        assert(spent_outpoints.insert(input.prevout).second);
        const auto coin{wallet_coins.find(input.prevout)};
        assert(coin != wallet_coins.end());
        input_value += coin->second.nValue;
        assert(MoneyRange(input_value));
    }
    assert(input_value == CalculateOutputValue(*result->tx) + result->fee);

    LOCK(fuzzed_wallet.wallet->cs_wallet);
    for (const CTxIn& input : result->tx->vin) {
        assert(fuzzed_wallet.wallet->IsLockedCoin(input.prevout) == lock_unspents);
    }
}
} // namespace
} // namespace wallet
