// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <validation.h> //for mempool access
#include <txmempool.h>
#include <utilmoneystr.h>
#include <util.h>
#include <net.h>

//! Check whether transaction has descendant in wallet or mempool, or has been
//! mined, or conflicts with a mined transaction. Return a feebumper::Result.
static feebumper::Result PreconditionChecks(const CWallet* wallet, const CWalletTx& wtx, std::vector<std::string>& errors)
{
    if (wallet->HasWalletSpend(wtx.GetHash())) {
        errors.push_back("Transaction has descendants in the wallet");
        return feebumper::Result::INVALID_PARAMETER;
    }

    {
        LOCK(mempool.cs);
        auto it_mp = mempool.mapTx.find(wtx.GetHash());
        if (it_mp != mempool.mapTx.end() && it_mp->GetCountWithDescendants() > 1) {
            errors.push_back("Transaction has descendants in the mempool");
            return feebumper::Result::INVALID_PARAMETER;
        }
    }

    if (wtx.GetDepthInMainChain() != 0) {
        errors.push_back("Transaction has been mined, or is conflicted with a mined transaction");
        return feebumper::Result::WALLET_ERROR;
    }

    if (!SignalsOptInRBF(*wtx.tx)) {
        errors.push_back("Transaction is not BIP 125 replaceable");
        return feebumper::Result::WALLET_ERROR;
    }

    if (wtx.mapValue.count("replaced_by_txid")) {
        errors.push_back(strprintf("Cannot bump transaction %s which was already bumped by transaction %s", wtx.GetHash().ToString(), wtx.mapValue.at("replaced_by_txid")));
        return feebumper::Result::WALLET_ERROR;
    }

    // check that original tx consists entirely of our inputs
    // if not, we can't bump the fee, because the wallet has no way of knowing the value of the other inputs (thus the fee)
    if (!wallet->IsAllFromMe(*wtx.tx, ISMINE_SPENDABLE)) {
        errors.push_back("Transaction contains inputs that don't belong to this wallet");
        return feebumper::Result::WALLET_ERROR;
    }


    return feebumper::Result::OK;
}

namespace feebumper {

bool TransactionCanBeBumped(const CWallet* wallet, const uint256& txid)
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx* wtx = wallet->GetWalletTx(txid);
    if (wtx == nullptr) return false;

    std::vector<std::string> errors_dummy;
    feebumper::Result res = PreconditionChecks(wallet, *wtx, errors_dummy);
    return res == feebumper::Result::OK;
}

Result CreateTransaction(const CWallet* wallet, const uint256& txid, CCoinControl& coin_control, CAmount total_fee, std::vector<std::string>& errors,
                         CAmount& old_fee, CAmount& new_fee, CMutableTransaction& mtx)
{
    LOCK2(cs_main, wallet->cs_wallet);
    errors.clear();
    auto it = wallet->mapWallet.find(txid);
    if (it == wallet->mapWallet.end()) {
        errors.push_back("Invalid or non-wallet transaction id");
        return Result::INVALID_ADDRESS_OR_KEY;
    }
    const CWalletTx& wtx = it->second;

    // Does some basic checks before attempting a bump
    Result result = PreconditionChecks(wallet, wtx, errors);
    if (result != Result::OK) {
        return result;
    }

    // Does size checks of old and new... for now they're ~same
    // Calculate the expected size of the new transaction.
    int64_t txSize = GetVirtualTransactionSize(*(wtx.tx));
    const int64_t maxNewTxSize = CalculateMaximumSignedTxSize(*wtx.tx, wallet);
    if (maxNewTxSize < 0) {
        errors.push_back("Transaction contains inputs that cannot be signed");
        return Result::INVALID_ADDRESS_OR_KEY;
    }

    // calculate the old fee and fee-rate
    old_fee = wtx.GetDebit(ISMINE_SPENDABLE) - wtx.tx->GetValueOut();
    CFeeRate nOldFeeRate(old_fee, txSize);
    CFeeRate nNewFeeRate;
    // The wallet uses a conservative WALLET_INCREMENTAL_RELAY_FEE value to
    // future proof against changes to network wide policy for incremental relay
    // fee that our node may not be aware of.
    CFeeRate walletIncrementalRelayFee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
    if (::incrementalRelayFee > walletIncrementalRelayFee) {
        walletIncrementalRelayFee = ::incrementalRelayFee;
    }

    // ABSOLUTE: all inputs pre-selected, no new ones allowed, ??? garbage, don't handle it
    // RELATIVE: ", just target new feerate
    // Does checks based on total fee bump required, or rate
    if (total_fee > 0) {
        return Result::INVALID_PARAMETER;
    } else {

        // New fee rate must be at least old rate + minimum incremental relay rate
        // walletIncrementalRelayFee.GetFeePerK() should be exact, because it's initialized
        // in that unit (fee per kb).
        // However, nOldFeeRate is a calculated value from the tx fee/size, so
        // add 1 satoshi to the result, because it may have been rounded down.
        if (nNewFeeRate.GetFeePerK() < nOldFeeRate.GetFeePerK() + 1 + walletIncrementalRelayFee.GetFeePerK()) {
            coin_control.m_feerate = std::optional<CFeeRate(nOldFeeRate.GetFeePerK() + 1 + walletIncrementalRelayFee.GetFeePerK())>;
        }
    }

    // Build CreateTransaction arguments
    std::vector<CRecipient> recipients;
    int change_pos_inout = -1;
    for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
        if (wallet->IsChange(wtx.tx->vout[i])) {
            change_pos_inout = i;
            ExtractDestination(wtx.tx->vout[i].scriptPubKey, coin_control.destChange);
        }
    }

    // Capture inputs, make them mandatory
    for (unsigned int i = 0; i < wtx.tx->vin.size(); i++) {
        coin_control.Select(wtx.tx->vin[i].prevout);
    }

    // No other coins allowed(for now)
    coin_control.fAllowOtherInputs = false;

    CTransactionRef tx;
    CReserveKey reservekey; //blank, we're using coin_control
    CAmount fee_ret = 0;
    std::string fail_reason;

    if (!wallet->CreateTransaction(recipients, tx, reservekey, fee_ret, change_pos_inout, fail_reason, coin_control, false /* sign */)) {
        return Result::MISC_ERROR;
    }

    return Result::OK;
}

bool SignTransaction(CWallet* wallet, CMutableTransaction& mtx) {
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->SignTransaction(mtx);
}

Result CommitTransaction(CWallet* wallet, const uint256& txid, CMutableTransaction&& mtx, std::vector<std::string>& errors, uint256& bumped_txid)
{
    LOCK2(cs_main, wallet->cs_wallet);
    if (!errors.empty()) {
        return Result::MISC_ERROR;
    }
    auto it = txid.IsNull() ? wallet->mapWallet.end() : wallet->mapWallet.find(txid);
    if (it == wallet->mapWallet.end()) {
        errors.push_back("Invalid or non-wallet transaction id");
        return Result::MISC_ERROR;
    }
    CWalletTx& oldWtx = it->second;

    // make sure the transaction still has no descendants and hasn't been mined in the meantime
    Result result = PreconditionChecks(wallet, oldWtx, errors);
    if (result != Result::OK) {
        return result;
    }

    // commit/broadcast the tx
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    mapValue_t mapValue = oldWtx.mapValue;
    mapValue["replaces_txid"] = oldWtx.GetHash().ToString();

    CReserveKey reservekey(wallet);
    CValidationState state;
    if (!wallet->CommitTransaction(tx, std::move(mapValue), oldWtx.vOrderForm, oldWtx.strFromAccount, reservekey, g_connman.get(), state)) {
        // NOTE: CommitTransaction never returns false, so this should never happen.
        errors.push_back(strprintf("The transaction was rejected: %s", FormatStateMessage(state)));
        return Result::WALLET_ERROR;
    }

    bumped_txid = tx->GetHash();
    if (state.IsInvalid()) {
        // This can happen if the mempool rejected the transaction.  Report
        // what happened in the "errors" response.
        errors.push_back(strprintf("Error: The transaction was rejected: %s", FormatStateMessage(state)));
    }

    // mark the original tx as bumped
    if (!wallet->MarkReplaced(oldWtx.GetHash(), bumped_txid)) {
        // TODO: see if JSON-RPC has a standard way of returning a response
        // along with an exception. It would be good to return information about
        // wtxBumped to the caller even if marking the original transaction
        // replaced does not succeed for some reason.
        errors.push_back("Created new bumpfee transaction but could not mark the original transaction as replaced");
    }
    return Result::OK;
}

} // namespace feebumper
