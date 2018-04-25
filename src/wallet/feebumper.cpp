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

Result CreateTransaction(CWallet* wallet, const CWalletTx& tx_to_bump, const CCoinControl& coin_control, CAmount total_fee, std::vector<std::string>& errors,
                         CAmount& old_fee, CAmount& new_fee, CMutableTransaction& mtx, CReserveKey& reservekey)
{
    LOCK2(cs_main, wallet->cs_wallet);
    errors.clear();

    Result result = PreconditionChecks(wallet, tx_to_bump, errors);
    if (result != Result::OK) {
        return result;
    }

    std::vector<CRecipient> recipients;
    CTransactionRef new_tx;
    int change_pos = -1;
    std::string fail_reason;

    // Gather destinations
    for (auto& output : tx_to_bump.tx->vout) {
        if (!wallet->IsChange(output)) {
            CRecipient recipient = {output.scriptPubKey, output.nValue, false};
            recipients.push_back(recipient);
        }
    }

    // TODO blacklist outputs in this transaction from being sourced in AvailableCoins:
    // coin_control.m_excluded_coins
    //
    // TODO Have CreateTransaction take into account that it needs to be BIP125 compatible
    // aka fees of new transaction MUST be relay_fee*nbytes + old_fee
    // Easiest implementation is to use WALLET_INCREMENTAL_RELAY_FEE (5 sat/byte default)
    // for new tx bytes selected
    // and target the old_fee total during coin selection, reserving this for fee explicitly
    // *But*, new conf target may "dominate" this, depending on how many inputs it picks.
    // Maybe just make new transaction using the conf target
    // During coin selection, we know how much fees we're going to end up with.
    // If we hit target amount but fees insufficient, keep going, dumping required amount to fees.
    // This only really works with SRD, is that ok?
    // In some cases, you'll hit your destination amount, and have change that can be re-balanced
    // to hit total fee target. If dumping the whole amount isn't enough, you have to select more.
    //
    // For CPFP, mandatory spend the output(and only the output? coin selection can deal with that)
    // but must be unspent. (new_tx_feerate - old_tx_feerate)*old_nbytes = total extra destination
    // amount, otherwise target feerate in new tx construction. Dump the total extra to additional
    // fee
    //
    // With both CPFP and RBF at disposal, make whatever bump you can, compare total cost, take min.

    if (!wallet->CreateTransaction(recipients, new_tx, reservekey, total_fee, change_pos, fail_reason, coin_control, false)) {
        errors.push_back(fail_reason);
        return Result::MISC_ERROR;
    }

    new_fee = total_fee;

    mtx = *new_tx;

    return Result::OK;
}

bool SignTransaction(CWallet* wallet, CMutableTransaction& mtx) {
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->SignTransaction(mtx);
}

Result CommitTransaction(CWallet* wallet, const uint256& txid, CMutableTransaction&& mtx, std::vector<std::string>& errors, uint256& bumped_txid, CReserveKey& reservekey)
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
