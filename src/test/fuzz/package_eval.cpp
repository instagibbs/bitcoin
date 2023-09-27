// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <util/rbf.h>
#include <validation.h>
#include <validationinterface.h>

using node::BlockAssembler;
using node::NodeContext;

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_outpoints_coinbase_init_mature;
std::vector<COutPoint> g_outpoints_coinbase_init_immature;

struct MockedTxPool : public CTxMemPool {
    void RollingFeeUpdate() EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        lastRollingFeeUpdate = GetTime();
        blockSinceLastRollingFeeBump = true;
    }
};

// Allows (failed) wtxid replacement by leaving it up to spend time to provide truth-y value
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

void initialize_tx_pool()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(g_setup->m_node, P2WSH_EMPTY)};
        // Remember the txids to avoid expensive disk access later on
        auto& outpoints = i < COINBASE_MATURITY ?
                              g_outpoints_coinbase_init_mature :
                              g_outpoints_coinbase_init_immature;
        outpoints.push_back(prevout);
    }
    SyncWithValidationInterfaceQueue();
}

struct OutpointsUpdater final : public CValidationInterface {
    std::set<COutPoint>& m_mempool_outpoints;

    explicit OutpointsUpdater(std::set<COutPoint>& r)
        : m_mempool_outpoints{r} {}

    void TransactionAddedToMempool(const CTransactionRef& tx, uint64_t /* mempool_sequence */) override
    {
        // for coins spent we always want to be able to rbf so they're not removed

        // outputs from this tx can now be spent
        for (uint32_t index{0}; index < tx->vout.size(); ++index) {
            m_mempool_outpoints.insert(COutPoint{tx->GetHash(), index});
        }
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        // outpoints spent by this tx are now available
        for (const auto& input : tx->vin) {
            // Could already exist if this was a replacement
            m_mempool_outpoints.insert(input.prevout);
        }
        // outpoints created by this tx no longer exist
        for (uint32_t index{0}; index < tx->vout.size(); ++index) {
            m_mempool_outpoints.erase(COutPoint{tx->GetHash(), index});
        }
    }
};

struct TransactionsDelta final : public CValidationInterface {
    std::set<CTransactionRef>& m_removed;
    std::set<CTransactionRef>& m_added;

    explicit TransactionsDelta(std::set<CTransactionRef>& r, std::set<CTransactionRef>& a)
        : m_removed{r}, m_added{a} {}

    void TransactionAddedToMempool(const CTransactionRef& tx, uint64_t /* mempool_sequence */) override
    {
        // Transactions may be entered and booted any number of times
        m_added.insert(tx);
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        // Transactions may be entered and booted any number of times
        m_removed.insert(tx);
    }
};

void Finish(FuzzedDataProvider& fuzzed_data_provider, MockedTxPool& tx_pool, Chainstate& chainstate)
{
    WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
    {
        BlockAssembler::Options options;
        options.nBlockMaxWeight = fuzzed_data_provider.ConsumeIntegralInRange(0U, MAX_BLOCK_WEIGHT);
        options.blockMinFeeRate = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        auto assembler = BlockAssembler{chainstate, &tx_pool, options};
        auto block_template = assembler.CreateNewBlock(CScript{} << OP_TRUE);
    }
    const auto info_all = tx_pool.infoAll();
    if (!info_all.empty()) {
        const auto& tx_to_remove = *PickValue(fuzzed_data_provider, info_all).tx;
        const auto tx_it = WITH_LOCK(tx_pool.cs, return tx_pool.mapTx.find(tx_to_remove.GetHash()));
        size_t num_descendants = tx_it->GetCountWithDescendants();
        WITH_LOCK(tx_pool.cs, tx_pool.removeRecursive(tx_to_remove, MemPoolRemovalReason::BLOCK /* dummy */));
        std::vector<uint256> all_txids;
        tx_pool.queryHashes(all_txids);
        assert(all_txids.size() == info_all.size() - num_descendants);
        WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
    }
    SyncWithValidationInterfaceQueue();
}

void MockTime(FuzzedDataProvider& fuzzed_data_provider, const Chainstate& chainstate)
{
    const auto time = ConsumeTime(fuzzed_data_provider,
                                  chainstate.m_chain.Tip()->GetMedianTimePast() + 1,
                                  std::numeric_limits<decltype(chainstate.m_chain.Tip()->nTime)>::max());
    SetMockTime(time);
}

CTxMemPool MakeMempool(FuzzedDataProvider& fuzzed_data_provider, const NodeContext& node)
{
    // Take the default options for tests...
    CTxMemPool::Options mempool_opts{MemPoolOptionsForTest(node)};


    // ...override specific options for this specific fuzz suite
    mempool_opts.limits.ancestor_count = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 50);
    mempool_opts.limits.ancestor_size_vbytes = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 202) * 1'000;
    mempool_opts.limits.descendant_count = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 50);
    mempool_opts.limits.descendant_size_vbytes = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 202) * 1'000;
    mempool_opts.max_size_bytes = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200) * 1'000'000;
    mempool_opts.expiry = std::chrono::hours{fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 999)};
    nBytesPerSigOp = fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(1, 999);

    mempool_opts.estimator = nullptr;
    mempool_opts.check_ratio = 1;
    mempool_opts.require_standard = fuzzed_data_provider.ConsumeBool();

    // ...and construct a CTxMemPool from it
    return CTxMemPool{mempool_opts};
}

CTransactionRef CreatePackageTxn(FuzzedDataProvider& fuzzed_data_provider, std::set<COutPoint>& mempool_outpoints, std::set<COutPoint>& package_outpoints, std::map<COutPoint, CAmount>& outpoints_value, std::set<uint256>& txids_to_spend)
{
    CMutableTransaction tx_mut;
    tx_mut.nVersion = CTransaction::CURRENT_VERSION;
    tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    size_t total_outpoints = mempool_outpoints.size() + package_outpoints.size();

    Assume(total_outpoints > 0);

    const auto num_in = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, total_outpoints);
    const auto num_out = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, total_outpoints * 2);

    // We want to allow double-spends, so these are re-added
    std::vector<COutPoint> outpoints_to_restore;
    std::vector<COutPoint> package_outpoints_to_restore;

    CAmount amount_in{0};
    for (size_t i = 0; i < (size_t) num_in; ++i) {
        // Grab arbitrary outpoint set that is non-empty
        bool is_package_outpoint = mempool_outpoints.empty() ||
            (!package_outpoints.empty() && fuzzed_data_provider.ConsumeBool());
        auto& outpoints = is_package_outpoint ? package_outpoints : mempool_outpoints;
        assert(!outpoints.empty());

        // Pop random outpoint
        auto pop = outpoints.begin();
        std::advance(pop, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, outpoints.size() - 1));
        const auto outpoint = *pop;
        outpoints.erase(pop);
        // no need to update or erase from outpoints_value
        amount_in += outpoints_value.at(outpoint);

        // Create input
        const auto sequence = ConsumeSequence(fuzzed_data_provider);
        const auto script_sig = CScript{};
        const auto script_wit_stack = fuzzed_data_provider.ConsumeBool() ? P2WSH_EMPTY_TRUE_STACK : P2WSH_EMPTY_TWO_STACK;
        CTxIn in;
        in.prevout = outpoint;
        in.nSequence = sequence;
        in.scriptSig = script_sig;
        in.scriptWitness.stack = script_wit_stack;

        tx_mut.vin.push_back(in);

        if (!is_package_outpoint) {
            outpoints_to_restore.emplace_back(outpoint);
        } else {
            package_outpoints_to_restore.emplace_back(outpoint);
        }

        txids_to_spend.erase(outpoint.hash);
    }

    // Duplicate an input
    if (fuzzed_data_provider.ConsumeBool()) {
        tx_mut.vin.push_back(tx_mut.vin.back());
    }

    // Refer to a non-existant input
    if (fuzzed_data_provider.ConsumeBool()) {
        tx_mut.vin.emplace_back();
    }

    const auto amount_fee = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, amount_in);
    const auto amount_out = (amount_in - amount_fee) / num_out;
    for (int i = 0; i < num_out; ++i) {
        tx_mut.vout.emplace_back(amount_out, P2WSH_EMPTY);
    }

    // TODO vary transaction sizes to catch size-related issues
    auto tx = MakeTransactionRef(tx_mut);
    // Restore all spent outpoints to their spots to allow RBF attempts and in case of rejection
    for (const auto& out : outpoints_to_restore) {
        Assert(mempool_outpoints.insert(out).second);
    }
    for (const auto& out : package_outpoints_to_restore) {
        Assert(package_outpoints.insert(out).second);
    }
    // We need newly-created values for the duration of this run
    for (size_t i = 0; i < tx->vout.size(); ++i) {
        outpoints_value[COutPoint(tx->GetHash(), i)] = tx->vout[i].nValue;
    }
    txids_to_spend.insert(tx->GetHash());
    return tx;
}

CTransactionRef CreateChildTxn(FuzzedDataProvider& fuzzed_data_provider, std::set<COutPoint>& mempool_outpoints, std::set<COutPoint>& package_outpoints, std::map<COutPoint, CAmount>& outpoints_value, std::set<uint256>& txids_to_spend)
{
    CMutableTransaction tx_mut;
    tx_mut.nVersion = CTransaction::CURRENT_VERSION;
    tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    size_t total_outpoints = mempool_outpoints.size() + package_outpoints.size();

    // We will add more inputs later from txids_to_spend
    const auto num_in = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, total_outpoints);
    const auto num_out = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, total_outpoints * 2);

    // We want to allow double-spends, so these are re-added
    std::vector<COutPoint> outpoints_to_restore;
    std::vector<COutPoint> package_outpoints_to_restore;

    CAmount amount_in{0};
    for (size_t i = 0; i < (size_t) num_in; ++i) {
        // Grab arbitrary outpoint set that is non-empty
        bool is_package_outpoint = mempool_outpoints.empty() ||
            (!package_outpoints.empty() && fuzzed_data_provider.ConsumeBool());
        auto& outpoints = is_package_outpoint ? package_outpoints : mempool_outpoints;
        assert(!outpoints.empty());

        // Pop random outpoint
        auto pop = outpoints.begin();
        std::advance(pop, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, outpoints.size() - 1));
        const auto outpoint = *pop;
        outpoints.erase(pop);
        // no need to update or erase from outpoints_value
        amount_in += outpoints_value.at(outpoint);

        // Create input
        const auto sequence = ConsumeSequence(fuzzed_data_provider);
        const auto script_sig = CScript{};
        const auto script_wit_stack = fuzzed_data_provider.ConsumeBool() ? P2WSH_EMPTY_TRUE_STACK : P2WSH_EMPTY_TWO_STACK;


        CTxIn in;
        in.prevout = outpoint;
        in.nSequence = sequence;
        in.scriptSig = script_sig;
        in.scriptWitness.stack = script_wit_stack;

        tx_mut.vin.push_back(in);

        if (!is_package_outpoint) {
            outpoints_to_restore.emplace_back(outpoint);
        }

        txids_to_spend.erase(outpoint.hash);
    }

    // Now try to ensure this is a child tx
    for (const auto txid_to_spend : txids_to_spend) {

        // We know these transactions have no spends yet, so just spend index 0
        const auto outpoint = COutPoint(txid_to_spend, 0);

        // Create input
        const auto sequence = ConsumeSequence(fuzzed_data_provider);
        const auto script_sig = CScript{};
        const auto script_wit_stack = fuzzed_data_provider.ConsumeBool() ? P2WSH_EMPTY_TRUE_STACK : P2WSH_EMPTY_TWO_STACK;

        CTxIn in;
        in.prevout = outpoint;
        in.nSequence = sequence;
        in.scriptSig = script_sig;
        in.scriptWitness.stack = script_wit_stack;

        tx_mut.vin.push_back(in);
    }

    const auto amount_fee = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, amount_in);
    const auto amount_out = (amount_in - amount_fee) / num_out;
    for (int i = 0; i < num_out; ++i) {
        tx_mut.vout.emplace_back(amount_out, P2WSH_EMPTY);
    }
    // TODO vary transaction sizes to catch size-related issues
    auto tx = MakeTransactionRef(tx_mut);

    // Restore all spent outpoints to their spots to allow RBF attempts and in case of rejection
    for (const auto& out : outpoints_to_restore) {
        Assert(mempool_outpoints.insert(out).second);
    }

    // We need newly-created values for the duration of this run
    for (size_t i = 0; i < tx->vout.size(); ++i) {
        outpoints_value[COutPoint(tx->GetHash(), i)] = tx->vout[i].nValue;
    }
    return tx;
}


FUZZ_TARGET(tx_package_eval, .init = initialize_tx_pool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const auto& node = g_setup->m_node;
    auto& chainstate{static_cast<DummyChainState&>(node.chainman->ActiveChainstate())};

    MockTime(fuzzed_data_provider, chainstate);

    // All RBF-spendable outpoints outside of the unsubmitted package
    std::set<COutPoint> mempool_outpoints;
    std::map<COutPoint, CAmount> outpoints_value;
    for (const auto& outpoint : g_outpoints_coinbase_init_mature) {
        Assert(mempool_outpoints.insert(outpoint).second);
        outpoints_value[outpoint] = 50 * COIN;
    }

    auto outpoints_updater = std::make_shared<OutpointsUpdater>(mempool_outpoints);
    RegisterSharedValidationInterface(outpoints_updater);

    CTxMemPool tx_pool_{MakeMempool(fuzzed_data_provider, node)};
    MockedTxPool& tx_pool = *static_cast<MockedTxPool*>(&tx_pool_);

    chainstate.SetMempool(&tx_pool);

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 300)
    {
        Assert(!mempool_outpoints.empty());

        std::vector<CTransactionRef> txs;
        std::map<uint256, CTransactionRef> wtxid_to_tx;


        // Make packages of 1-to-26 transactions
        const auto num_txs = (size_t) fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 26);
        std::set<COutPoint> package_outpoints;
        std::set<uint256> txids_to_spend;
        while (txs.size() < num_txs) {

            // Last transaction in a package needs to be a descendant of ancestors to get further in validation
            // so the last transaction to be generated(in a >1 package) must spend additional outputs potentially.
            // We will make sure of this by making sure each non-child transaction has at least one spent output.
            bool child_tx = fuzzed_data_provider.ConsumeBool() && num_txs > 1 && txs.size() == num_txs - 1;

            const CTransactionRef tx = child_tx ? CreateChildTxn(fuzzed_data_provider, mempool_outpoints, package_outpoints, outpoints_value, txids_to_spend) :
                CreatePackageTxn(fuzzed_data_provider, mempool_outpoints, package_outpoints, outpoints_value, txids_to_spend);

            txs.push_back(tx);
            wtxid_to_tx[tx->GetWitnessHash()] = tx;
        }

        if (fuzzed_data_provider.ConsumeBool()) {
            MockTime(fuzzed_data_provider, chainstate);
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            tx_pool.RollingFeeUpdate();
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            const auto& txid = fuzzed_data_provider.ConsumeBool() ?
                                   txs.back()->GetHash() :
                                   PickValue(fuzzed_data_provider, mempool_outpoints).hash;
            const auto delta = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(-50 * COIN, +50 * COIN);
            tx_pool.PrioritiseTransaction(txid, delta);
        }

        // Remember all removed and added transactions
        std::set<CTransactionRef> removed;
        std::set<CTransactionRef> added;
        auto txr = std::make_shared<TransactionsDelta>(removed, added);
        RegisterSharedValidationInterface(txr);
        const bool bypass_limits = fuzzed_data_provider.ConsumeBool();

        // When there are multiple transactions in the package, we call ProcessNewPackage(txs, test_accept=false)
        // and AcceptToMemoryPool(txs.back(), test_accept=true). When there is only 1 transaction, we might flip it
        // (the package is a test accept and ATMP is a submission).
        auto single_submit = txs.size() == 1 && fuzzed_data_provider.ConsumeBool();
        auto package_submit = !single_submit;

        const auto result_package = WITH_LOCK(::cs_main,
                                    return ProcessNewPackage(chainstate, tx_pool, txs, /*test_accept=*/!package_submit));
        // If something went wrong due to a package-specific policy, it might not return a
        // validation result for the transaction.
        if (result_package.m_state.GetResult() != PackageValidationResult::PCKG_POLICY) {
            auto it = result_package.m_tx_results.find(txs.back()->GetWitnessHash());
            Assert(it != result_package.m_tx_results.end());
            Assert(it->second.m_result_type == MempoolAcceptResult::ResultType::VALID ||
                   it->second.m_result_type == MempoolAcceptResult::ResultType::INVALID ||
                   it->second.m_result_type == MempoolAcceptResult::ResultType::MEMPOOL_ENTRY ||
                   it->second.m_result_type == MempoolAcceptResult::ResultType::DIFFERENT_WITNESS);
        }

        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(chainstate, txs.back(), GetTime(), bypass_limits, /*test_accept=*/!single_submit));
        const bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;

        SyncWithValidationInterfaceQueue();
        UnregisterSharedValidationInterface(txr);

        // There is only 1 transaction in the package. We did a test-package-accept and a ATMP
        if (single_submit) {
            Assert(accepted != added.empty());
            Assert(accepted == res.m_state.IsValid());
            if (accepted) {
                Assert(added.size() == 1);
                Assert(txs.back() == *added.begin());
            } else {
                // Do not consider rejected transaction removed
                removed.erase(txs.back());
            }
        } else {
            // This is empty if it fails early checks, or "full" if transactions are looked at deeper
            Assert(result_package.m_tx_results.size() == txs.size() || result_package.m_tx_results.empty());
            if (result_package.m_state.GetResult() == PackageValidationResult::PCKG_POLICY) {
                for (const auto& tx : txs) {
                    removed.erase(tx);
                }
            } else {
                for (const auto& [k, v] : result_package.m_tx_results) {
                    if (v.m_result_type == MempoolAcceptResult::ResultType::INVALID) {
                        removed.erase(wtxid_to_tx[k]);
                    }
                }
            }
        }
    }

    UnregisterSharedValidationInterface(outpoints_updater);

    Finish(fuzzed_data_provider, tx_pool, chainstate);
}
} // namespace
