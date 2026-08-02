// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <kernel/coinstats.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/time.h>
#include <validation.h>

#include <cstdint>
#include <functional>
#include <ios>
#include <memory>
#include <optional>
#include <vector>

using node::SnapshotMetadata;

namespace {

const std::vector<std::shared_ptr<CBlock>>* g_chain;
TestingSetup* g_setup{nullptr};

/** Sanity check the assumeutxo values hardcoded in chainparams for the fuzz target. */
void sanity_check_snapshot()
{
    Assert(g_chain && g_setup == nullptr);

    // Create a temporary chainstate manager to connect the chain to.
    const auto tmp_setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, TestOpts{.setup_net = false})};
    const auto& node{tmp_setup->m_node};
    for (auto& block: *g_chain) {
        ProcessBlock(node, block);
    }

    // Connect the chain to the tmp chainman and sanity check the chainparams snapshot values.
    LOCK(cs_main);
    auto& cs{node.chainman->ActiveChainstate()};
    cs.ForceFlushStateToDisk(/*wipe_cache=*/false);
    const auto stats{*Assert(kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED, cs.CoinsDB(), node.chainman->m_blockman))};
    const auto cp_au_data{*Assert(node.chainman->GetParams().AssumeutxoForHeight(2 * COINBASE_MATURITY))};
    Assert(stats.nHeight == cp_au_data.height);
    Assert(stats.nTransactions + 1 == cp_au_data.m_chain_tx_count); // +1 for the genesis tx.
    Assert(stats.hashBlock == cp_au_data.blockhash);
    Assert(AssumeutxoHash{stats.hashSerialized} == cp_au_data.hash_serialized);
}

void initialize_snapshot_chain()
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    static const auto chain{CreateBlockChain(2 * COINBASE_MATURITY, *params)};
    g_chain = &chain;
    SetMockTime(chain.back()->Time());

    // Make sure we can generate a valid snapshot.
    sanity_check_snapshot();
}

template <bool INVALID>
void initialize_chain()
{
    initialize_snapshot_chain();

    static const auto setup{
        MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST,
                                           TestOpts{
                                               .setup_net = false,
                                               .setup_validation_interface = false,
                                               .min_validation_cache = true,
                                           }),
    };
    if constexpr (INVALID) {
        auto& chainman{*setup->m_node.chainman};
        for (const auto& block : *g_chain) {
            BlockValidationState dummy;
            bool processed{chainman.ProcessNewBlockHeaders({{*block}}, true, dummy)};
            Assert(processed);
            const auto* index{WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
            Assert(index);
        }
    }
    g_setup = setup.get();
}

template <bool INVALID>
void utxo_snapshot_fuzz(FuzzBufferType buffer)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider, /*min=*/1296688602)}; // regtest genesis block timestamp
    auto& setup{*g_setup};
    bool dirty_chainman{false}; // Reuse the global chainman, but reset it when it is dirty
    auto& chainman{*setup.m_node.chainman};

    const auto snapshot_path = gArgs.GetDataDirNet() / "fuzzed_snapshot.dat";

    Assert(!chainman.ActiveChainstate().m_from_snapshot_blockhash);

    {
        AutoFile outfile{fsbridge::fopen(snapshot_path, "wb")};
        // Metadata
        if (fuzzed_data_provider.ConsumeBool()) {
            std::vector<uint8_t> metadata{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
            outfile << std::span{metadata};
        } else {
            auto msg_start = chainman.GetParams().MessageStart();
            int base_blockheight{fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 2 * COINBASE_MATURITY)};
            uint256 base_blockhash{g_chain->at(base_blockheight - 1)->GetHash()};
            uint64_t m_coins_count{fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(1, 3 * COINBASE_MATURITY)};
            SnapshotMetadata metadata{msg_start, base_blockhash, m_coins_count};
            outfile << metadata;
        }
        // Coins
        if (fuzzed_data_provider.ConsumeBool()) {
            std::vector<uint8_t> file_data{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
            outfile << std::span{file_data};
        } else {
            int height{1};
            for (const auto& block : *g_chain) {
                auto coinbase{block->vtx.at(0)};
                outfile << coinbase->GetHash();
                WriteCompactSize(outfile, 1); // number of coins for the hash
                WriteCompactSize(outfile, 0); // index of coin
                outfile << Coin(coinbase->vout[0], height, /*fCoinBaseIn=*/true);
                height++;
            }
        }
        if constexpr (INVALID) {
            // Append an invalid coin to ensure invalidity. This error will be
            // detected late in PopulateAndValidateSnapshot, and allows the
            // INVALID fuzz target to reach more potential code coverage.
            const auto& coinbase{g_chain->back()->vtx.back()};
            outfile << coinbase->GetHash();
            WriteCompactSize(outfile, 1);   // number of coins for the hash
            WriteCompactSize(outfile, 999); // index of coin
            outfile << Coin{coinbase->vout[0], /*nHeightIn=*/999, /*fCoinBaseIn=*/false};
        }
        assert(outfile.fclose() == 0);
    }

    const auto ActivateFuzzedSnapshot{[&] {
        AutoFile infile{fsbridge::fopen(snapshot_path, "rb")};
        auto msg_start = chainman.GetParams().MessageStart();
        SnapshotMetadata metadata{msg_start};
        try {
            infile >> metadata;
        } catch (const std::ios_base::failure&) {
            return false;
        }
        return !!chainman.ActivateSnapshot(infile, metadata, /*in_memory=*/true);
    }};

    if (fuzzed_data_provider.ConsumeBool()) {
        // Consume the bool, but skip the code for the INVALID fuzz target
        if constexpr (!INVALID) {
            for (const auto& block : *g_chain) {
                BlockValidationState dummy;
                bool processed{chainman.ProcessNewBlockHeaders({{*block}}, true, dummy)};
                Assert(processed);
                const auto* index{WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
                Assert(index);
            }
            dirty_chainman = true;
        }
    }

    const bool complete_snapshot_validation{fuzzed_data_provider.ConsumeBool()};
    if (ActivateFuzzedSnapshot()) {
        {
            LOCK(::cs_main);
            Assert(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());
            const auto& coinscache{chainman.ActiveChainstate().CoinsTip()};
            for (const auto& block : *g_chain) {
                Assert(coinscache.HaveCoin(COutPoint{block->vtx.at(0)->GetHash(), 0}));
                const auto* index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
                Assert(index);
                Assert(index->nTx == 0);
                if (index->nHeight == chainman.ActiveChainstate().SnapshotBase()->nHeight) {
                    auto params{chainman.GetParams().AssumeutxoForHeight(index->nHeight)};
                    Assert(params.has_value());
                    Assert(params.value().m_chain_tx_count == index->m_chain_tx_count);
                } else {
                    Assert(index->m_chain_tx_count == 0);
                }
            }
            Assert(g_chain->size() == coinscache.GetCacheSize());
        }

        if (complete_snapshot_validation) {
            Chainstate* const background_chainstate{WITH_LOCK(::cs_main, return chainman.HistoricalChainstate())};
            Assert(background_chainstate);
            const uint256 snapshot_tip{WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash())};

            for (const auto& block : *g_chain) {
                bool new_block{false};
                Assert(chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
                Assert(new_block);

                LOCK(::cs_main);
                Assert(chainman.ActiveTip()->GetBlockHash() == snapshot_tip);
                Assert(background_chainstate->m_chain.Tip()->GetBlockHash() == block->GetHash());
                Assert(background_chainstate->CoinsTip().GetBestBlock() == block->GetHash());
            }

            LOCK(::cs_main);
            const auto params{chainman.GetParams().AssumeutxoForHeight(g_chain->size())};
            Assert(params);
            Assert(!chainman.HistoricalChainstate());
            Assert(chainman.ActiveChainstate().m_assumeutxo == Assumeutxo::VALIDATED);
            Assert(background_chainstate->ReachedTarget());
            Assert(background_chainstate->m_target_utxohash);
            Assert(*background_chainstate->m_target_utxohash == params->hash_serialized);
            Assert(chainman.ActiveChainstate().CoinsTip().GetBestBlock() == snapshot_tip);
            for (const auto& block : *g_chain) {
                const COutPoint outpoint{block->vtx.at(0)->GetHash(), 0};
                const auto snapshot_coin{chainman.ActiveChainstate().CoinsTip().GetCoin(outpoint)};
                const auto background_coin{background_chainstate->CoinsTip().GetCoin(outpoint)};
                Assert(snapshot_coin && background_coin);
                Assert(snapshot_coin->out == background_coin->out);
                Assert(snapshot_coin->nHeight == background_coin->nHeight);
                Assert(snapshot_coin->fCoinBase == background_coin->fCoinBase);
            }
            chainman.CheckBlockIndex();
        }
        dirty_chainman = true;
    } else {
        Assert(!chainman.ActiveChainstate().m_from_snapshot_blockhash);
    }
    // Snapshot should refuse to load a second time regardless of validity
    Assert(!ActivateFuzzedSnapshot());
    if constexpr (INVALID) {
        // Activating the snapshot, or any other action that makes the chainman
        // "dirty" can and must not happen for the INVALID fuzz target
        Assert(!dirty_chainman);
    }
    if (dirty_chainman) {
        setup.m_node.chainman.reset();
        setup.m_make_chainman();
        setup.LoadVerifyActivateChainstate();
    }
}

/** Exercise on-disk snapshot validation and recovery across node restarts. */
void utxo_snapshot_persistence_fuzz(FuzzBufferType buffer)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(provider, /*min=*/1296688602)};
    const bool corrupt_background{provider.ConsumeBool()};
    const size_t expected_snapshot_download_completed_calls{corrupt_background ? 0U : 1U};
    const size_t restart_height{
        provider.ConsumeIntegralInRange<size_t>(0, g_chain->size() - 1)};

    ChainTestingSetup setup{
        ChainType::REGTEST,
        TestOpts{
            .block_tree_db_in_memory = false,
            .setup_net = false,
            .setup_validation_interface = false,
            .min_validation_cache = true,
        },
    };
    setup.m_coins_db_in_memory = false;
    setup.LoadVerifyActivateChainstate();
    setup.m_node.notifications->m_shutdown_on_fatal_error = false;
    auto& chainman{*Assert(setup.m_node.chainman)};
    const auto& params{chainman.GetParams()};
    size_t snapshot_download_completed_calls{0};
    const auto install_snapshot_completion_callback = [&](ChainstateManager& manager) {
        manager.snapshot_download_completed = [&, expected_manager = &manager] {
            AssertLockNotHeld(::cs_main);
            Assert(setup.m_node.chainman.get() == expected_manager);
            Assert(++snapshot_download_completed_calls == 1);
            Assert(WITH_LOCK(
                expected_manager->GetMutex(),
                return expected_manager->HistoricalChainstate()) == nullptr);
        };
    };
    install_snapshot_completion_callback(chainman);

    for (const auto& block : *g_chain) {
        BlockValidationState state;
        const CBlockIndex* accepted{nullptr};
        Assert(chainman.ProcessNewBlockHeaders(
            {{*block}}, /*min_pow_checked=*/true, state, &accepted));
        Assert(state.IsValid());
        Assert(accepted);
        Assert(accepted->GetBlockHash() == block->GetHash());
    }

    const fs::path snapshot_file{setup.m_args.GetDataDirNet() / "persistent_snapshot.dat"};
    const SnapshotMetadata metadata{
        params.MessageStart(), g_chain->back()->GetHash(), g_chain->size()};
    {
        AutoFile outfile{fsbridge::fopen(snapshot_file, "wb")};
        Assert(!outfile.IsNull());
        outfile << metadata;
        int height{1};
        for (const auto& block : *g_chain) {
            const CTransactionRef& coinbase{block->vtx.front()};
            outfile << coinbase->GetHash();
            WriteCompactSize(outfile, 1);
            WriteCompactSize(outfile, 0);
            outfile << Coin{coinbase->vout.front(), height++, /*fCoinBaseIn=*/true};
        }
        Assert(outfile.fclose() == 0);
    }
    {
        AutoFile infile{fsbridge::fopen(snapshot_file, "rb")};
        Assert(!infile.IsNull());
        SnapshotMetadata loaded{params.MessageStart()};
        infile >> loaded;
        Assert(loaded.m_base_blockhash == metadata.m_base_blockhash);
        Assert(loaded.m_coins_count == metadata.m_coins_count);
        Assert(chainman.ActivateSnapshot(infile, loaded, /*in_memory=*/false));
        Assert(infile.fclose() == 0);
    }

    const fs::path default_dir{setup.m_args.GetDataDirNet() / "chainstate"};
    const fs::path snapshot_dir{setup.m_args.GetDataDirNet() / "chainstate_snapshot"};
    const fs::path invalid_dir{setup.m_args.GetDataDirNet() / "chainstate_snapshot_INVALID"};
    const fs::path delete_dir{setup.m_args.GetDataDirNet() / "chainstate_todelete"};
    Assert(fs::exists(default_dir));
    Assert(fs::exists(snapshot_dir));
    Assert(!fs::exists(invalid_dir));
    Assert(!fs::exists(delete_dir));

    kernel::CCoinsStats expected_stats;
    {
        LOCK(chainman.GetMutex());
        Chainstate& snapshot{chainman.ActiveChainstate()};
        Assert(chainman.m_chainstates.size() == 2);
        Assert(snapshot.m_from_snapshot_blockhash == metadata.m_base_blockhash);
        Assert(snapshot.m_assumeutxo == Assumeutxo::UNVALIDATED);
        Assert(chainman.ActiveHeight() == static_cast<int>(g_chain->size()));
        Assert(chainman.ActiveTip()->GetBlockHash() == metadata.m_base_blockhash);
        Assert(Assert(chainman.HistoricalChainstate())->m_chain.Height() == 0);
        snapshot.ForceFlushStateToDisk(/*wipe_cache=*/false);
        expected_stats = *Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            snapshot.CoinsDB(),
            chainman.m_blockman));
    }
    const auto assumeutxo_data{
        *Assert(params.AssumeutxoForHeight(g_chain->size()))};
    Assert(AssumeutxoHash{expected_stats.hashSerialized} == assumeutxo_data.hash_serialized);
    Assert(expected_stats.coins_count == g_chain->size());
    Assert(expected_stats.nHeight == static_cast<int>(g_chain->size()));
    Assert(expected_stats.hashBlock == metadata.m_base_blockhash);

    const COutPoint corruption_outpoint{Txid::FromUint256(uint256::ONE), 0};
    if (corrupt_background) {
        LOCK(chainman.GetMutex());
        Chainstate& background{*Assert(chainman.HistoricalChainstate())};
        Assert(background.CoinsTip().AccessCoin(corruption_outpoint).IsSpent());
        background.CoinsTip().AddCoin(
            corruption_outpoint,
            Coin{CTxOut{COIN, CScript{} << OP_TRUE}, /*height=*/1, /*coinbase=*/false},
            /*possible_overwrite=*/false);
    }

    const auto process_blocks = [&](size_t begin, size_t end) {
        auto& current_chainman{*Assert(setup.m_node.chainman)};
        for (size_t index{begin}; index < end; ++index) {
            bool new_block{false};
            Assert(current_chainman.ProcessNewBlock(
                (*g_chain)[index],
                /*force_processing=*/true,
                /*min_pow_checked=*/true,
                &new_block));
            Assert(new_block);
        }
    };
    const auto restart = [&] {
        auto& old_chainman{*Assert(setup.m_node.chainman)};
        {
            LOCK(old_chainman.GetMutex());
            for (const auto& chainstate : old_chainman.m_chainstates) {
                if (chainstate->CanFlushToDisk()) {
                    chainstate->ForceFlushStateToDisk(/*wipe_cache=*/false);
                }
            }
        }
        setup.m_node.chainman.reset();
        setup.m_make_chainman();
        setup.LoadVerifyActivateChainstate();
        Assert(setup.m_node.chainman);
    };

    process_blocks(/*begin=*/0, restart_height);
    Assert(snapshot_download_completed_calls == 0);
    restart();
    {
        auto& restarted{*Assert(setup.m_node.chainman)};
        LOCK(restarted.GetMutex());
        Assert(restarted.m_chainstates.size() == 2);
        Assert(restarted.ActiveHeight() == static_cast<int>(g_chain->size()));
        Assert(restarted.ActiveTip()->GetBlockHash() == metadata.m_base_blockhash);
        Assert(restarted.CurrentChainstate().m_assumeutxo == Assumeutxo::UNVALIDATED);
        Assert(restarted.CurrentChainstate().m_from_snapshot_blockhash ==
               metadata.m_base_blockhash);
        Chainstate& background{*Assert(restarted.HistoricalChainstate())};
        Assert(background.m_chain.Height() == static_cast<int>(restart_height));
        Assert(background.CoinsTip().GetBestBlock() ==
               (restart_height == 0
                    ? params.GetConsensus().hashGenesisBlock
                    : (*g_chain)[restart_height - 1]->GetHash()));
        Assert(background.CoinsTip().AccessCoin(corruption_outpoint).IsSpent() !=
               corrupt_background);
    }
    Assert(fs::exists(default_dir));
    Assert(fs::exists(snapshot_dir));
    Assert(!fs::exists(invalid_dir));
    Assert(!fs::exists(delete_dir));

    install_snapshot_completion_callback(*Assert(setup.m_node.chainman));
    process_blocks(restart_height, g_chain->size());
    Assert(snapshot_download_completed_calls == expected_snapshot_download_completed_calls);
    {
        auto& completed{*Assert(setup.m_node.chainman)};
        LOCK(completed.GetMutex());
        Assert(completed.m_chainstates.size() == 2);
        Assert(completed.ActiveHeight() == static_cast<int>(g_chain->size()));
        Assert(completed.ActiveTip()->GetBlockHash() == metadata.m_base_blockhash);
        Assert(!completed.HistoricalChainstate());
        if (corrupt_background) {
            Assert(!completed.CurrentChainstate().m_from_snapshot_blockhash);
            bool found_invalid{false};
            for (const auto& chainstate : completed.m_chainstates) {
                if (chainstate->m_from_snapshot_blockhash) {
                    Assert(chainstate->m_assumeutxo == Assumeutxo::INVALID);
                    found_invalid = true;
                }
            }
            Assert(found_invalid);
        } else {
            Assert(completed.CurrentChainstate().m_from_snapshot_blockhash ==
                   metadata.m_base_blockhash);
            Assert(completed.CurrentChainstate().m_assumeutxo == Assumeutxo::VALIDATED);
        }
    }
    Assert(fs::exists(default_dir));
    Assert(fs::exists(snapshot_dir) != corrupt_background);
    Assert(fs::exists(invalid_dir) == corrupt_background);

    restart();
    auto& final_chainman{*Assert(setup.m_node.chainman)};
    kernel::CCoinsStats final_stats;
    {
        LOCK(final_chainman.GetMutex());
        Chainstate& final_chainstate{final_chainman.ActiveChainstate()};
        Assert(final_chainman.m_chainstates.size() == 1);
        Assert(!final_chainstate.m_from_snapshot_blockhash);
        Assert(final_chainstate.m_assumeutxo == Assumeutxo::VALIDATED);
        Assert(final_chainman.ActiveHeight() == static_cast<int>(g_chain->size()));
        Assert(final_chainman.ActiveTip()->GetBlockHash() == metadata.m_base_blockhash);
        Assert(final_chainstate.CoinsTip().GetBestBlock() == metadata.m_base_blockhash);
        Assert(!final_chainman.HistoricalChainstate());
        for (size_t index{0}; index < g_chain->size(); ++index) {
            const CTransactionRef& coinbase{(*g_chain)[index]->vtx.front()};
            const Coin& coin{final_chainstate.CoinsTip().AccessCoin(
                COutPoint{coinbase->GetHash(), 0})};
            Assert(!coin.IsSpent());
            Assert(coin.IsCoinBase());
            Assert(coin.nHeight == static_cast<int>(index + 1));
            Assert(coin.out == coinbase->vout.front());
        }
        Assert(final_chainstate.CoinsTip().AccessCoin(corruption_outpoint).IsSpent() !=
               corrupt_background);
        final_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
        final_stats = *Assert(kernel::ComputeUTXOStats(
            kernel::CoinStatsHashType::HASH_SERIALIZED,
            final_chainstate.CoinsDB(),
            final_chainman.m_blockman));
        Assert(final_chainman.BlockIndex().size() == g_chain->size() + 1);
        final_chainman.CheckBlockIndex();
    }
    CAmount expected_supply{0};
    for (int height{1}; height <= static_cast<int>(g_chain->size()); ++height) {
        expected_supply += GetBlockSubsidy(height, params.GetConsensus());
    }
    Assert(*Assert(final_stats.total_amount) ==
           expected_supply + (corrupt_background ? COIN : 0));
    Assert(final_stats.coins_count == g_chain->size() + corrupt_background);
    Assert(final_stats.nHeight == static_cast<int>(g_chain->size()));
    Assert(final_stats.hashBlock == metadata.m_base_blockhash);
    Assert((final_stats.hashSerialized == expected_stats.hashSerialized) !=
           corrupt_background);
    Assert(snapshot_download_completed_calls == expected_snapshot_download_completed_calls);
    Assert(fs::exists(default_dir));
    Assert(!fs::exists(snapshot_dir));
    Assert(fs::exists(invalid_dir) == corrupt_background);
    Assert(!fs::exists(delete_dir));
}

// There are three fuzz targets:
//
// The target 'utxo_snapshot', which allows valid snapshots, but is slow,
// because it has to reset the chainstate manager on almost all fuzz inputs.
// Otherwise, a dirty header tree or dirty chainstate could leak from one fuzz
// input execution into the next, which makes execution non-deterministic.
//
// The target 'utxo_snapshot_invalid', which is fast and does not require any
// expensive state to be reset.
//
// The target 'utxo_snapshot_persistence', which exercises valid and corrupted
// background validation across partial syncs and on-disk restarts.
FUZZ_TARGET(utxo_snapshot /*valid*/, .init = initialize_chain<false>) { utxo_snapshot_fuzz<false>(buffer); }
FUZZ_TARGET(utxo_snapshot_invalid, .init = initialize_chain<true>) { utxo_snapshot_fuzz<true>(buffer); }
FUZZ_TARGET(utxo_snapshot_persistence, .init = initialize_snapshot_chain) { utxo_snapshot_persistence_fuzz(buffer); }

} // namespace
