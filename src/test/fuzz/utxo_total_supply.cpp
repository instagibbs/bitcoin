// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <kernel/coinstats.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <txdb.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

FUZZ_TARGET(utxo_total_supply)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider, /*min=*/1296688602)}; // regtest genesis block timestamp
    /** The testing setup that creates a chainman only (no chainstate) */
    ChainTestingSetup test_setup{
        ChainType::REGTEST,
        {
            .extra_args = {
                "-testactivationheight=bip34@2",
            },
        },
    };
    // Create chainstate
    test_setup.LoadVerifyActivateChainstate();
    auto& node{test_setup.m_node};
    auto& chainman{*Assert(test_setup.m_node.chainman)};

    const auto ActiveHeight = [&]() {
        LOCK(chainman.GetMutex());
        return chainman.ActiveHeight();
    };
    const auto PrepareNextBlock = [&]() {
        // Use OP_FALSE to avoid BIP30 check from hitting early
        auto block = PrepareBlock(node, {
            .coinbase_output_script = CScript() << OP_FALSE,
        });
        // Replace OP_FALSE with OP_TRUE
        {
            CMutableTransaction tx{*block->vtx.back()};
            tx.nLockTime = 0; // Use the same nLockTime for all as we want to duplicate one of them.
            tx.vout.at(0).scriptPubKey = CScript{} << OP_TRUE;
            block->vtx.back() = MakeTransactionRef(tx);
        }
        return block;
    };

    /** The block template this fuzzer is working on */
    auto current_block = PrepareNextBlock();
    /** Append-only set of tx outpoints, entries are not removed when spent */
    std::vector<std::pair<COutPoint, CTxOut>> txos;
    /** The utxo stats at the chain tip */
    kernel::CCoinsStats utxo_stats;
    /** The total amount of coins in the utxo set */
    CAmount circulation{0};


    // Store the tx out in the txo map
    const auto StoreLastTxo = [&]() {
        // get last tx
        const CTransaction& tx = *current_block->vtx.back();
        // get last out
        const uint32_t i = tx.vout.size() - 1;
        // store it
        txos.emplace_back(COutPoint{tx.GetHash(), i}, tx.vout.at(i));
        if (current_block->vtx.size() == 1 && tx.vout.at(i).scriptPubKey[0] == OP_RETURN) {
            // also store coinbase
            const uint32_t i = tx.vout.size() - 2;
            txos.emplace_back(COutPoint{tx.GetHash(), i}, tx.vout.at(i));
        }
    };
    const auto AppendRandomTxo = [&](CMutableTransaction& tx) {
        const auto& txo = txos.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, txos.size() - 1));
        tx.vin.emplace_back(txo.first);
        tx.vout.emplace_back(txo.second.nValue, txo.second.scriptPubKey); // "Forward" coin with no fee
    };
    const auto UpdateUtxoStats = [&](bool wipe_cache) {
        LOCK(chainman.GetMutex());
        chainman.ActiveChainstate().ForceFlushStateToDisk(wipe_cache);
        utxo_stats = std::move(
            *Assert(kernel::ComputeUTXOStats(kernel::CoinStatsHashType::HASH_SERIALIZED, chainman.ActiveChainstate().CoinsDB(), chainman.m_blockman, {})));
        // Check that miner can't print more money than they are allowed to
        assert(circulation == utxo_stats.total_amount);
        const CBlockIndex* tip{chainman.ActiveChain().Tip()};
        assert(tip);
        assert(utxo_stats.nHeight == tip->nHeight);
        assert(utxo_stats.hashBlock == tip->GetBlockHash());
        assert(chainman.ActiveChainstate().CoinsTip().GetBestBlock() == tip->GetBlockHash());
        Assert(node.mempool)->check(chainman.ActiveChainstate().CoinsTip(), tip->nHeight + 1);
    };


    // Update internal state to chain tip
    StoreLastTxo();
    UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());
    assert(ActiveHeight() == 0);
    // Get at which height we duplicate the coinbase
    // Assuming that the fuzzer will mine relatively short chains (less than 200 blocks), we want the duplicate coinbase to be not too high.
    // Up to 300 seems reasonable.
    int64_t duplicate_coinbase_height = fuzzed_data_provider.ConsumeIntegralInRange(0, 300);
    // Avoid bad-cb-length error at heights <= 16. Pad the BIP34-encoded height
    // with OP_0 to satisfy the minimum 2-byte coinbase scriptSig length.
    CScript duplicate_coinbase_script = CScript() << duplicate_coinbase_height;
    if (duplicate_coinbase_height <= 16) {
        duplicate_coinbase_script << OP_0;
    }
    // Mine the first block with this duplicate
    current_block = PrepareNextBlock();
    StoreLastTxo();

    {
        // Create duplicate (CScript should match exact format as in CreateNewBlock)
        CMutableTransaction tx{*current_block->vtx.front()};
        tx.vin.at(0).scriptSig = duplicate_coinbase_script;

        // Mine block and create next block template
        current_block->vtx.front() = MakeTransactionRef(tx);
    }
    current_block->hashMerkleRoot = BlockMerkleRoot(*current_block);
    assert(!MineBlock(node, current_block).IsNull());
    circulation += GetBlockSubsidy(ActiveHeight(), Params().GetConsensus());

    assert(ActiveHeight() == 1);
    UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());
    current_block = PrepareNextBlock();
    StoreLastTxo();

    // Limit to avoid timeout, but enough to cover duplicate_coinbase_height
    // and CVE-2018-17144.
    LIMITED_WHILE (fuzzed_data_provider.remaining_bytes(), 2'00) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Append an input-output pair to the last tx in the current block
                CMutableTransaction tx{*current_block->vtx.back()};
                AppendRandomTxo(tx);
                current_block->vtx.back() = MakeTransactionRef(tx);
                StoreLastTxo();
            },
            [&] {
                // Append a tx to the list of txs in the current block
                CMutableTransaction tx{};
                AppendRandomTxo(tx);
                current_block->vtx.push_back(MakeTransactionRef(tx));
                StoreLastTxo();
            },
            [&] {
                // Append the current block to the active chain
                node::RegenerateCommitments(*current_block, chainman);
                const bool was_valid = !MineBlock(node, current_block).IsNull();

                const uint256 prev_hash_serialized{utxo_stats.hashSerialized};
                if (was_valid) {
                    if (duplicate_coinbase_height == ActiveHeight()) {
                        // we mined the duplicate coinbase
                        assert(current_block->vtx.at(0)->vin.at(0).scriptSig == duplicate_coinbase_script);
                    }

                    circulation += GetBlockSubsidy(ActiveHeight(), Params().GetConsensus());
                }

                UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());

                if (!was_valid) {
                    // utxo stats must not change
                    assert(prev_hash_serialized == utxo_stats.hashSerialized);
                }

                current_block = PrepareNextBlock();
                StoreLastTxo();
            });
    }

    if (!buffer.empty() && (buffer.back() & 2) != 0 && ActiveHeight() >= 2) {
        std::optional<std::pair<COutPoint, Coin>> spendable;
        {
            LOCK(chainman.GetMutex());
            const int spend_height{chainman.ActiveHeight() + 1};
            for (const auto& [outpoint, _] : txos) {
                const Coin& coin{chainman.ActiveChainstate().CoinsTip().AccessCoin(outpoint)};
                if (!coin.IsSpent() &&
                    (!coin.IsCoinBase() || spend_height - coin.nHeight >= COINBASE_MATURITY) &&
                    coin.out.scriptPubKey == (CScript{} << OP_TRUE)) {
                    spendable.emplace(outpoint, coin);
                    break;
                }
            }
        }
        if (spendable) {
            auto spend_block{PrepareNextBlock()};
            CMutableTransaction spend;
            spend.vin.emplace_back(spendable->first);
            spend.vout.emplace_back(spendable->second.out.nValue, spendable->second.out.scriptPubKey);
            spend_block->vtx.push_back(MakeTransactionRef(spend));
            node::RegenerateCommitments(*spend_block, chainman);
            assert(!MineBlock(node, spend_block).IsNull());
            circulation += GetBlockSubsidy(ActiveHeight(), Params().GetConsensus());
            UpdateUtxoStats(/*wipe_cache=*/false);
        }

        const int original_height{ActiveHeight()};
        const uint256 original_utxo_hash{utxo_stats.hashSerialized};
        CBlockIndex* original_tip;
        CBlockIndex* original_fork_child;
        {
            LOCK(chainman.GetMutex());
            original_tip = chainman.ActiveChain().Tip();
            assert(original_tip);
            original_fork_child = original_tip->pprev;
            assert(original_fork_child && original_fork_child->pprev);
        }

        BlockValidationState state;
        assert(chainman.ActiveChainstate().InvalidateBlock(state, original_fork_child));
        assert(ActiveHeight() == original_height - 2);
        circulation -= GetBlockSubsidy(original_height, Params().GetConsensus());
        circulation -= GetBlockSubsidy(original_height - 1, Params().GetConsensus());
        UpdateUtxoStats(/*wipe_cache=*/false);

        auto alternative_block{PrepareNextBlock()};
        {
            CMutableTransaction coinbase{*alternative_block->vtx.front()};
            ++coinbase.version; // Ensure this fork block differs from the original block at the same height.
            alternative_block->vtx.front() = MakeTransactionRef(coinbase);
        }
        node::RegenerateCommitments(*alternative_block, chainman);
        assert(!MineBlock(node, alternative_block).IsNull());
        assert(ActiveHeight() == original_height - 1);
        circulation += GetBlockSubsidy(original_height - 1, Params().GetConsensus());
        UpdateUtxoStats(/*wipe_cache=*/true);

        {
            LOCK(chainman.GetMutex());
            chainman.ActiveChainstate().ResetBlockFailureFlags(original_fork_child);
            chainman.RecalculateBestHeader();
        }
        state = BlockValidationState{};
        assert(chainman.ActiveChainstate().ActivateBestChain(state));
        assert(ActiveHeight() == original_height);
        circulation += GetBlockSubsidy(original_height, Params().GetConsensus());
        UpdateUtxoStats(/*wipe_cache=*/false);

        assert(WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip()) == original_tip);
        assert(utxo_stats.hashSerialized == original_utxo_hash);
        chainman.CheckBlockIndex();
    }
}
