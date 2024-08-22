// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <node/utxo_snapshot.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <validation.h>
#include <validationinterface.h>
#include <pow.h>

using node::SnapshotMetadata;

namespace {

const std::vector<std::shared_ptr<CBlock>>* g_chain;

void initialize_chain()
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    // Generate 5 retarget periods worth of blockheaders even though
    // we only should see 3 periods worth of blocks accepted
    std::vector<int64_t> block_times(6 * 5);
    std::iota(block_times.begin(), block_times.end(), 1);
    for (size_t i = 0; i < block_times.size(); i++) {
        block_times[i] += params->GenesisBlock().nTime;
    }
    static const auto chain{CreateBlockChainDiff(block_times, *params)};
    g_chain = &chain;
}

FUZZ_TARGET(timewarp, .init = initialize_chain)
{
    // FIXME how to model a timewarp?

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    std::unique_ptr<const TestingSetup> setup{
        MakeNoLogFileContext<const TestingSetup>(
            ChainType::REGTEST,
            TestOpts{
                .setup_net = false,
                .setup_validation_interface = false,
            })};
    const auto& node = setup->m_node;
    auto& chainman{*node.chainman};
    const Consensus::Params& consensusParams = chainman.GetConsensus();
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};

    int blocks_accepted{0};
    CBlockIndex* index{nullptr};
    for (const auto& block : *g_chain) {
        if (index != nullptr) {
            const auto next_nBits = GetNextWorkRequired(index, &(*block), consensusParams);
            if (next_nBits != block->nBits) {
                // Need to recompute new block since we changed nBits
                block->nBits = next_nBits;
                block->hashPrevBlock = (blocks_accepted >= 1 ? *g_chain->at(blocks_accepted - 1) : params->GenesisBlock()).GetHash();
            }
        }
        BlockValidationState dummy;
        bool processed{chainman.ProcessNewBlockHeaders({*block}, true, dummy)};
        // Rest of chain doesn't work for whatever reason
        if (!processed) {
            break;
        }
        blocks_accepted++;
        index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()));
        Assert(index);
    }
    // Should accept until nBits changes
    Assert(blocks_accepted == 30);
}
} // namespace
