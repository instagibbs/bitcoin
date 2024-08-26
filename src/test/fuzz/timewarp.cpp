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
static int high_water_mark{0};

void initialize_chain()
{
/*    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    // Generate 7 retarget periods worth of blockheaders even though
    // we only should see 4 periods worth of blocks accepted
    std::vector<int64_t> block_times(6 * 7);
    std::iota(block_times.begin(), block_times.end(), 1);
    for (size_t i = 0; i < block_times.size(); i++) {
        block_times[i] += params->GenesisBlock().nTime;
    }
    static const auto chain{CreateBlockChainDiff(block_times, *params)};
    g_chain = &chain;*/
}

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex& blockindex)
{
    int nShift = (blockindex.nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex.nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

FUZZ_TARGET(timewarp, .init = initialize_chain)
{

    // FIXME how to model a timewarp?
    // Stop mining after chainwork hits target?
    // Make sure max timestamp is bounded
    // Account for miners' "hashpower" increasing the nBits
    // initialize_chain gets into steady state too?
    // Use fuzzer to sample times above MTP
    // Make one block at a time

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
    //const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};

    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};

    int64_t start_time = params->GenesisBlock().nTime;
    // We end the simulation "4 hours" from the beginning
    int64_t end_time = start_time + (60 * 60 * 4);
    int64_t duration = end_time - start_time;

    // Start at genesis
    int64_t cur_time = params->GenesisBlock().nTime;

    // Generate 7 retarget periods worth of blockheaders even though
    // we only should see 4 periods worth of blocks accepted
    std::vector<int64_t> block_times(6 * 7);
    for (size_t i = 0; i < block_times.size(); i++) {
        // Jump back and forth
        cur_time += fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(-(cur_time - start_time), end_time - cur_time);
        block_times[i] = cur_time;
    }
    if (block_times[0] > start_time) {
        g_chain;
    }

    const auto chain{CreateBlockChainDiff(block_times, *params)};
    g_chain = &chain;

    int blocks_accepted{0};
    // FIXME set this to some reasonable target that "consumes" pregenerated chain, or generate
    // blocks JIT
    arith_uint256 genesis_work;
    bool neg, over;
    genesis_work.SetCompact(g_chain->front()->nBits, &neg, &over);
    // Ripped from GetBlockProof to convert this into something to compare nChainWork with
    // I don't understand the conversion rates however!
    genesis_work = (~genesis_work / ( genesis_work + 1)) + 1;

    // 6*6 post-retarget(1800x???) work
    arith_uint256 target_chainwork{(g_chain->size() - 6) * genesis_work * 1800};
    CBlockIndex* index{nullptr};
    for (const auto& block : *g_chain) {
        if (index != nullptr) {
            const auto next_nBits = GetNextWorkRequired(index, &(*block), consensusParams);
            // FIXME Should just generate blocks in real time
            block->nBits = next_nBits;
            block->hashPrevBlock = (blocks_accepted >= 1 ? *g_chain->at(blocks_accepted - 1) : params->GenesisBlock()).GetHash();
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

        const auto diff{GetDifficulty(*index)};
        const auto chainwork{index->nChainWork};
        arith_uint256 block_chainwork;
        block_chainwork.SetCompact(block->nBits);
        block_chainwork = (~block_chainwork / (block_chainwork + 1)) + 1;
        // FIXME abort before submitting this block
        if (chainwork >= target_chainwork) {
            break;
        }
    }
    // Shouldn't see more than "4 hours" of blocks
    // How to pricely define this?
    Assert(blocks_accepted <= 50);
    if (blocks_accepted > high_water_mark) {
        high_water_mark = blocks_accepted;
        fprintf(stderr, "Blocks accepted: %d\n", blocks_accepted);
    }
}
// FIXME:
/*
    Generate first sequence of blocks as fast as possible
        and don't count those towards the attack window.
        Also see if 100x'ing the 900/3600 changes the result
    Once retarget happens...
    Determine "hashrate" of miner to exactly "use up" the N weeks to end_time
        Instead of making it up hap-hazardly
    Generate one block at a time, can pick delta with MTP respected
*/
} // namespace
