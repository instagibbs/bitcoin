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

// Custom regtest difficulty period
static int DIFF_PERIOD = 6;

// Number of periods we simulate attacking miner
static int NUM_PERIODS = 3;

namespace {

const std::vector<std::shared_ptr<CBlock>>* g_chain;
static int high_water_mark{0};

/* Makes a chain one difficulty period long, where each
   block is +1 the previous. Should trigger maximal retarget. */
void initialize_chain()
{
    /*
    const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};

    std::vector<int64_t> block_times(DIFF_PERIOD);
    std::iota(block_times.begin(), block_times.end(), 1);
    for (size_t i = 0; i < block_times.size(); i++) {
        block_times[i] += params->GenesisBlock().nTime;
    }

    const auto chain{CreateBlockChainDiff(block_times, *params)};
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

    std::vector<int64_t> block_times(DIFF_PERIOD);
    std::iota(block_times.begin(), block_times.end(), 1);
    for (size_t i = 0; i < block_times.size(); i++) {
        block_times[i] += params->GenesisBlock().nTime;
    }

    const auto chain{CreateBlockChainDiff(block_times, *params)};
    g_chain = &chain;

    int64_t start_time = params->GenesisBlock().nTime;
    // We end the simulation "NUM_PERIODS hours" from the beginning, first period takes DIFF_PERIOD seconds
    int64_t end_time = start_time + (60 * 60 * NUM_PERIODS);

    // Start at genesis
    int64_t cur_time = params->GenesisBlock().nTime;

    int block_height{0};

    // First, submit the first period to get new difficulty
    CBlockIndex* index{nullptr};
    for (const auto& block : *g_chain) {
        if (index != nullptr) {
            const auto next_nBits = GetNextWorkRequired(index, &(*block), consensusParams);
            // We stop once we hit retarget
            if (next_nBits != block->nBits) {
                break;
            }
        }
        BlockValidationState dummy;
        bool processed{chainman.ProcessNewBlockHeaders({*block}, true, dummy)};
        Assert(processed);
        block_height++;
        index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()));
        Assert(index);

        const auto diff{GetDifficulty(*index)};
        const auto chainwork{index->nChainWork};
        arith_uint256 block_chainwork;
        block_chainwork.SetCompact(block->nBits);
        block_chainwork = (~block_chainwork / (block_chainwork + 1)) + 1;
    }

    // We don't submit the last one
    Assert(block_height == DIFF_PERIOD - 1);
    int ramp_block_height = block_height;

    // Now that we have difficulty ratcheted up, run simulation of a 100% miner

    // Take per-block chainwork of new difficulty and budget the miner with that value
    const auto next_nBits = GetNextWorkRequired(index, &(*g_chain->back()), consensusParams);
    arith_uint256 per_block_chainwork;
    per_block_chainwork.SetCompact(next_nBits);
    per_block_chainwork = (~per_block_chainwork / (per_block_chainwork + 1)) + 1;

    // Compare with genesis period chainwork
    arith_uint256 genesis_block_chainwork;
    genesis_block_chainwork.SetCompact(g_chain->front()->nBits);
    genesis_block_chainwork = (~genesis_block_chainwork / (genesis_block_chainwork + 1)) + 1;

    // 1800x difficulty adjustment because of overflow on regtest nBits values
    Assert(per_block_chainwork >= genesis_block_chainwork * 1800);

    // 3 periods worth of new difficulty for miner to "spend"
    arith_uint256 target_chainwork{per_block_chainwork * DIFF_PERIOD * NUM_PERIODS};

    // Now, in a loop:
    // 1) Generate new block with fuzz-generated block time within given simulation window
    // 2) Check if remaining miner chainwork is available (if not, break)
    // 3) Submit block header
    // 4) Check that it's accepted, break if not accepted
    Assert(index);
    std::vector<std::shared_ptr<CBlock>> new_blocks;
    while (true) {
        // Make block time jump forward or back arbitrarily between start and end time
        cur_time += fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(-(cur_time - start_time), end_time - cur_time);
        int64_t block_time{cur_time};

        uint256 prev_block_hash = new_blocks.empty() ? g_chain->back()->GetHash() : new_blocks.back()->GetHash();
        const auto& new_block{CreateBlockWithTime(block_time, prev_block_hash, /*prev_block_height=*/block_height, *params)};

        // Modify nBits since function just gives genesis nBits
        const auto next_nBits = GetNextWorkRequired(index, &(*new_block), consensusParams);
        if (next_nBits != new_block->nBits) {
            new_block->nBits = next_nBits;
        }

        arith_uint256 new_block_chainwork;
        new_block_chainwork.SetCompact(new_block->nBits);
        new_block_chainwork = (~new_block_chainwork / (new_block_chainwork + 1)) + 1;

        // Don't "mine" if we were to exceed our budget
        const auto chainwork{index->nChainWork};
        if (chainwork + new_block_chainwork > target_chainwork) {
            break;
        }

        // "Mine" new block
        BlockValidationState dummy;
        bool processed{chainman.ProcessNewBlockHeaders({*new_block}, true, dummy)};
        // Rest of chain doesn't work for whatever reason
        if (!processed) {
            break;
        }

        new_blocks.push_back(new_block);

        // Should be way larger than genesis difficulty
        const auto diff{GetDifficulty(*index)};

        block_height++;
        index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(new_block->GetHash()));
        Assert(index);
    }

    // Shouldn't see more than expected during simulation
    size_t attacker_mined_blocks = block_height - ramp_block_height;
    Assert(attacker_mined_blocks == new_blocks.size());
    Assert(attacker_mined_blocks <= (size_t) DIFF_PERIOD * NUM_PERIODS);

    if (block_height > high_water_mark) {
        high_water_mark = block_height;
        fprintf(stderr, "Blocks accepted: %d\n", block_height);
    }
}
} // namespace
