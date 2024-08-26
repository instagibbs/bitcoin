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

/* FIXME put initial DIFF_PERIOD blocks here */
void initialize_chain()
{
}

// step one second forward
// step to MTP+1
// step forward a DIFF_PERIOD
// step backward a DIFF_PERIOD
// step anytime MTP + 2 to end_time
int64_t ChooseTimestampDelta(FuzzedDataProvider& fuzzed_data_provider, int64_t last_block_time, int64_t mediantimepast, int64_t end_time)
{
    Assert(last_block_time >= mediantimepast);
    Assert(end_time >= last_block_time);

    int64_t TIME_SKIPS[6];
    TIME_SKIPS[0] = 1; // Forward a second
    TIME_SKIPS[1] = -(last_block_time - mediantimepast) + 1; // (back to) MTP + 1
    TIME_SKIPS[2] = DIFF_PERIOD * 60 * 10; // ahead one period
    TIME_SKIPS[3] = -(DIFF_PERIOD * 60 * 10); // back one period
    TIME_SKIPS[4] = DIFF_PERIOD * 60 * 10 / 2; // ahead one half period
    TIME_SKIPS[5] = -(DIFF_PERIOD * 60 * 10 / 2); // back one half period

    // Starts as MTP + 2
    int64_t random_lower_bound{TIME_SKIPS[1] + 1};
    int64_t random_upper_bound{end_time - last_block_time};
    if (random_lower_bound > random_upper_bound) {
        random_lower_bound = random_upper_bound;
    }

    // Pick template or pick a delta time in legal bounds MTP + 2 to end time
    auto time_delta = fuzzed_data_provider.ConsumeBool() ? fuzzed_data_provider.PickValueInArray(TIME_SKIPS) :
        fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(random_lower_bound, random_upper_bound);;

    if (time_delta < TIME_SKIPS[1]) {
        // Delta has to reach MTP + 1
        time_delta = TIME_SKIPS[1];
    }
    if (last_block_time + time_delta > end_time) {
        // clamp to end of simulation
        time_delta = end_time - last_block_time;
    }
    return time_delta;
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

    uint256 prev_block_hash;

    // The value we have to exceed for next block
    int64_t cur_MTP{start_time};

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
        if (!processed) {
            processed;
        }
        Assert(processed);
        block_height++;
        index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block->GetHash()));
        Assert(index);

        prev_block_hash = block->GetHash();

        cur_time = block->nTime;
        cur_MTP = index->GetMedianTimePast();

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

        // Can't make any more blocks(since we're always advancing a second); abort
        if (cur_MTP == end_time) {
            break;
        }

        cur_time += ChooseTimestampDelta(fuzzed_data_provider, cur_time, cur_MTP, end_time);

        int64_t block_time{cur_time};

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
            processed;
        }
        Assert(processed);

        new_blocks.push_back(new_block);
        prev_block_hash = new_block->GetHash();

        block_height++;
        index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(new_block->GetHash()));
        Assert(index);

        cur_MTP = index->GetMedianTimePast();
    }

    // Shouldn't see more than expected during simulation
    size_t attacker_mined_blocks = block_height - ramp_block_height;
    Assert(attacker_mined_blocks == new_blocks.size());
    Assert(attacker_mined_blocks <= (size_t) DIFF_PERIOD * NUM_PERIODS);

    if (block_height > high_water_mark) {
        high_water_mark = block_height;
        fprintf(stderr, "Blocks accepted: %zu vs %d\n", attacker_mined_blocks, DIFF_PERIOD * NUM_PERIODS);
    }
}
} // namespace
