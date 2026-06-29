// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <node/park_buffer.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using node::ParkBuffer;

BOOST_FIXTURE_TEST_SUITE(park_buffer_tests, BasicTestingSetup)

// Build a minimal transaction spending the given outpoints. out_value varies the txid
// so distinct transactions can be built spending overlapping inputs.
static CTransactionRef MakeTx(const std::vector<COutPoint>& inputs, CAmount out_value = CENT)
{
    CMutableTransaction tx;
    for (const auto& in : inputs) tx.vin.emplace_back(in);
    tx.vout.resize(1);
    tx.vout[0].nValue = out_value;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(tx);
}

static ParkBuffer::ParkedPackage Pkg(const CTransactionRef& tx, CAmount value)
{
    return {.txns = {tx}, .value = value, .weight = GetTransactionWeight(*tx)};
}

static COutPoint RandOutpoint(FastRandomContext& rng)
{
    return COutPoint{Txid::FromUint256(rng.rand256()), 0};
}

BOOST_AUTO_TEST_CASE(park_and_find_by_footprint)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    ParkBuffer buffer{/*max_weight=*/4'000'000};

    const COutPoint o = RandOutpoint(rng);
    const auto victim = MakeTx({o});
    BOOST_CHECK(buffer.Park(Pkg(victim, 10'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 1u);

    const auto* found = buffer.FindByInput(o);
    BOOST_REQUIRE(found != nullptr);
    BOOST_REQUIRE_EQUAL(found->txns.size(), 1u);
    BOOST_CHECK(found->txns.at(0) == victim);

    BOOST_CHECK(buffer.FindByInput(RandOutpoint(rng)) == nullptr);
}

BOOST_AUTO_TEST_CASE(disjoint_packages_coexist)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    ParkBuffer buffer{/*max_weight=*/4'000'000};

    const COutPoint o1 = RandOutpoint(rng);
    const COutPoint o2 = RandOutpoint(rng);
    BOOST_CHECK(buffer.Park(Pkg(MakeTx({o1}), 10'000)));
    BOOST_CHECK(buffer.Park(Pkg(MakeTx({o2}), 20'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 2u);
    BOOST_CHECK(buffer.FindByInput(o1) != nullptr);
    BOOST_CHECK(buffer.FindByInput(o2) != nullptr);
}

BOOST_AUTO_TEST_CASE(rejects_footprint_conflicting_package)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    ParkBuffer buffer{/*max_weight=*/4'000'000};

    const COutPoint shared = RandOutpoint(rng);
    const COutPoint o1 = RandOutpoint(rng);
    const COutPoint o2 = RandOutpoint(rng);

    BOOST_CHECK(buffer.Park(Pkg(MakeTx({o1, shared}), 10'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 1u);

    // Conflicts on `shared`; rejected even though higher value (no in-buffer RBF yet).
    BOOST_CHECK(!buffer.Park(Pkg(MakeTx({o2, shared}), 50'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 1u);
    BOOST_CHECK(buffer.FindByInput(o2) == nullptr);
    BOOST_CHECK(buffer.FindByInput(shared) != nullptr);
    BOOST_CHECK(buffer.FindByInput(o1) != nullptr);
}

BOOST_AUTO_TEST_CASE(package_footprint_includes_all_spent_outpoints)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    ParkBuffer buffer{/*max_weight=*/4'000'000};

    // 2-tx package: parent spends an external outpoint, child spends the parent's output.
    const COutPoint o_ext = RandOutpoint(rng);
    const auto parent = MakeTx({o_ext});
    const COutPoint parent_out{parent->GetHash(), 0};
    const auto child = MakeTx({parent_out});

    ParkBuffer::ParkedPackage pkg{.txns = {parent, child}, .value = 10'000,
                                  .weight = GetTransactionWeight(*parent) + GetTransactionWeight(*child)};
    BOOST_CHECK(buffer.Park(std::move(pkg)));

    // Both the external input and the internal parent->child link are indexed: the contended
    // outpoint an attacker cycles can be the internal link (a CPFP anchor), so it must be
    // findable to drive reinstatement.
    BOOST_CHECK(buffer.FindByInput(o_ext) != nullptr);
    BOOST_CHECK(buffer.FindByInput(parent_out) != nullptr);
}

BOOST_AUTO_TEST_CASE(evicts_lowest_value_over_cap)
{
    FastRandomContext rng{/*fDeterministic=*/true};

    const COutPoint o1 = RandOutpoint(rng);
    const COutPoint o2 = RandOutpoint(rng);
    const COutPoint o3 = RandOutpoint(rng);
    const auto t1 = MakeTx({o1});
    const auto t2 = MakeTx({o2});
    const auto t3 = MakeTx({o3});
    const int64_t w = GetTransactionWeight(*t1);  // identical structure -> identical weight

    ParkBuffer buffer{/*max_weight=*/2 * w};  // room for exactly two packages

    BOOST_CHECK(buffer.Park(Pkg(t1, 10'000)));
    BOOST_CHECK(buffer.Park(Pkg(t2, 30'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 2u);
    BOOST_CHECK_EQUAL(buffer.TotalWeight(), 2 * w);

    // Parking a third (mid value) over the cap evicts the lowest-value package (o1 @ 10k).
    BOOST_CHECK(buffer.Park(Pkg(t3, 20'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 2u);
    BOOST_CHECK_EQUAL(buffer.TotalWeight(), 2 * w);
    BOOST_CHECK(buffer.FindByInput(o1) == nullptr);
    BOOST_CHECK(buffer.FindByInput(o2) != nullptr);
    BOOST_CHECK(buffer.FindByInput(o3) != nullptr);

    // A new lowest-value package over the cap is itself dropped (cannot displace higher
    // value). This is the DoS bound: occupying the buffer costs more than what is parked.
    const COutPoint o4 = RandOutpoint(rng);
    BOOST_CHECK(buffer.Park(Pkg(MakeTx({o4}), 1'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 2u);
    BOOST_CHECK(buffer.FindByInput(o4) == nullptr);
    BOOST_CHECK(buffer.FindByInput(o2) != nullptr);
    BOOST_CHECK(buffer.FindByInput(o3) != nullptr);
}

BOOST_AUTO_TEST_CASE(remove_clears_whole_footprint)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    ParkBuffer buffer{/*max_weight=*/4'000'000};

    const COutPoint o1 = RandOutpoint(rng);
    const COutPoint o2 = RandOutpoint(rng);
    const auto tx = MakeTx({o1, o2});
    const int64_t w = GetTransactionWeight(*tx);
    BOOST_CHECK(buffer.Park(Pkg(tx, 10'000)));
    BOOST_CHECK_EQUAL(buffer.TotalWeight(), w);

    // Remove by any footprint outpoint drops the whole package and clears its index.
    BOOST_CHECK(buffer.Remove(o1));
    BOOST_CHECK_EQUAL(buffer.Size(), 0u);
    BOOST_CHECK_EQUAL(buffer.TotalWeight(), 0);
    BOOST_CHECK(buffer.FindByInput(o1) == nullptr);
    BOOST_CHECK(buffer.FindByInput(o2) == nullptr);

    // Removing an unknown outpoint is a no-op.
    BOOST_CHECK(!buffer.Remove(RandOutpoint(rng)));

    // The freed outpoints can be re-parked (index fully cleared).
    BOOST_CHECK(buffer.Park(Pkg(MakeTx({o1}), 5'000)));
    BOOST_CHECK_EQUAL(buffer.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(randomized_invariants)
{
    FastRandomContext rng{/*fDeterministic=*/true};

    // Small fixed pool so packages frequently share inputs, exercising disjointness.
    std::vector<COutPoint> pool;
    for (int i = 0; i < 6; ++i) pool.push_back(RandOutpoint(rng));

    ParkBuffer buffer{/*max_weight=*/50'000};

    for (int iter = 0; iter < 2000; ++iter) {
        switch (rng.randrange(3)) {
        case 0: {
            // Park a package over a random distinct subset of the pool.
            std::vector<COutPoint> inputs;
            for (const auto& o : pool) {
                if (rng.randbool()) inputs.push_back(o);
            }
            if (inputs.empty()) inputs.push_back(pool[rng.randrange(pool.size())]);

            const auto tx = MakeTx(inputs, static_cast<CAmount>(rng.randrange(1000)) + 1);
            const bool conflict = std::any_of(inputs.begin(), inputs.end(),
                [&](const COutPoint& o) { return buffer.FindByInput(o) != nullptr; });
            const bool admitted = buffer.Park(Pkg(tx, static_cast<CAmount>(rng.randrange(100'000))));
            // First-come disjointness: a footprint-conflicting package is always rejected.
            if (conflict) BOOST_CHECK(!admitted);
            break;
        }
        case 1:
            buffer.FindByInput(pool[rng.randrange(pool.size())]);
            break;
        default:
            buffer.Remove(pool[rng.randrange(pool.size())]);
            break;
        }
        buffer.SanityCheck();
    }
}

BOOST_AUTO_TEST_SUITE_END()
