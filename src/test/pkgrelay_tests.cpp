// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>
#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <node/pkgrelay.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <optional>
#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
struct PkgRelaySetup : TestChain100Setup {
    CTxMemPool& pool{*Assert(m_node.mempool)};

    COutPoint Confirmed() { return COutPoint{Txid::FromUint256(m_rng.rand256()), 0}; }

    CTransactionRef Add(const std::vector<COutPoint>& prevouts, CAmount fee, size_t outputs = 1)
    {
        CMutableTransaction mtx;
        for (const auto& prevout : prevouts) mtx.vin.emplace_back(prevout);
        for (size_t i{0}; i < outputs; ++i) mtx.vout.emplace_back(CENT, CScript{} << OP_TRUE);
        const auto tx{MakeTransactionRef(mtx)};
        TryAddToMempool(pool, TestMemPoolEntryHelper{}.Fee(fee).FromTx(tx));
        return tx;
    }

    std::optional<Wtxid> PairedWith(const CTransactionRef& tx, const CFeeRate& filterrate)
    {
        LOCK(pool.cs);
        const auto* entry{pool.GetEntry(tx->GetHash())};
        BOOST_REQUIRE(entry);
        const auto* parent{node::GetPackageRelayParent(pool, *entry, filterrate)};
        if (!parent) return std::nullopt;
        return parent->GetTx().GetWitnessHash();
    }
};

std::set<Wtxid> Wtxids(const std::vector<CTransactionRef>& txs)
{
    std::set<Wtxid> res;
    for (const auto& tx : txs) res.insert(tx->GetWitnessHash());
    return res;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(pkgrelay_tests, PkgRelaySetup)

BOOST_AUTO_TEST_CASE(package_relay_parent)
{
    const CFeeRate filterrate{1000};

    // A transaction is announced with its parent if that is its only unconfirmed parent, and the
    // parent has no unconfirmed parent and no other child.
    const auto parent{Add({Confirmed()}, 1000, /*outputs=*/2)};
    const auto child{Add({{parent->GetHash(), 0}}, 1000)};
    BOOST_CHECK(PairedWith(child, filterrate) == parent->GetWitnessHash());
    BOOST_CHECK(!PairedWith(parent, filterrate));
    const auto sibling{Add({{parent->GetHash(), 1}}, 1000)};
    BOOST_CHECK(!PairedWith(child, filterrate));
    BOOST_CHECK(!PairedWith(sibling, filterrate));

    const auto grandparent{Add({Confirmed()}, 1000)};
    const auto middle{Add({{grandparent->GetHash(), 0}}, 1000)};
    const auto grandchild{Add({{middle->GetHash(), 0}}, 1000)};
    BOOST_CHECK(!PairedWith(grandchild, filterrate));
    BOOST_CHECK(PairedWith(middle, filterrate) == grandparent->GetWitnessHash());

    const auto parent_a{Add({Confirmed()}, 1000)};
    const auto parent_b{Add({Confirmed()}, 1000)};
    BOOST_CHECK(!PairedWith(Add({{parent_a->GetHash(), 0}, {parent_b->GetHash(), 0}}, 1000), filterrate));

    // The chunk must pay the feefilter: both transactions if the child pays a higher feerate than
    // the parent, the child alone otherwise.
    const auto free_parent{Add({Confirmed()}, 0)};
    const auto cheap_child{Add({{free_parent->GetHash(), 0}}, 10)};
    BOOST_CHECK(!PairedWith(cheap_child, filterrate));
    BOOST_CHECK(PairedWith(cheap_child, CFeeRate{0}) == free_parent->GetWitnessHash());
    const auto rich_parent{Add({Confirmed()}, 10000)};
    const auto modest_child{Add({{rich_parent->GetHash(), 0}}, 100)};
    BOOST_CHECK(PairedWith(modest_child, filterrate) == rich_parent->GetWitnessHash());
    BOOST_CHECK(!PairedWith(modest_child, CFeeRate{2000}));
}

BOOST_AUTO_TEST_CASE(select_inventory)
{
    const CFeeRate filterrate{1000};
    const auto parent{Add({Confirmed()}, 1000)};
    const auto child{Add({{parent->GetHash(), 0}}, 1000)};
    const auto standalone{Add({Confirmed()}, 1000)};
    const auto cheap{Add({Confirmed()}, 0)};
    const PkgInv pkg{parent->GetWitnessHash(), child->GetWitnessHash()};
    CRollingBloomFilter known{1000, 0.000001};

    const auto select{[&](bool pkgrelay) {
        LOCK(pool.cs);
        std::vector<Wtxid> wtxids{parent->GetWitnessHash(), child->GetWitnessHash(), standalone->GetWitnessHash(), cheap->GetWitnessHash()};
        const auto txiters{pool.ExtractBestByMiningScoreWithTopology(wtxids, wtxids.size())};
        return node::SelectInventory(pool, txiters, /*fallback=*/{}, filterrate, pkgrelay, known);
    }};

    // To a package relay peer, the child goes with its parent, which is not announced on its own.
    // Transactions that don't pay the feefilter are not announced.
    auto inv{select(/*pkgrelay=*/true)};
    BOOST_REQUIRE_EQUAL(inv.pkgs.size(), 1U);
    BOOST_CHECK(inv.pkgs[0].GetId() == pkg.GetId());
    BOOST_CHECK(Wtxids(inv.txs) == std::set{standalone->GetWitnessHash()});

    // To another peer, every transaction goes on its own.
    inv = select(/*pkgrelay=*/false);
    BOOST_CHECK(inv.pkgs.empty());
    BOOST_CHECK(Wtxids(inv.txs) == (std::set{parent->GetWitnessHash(), child->GetWitnessHash(), standalone->GetWitnessHash()}));

    // The package is not announced if the peer knows the child, or the package because we announced
    // it before; the parent is then announced on its own.
    const uint256 child_key{pkg.child.ToUint256()};
    const auto pkg_key{node::AnnouncedPackageKey(pkg)};
    for (const std::span<const unsigned char> key : {std::span<const unsigned char>{child_key}, std::span<const unsigned char>{pkg_key}}) {
        known.reset();
        known.insert(key);
        inv = select(/*pkgrelay=*/true);
        BOOST_CHECK(inv.pkgs.empty());
        BOOST_CHECK(Wtxids(inv.txs) == (std::set{parent->GetWitnessHash(), standalone->GetWitnessHash()}));
    }
    known.reset();

    // Fallback transactions are announced on their own, if they are in the mempool and pay the
    // feefilter.
    {
        LOCK(pool.cs);
        inv = node::SelectInventory(pool, /*txs=*/{}, {child->GetWitnessHash(), cheap->GetWitnessHash(), Wtxid::FromUint256(m_rng.rand256())},
                                    filterrate, /*pkgrelay=*/true, known);
    }
    BOOST_CHECK(inv.pkgs.empty());
    BOOST_CHECK(Wtxids(inv.txs) == std::set{child->GetWitnessHash()});
}

BOOST_AUTO_TEST_CASE(package_fallback)
{
    const auto parent{Add({Confirmed()}, 1000)};
    const auto child{Add({{parent->GetHash(), 0}}, 1000)};
    const auto standalone{Add({Confirmed()}, 1000)};
    const Wtxid missing{Wtxid::FromUint256(m_rng.rand256())};
    CRollingBloomFilter known{1000, 0.000001};
    node::PackageFallback fallback;
    const auto announce{[&](const PkgInv& pkg) { known.insert(node::AnnouncedPackageKey(pkg)); return pkg; }};

    // Nothing is queued for a package we did not announce, even if the peer announced its id to us
    // as if it were a wtxid.
    const PkgInv unannounced{parent->GetWitnessHash(), child->GetWitnessHash()};
    known.insert(unannounced.GetId().ToUint256());
    fallback.Add(unannounced, pool, known);
    BOOST_CHECK(fallback.empty());

    // The transactions in the mempool and not known to the peer are queued, each once.
    fallback.Add(announce({parent->GetWitnessHash(), missing}), pool, known);
    BOOST_CHECK_EQUAL(fallback.size(), 1U);
    fallback.Add(announce({parent->GetWitnessHash(), child->GetWitnessHash()}), pool, known);
    fallback.Add({parent->GetWitnessHash(), child->GetWitnessHash()}, pool, known);
    BOOST_CHECK_EQUAL(fallback.size(), 2U);
    known.insert(standalone->GetWitnessHash().ToUint256());
    fallback.Add(announce({standalone->GetWitnessHash(), missing}), pool, known);
    BOOST_CHECK_EQUAL(fallback.size(), 2U);
    BOOST_CHECK(fallback.Take() == (std::vector{parent->GetWitnessHash(), child->GetWitnessHash()}));
    BOOST_CHECK(fallback.empty());

    // Up to MAX_PKG_FALLBACK.
    std::vector<Wtxid> wtxids;
    for (size_t i{0}; i <= node::MAX_PKG_FALLBACK; ++i) wtxids.push_back(Add({Confirmed()}, 1000)->GetWitnessHash());
    for (size_t i{0}; i < wtxids.size(); i += 2) fallback.Add(announce({wtxids[i], wtxids[(i + 1) % wtxids.size()]}), pool, known);
    BOOST_CHECK_EQUAL(fallback.size(), node::MAX_PKG_FALLBACK);
}

BOOST_AUTO_TEST_CASE(bip_test_vectors)
{
    // The BIP's test vectors: P spends output 0 of a transaction with txid 11..11, C spends output 0
    // of P, and both pay to a P2WSH output with witness script OP_TRUE.
    const CScript witness_script{CScript{} << OP_TRUE};
    uint256 script_hash;
    CSHA256().Write(witness_script.data(), witness_script.size()).Finalize(script_hash.begin());
    const CScript p2wsh{CScript{} << OP_0 << ToByteVector(script_hash)};
    const auto spend{[&](const COutPoint& prevout, CAmount value) {
        CMutableTransaction mtx;
        mtx.version = 2;
        mtx.vin.emplace_back(prevout, CScript{}, 0xfffffffd);
        mtx.vin[0].scriptWitness.stack.emplace_back(witness_script.begin(), witness_script.end());
        mtx.vout.emplace_back(value, p2wsh);
        return MakeTransactionRef(mtx);
    }};
    const auto parent{spend(COutPoint{*Txid::FromHex(std::string(64, '1')), 0}, 10000)};
    const auto child{spend(COutPoint{parent->GetHash(), 0}, 9000)};
    BOOST_CHECK_EQUAL(parent->GetHash().ToString(), "8b00fe39967f29139f8d03498da3dc3c548a96028449a31b4ebb0c3629b50761");
    BOOST_CHECK_EQUAL(parent->GetWitnessHash().ToString(), "b91a8506a312c420747e7ad71856008a99d243c46e2f67f69ca17d871bba888f");
    BOOST_CHECK_EQUAL(child->GetHash().ToString(), "b441cde3cd0cb81a349d9097d551b9f53d39712a9dbae4b62cffd2d390d37181");
    BOOST_CHECK_EQUAL(child->GetWitnessHash().ToString(), "8df0d83ee566756891a7dbdcd760a42307587045b9fecd4a6137fd6f50e5b7e5");

    DataStream pkginv;
    pkginv << std::vector<PkgInv>{{parent->GetWitnessHash(), child->GetWitnessHash()}};
    BOOST_CHECK_EQUAL(HexStr(pkginv), "018f88ba1b877da19cf6672f6ec443d2998a005618d77a7e7420c412a306851ab9e5b7e5506ffd37614acdfeb94570580723a460d7dcdba791687566e53ed8f08d");

    DataStream pkg;
    pkg << TX_WITH_WITNESS(*parent) << TX_WITH_WITNESS(*child);
    BOOST_CHECK_EQUAL(HexStr(pkg), "0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000fdffffff0110270000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001015100000000020000000001016107b529360cbb4e1ba3498402968a543cdca38d49038d9f13297f9639fe008b0000000000fdffffff0128230000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001015100000000");
}

BOOST_AUTO_TEST_SUITE_END()
