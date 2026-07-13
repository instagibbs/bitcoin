// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <bench/bench.h>
#include <compat/compat.h>
#include <netaddress.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/data/ip_asn.dat.h>
#include <protocol.h>
#include <random.h>
#include <streams.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <cstring>
#include <optional>
#include <span>
#include <vector>

/* A "source" is a source address from which we have received a bunch of other addresses. */

static constexpr size_t NUM_SOURCES = 64;
static constexpr size_t NUM_ADDRESSES_PER_SOURCE = 256;

static auto EMPTY_NETGROUPMAN{NetGroupManager::NoAsmap()};
static constexpr uint32_t ADDRMAN_CONSISTENCY_CHECK_RATIO{0};

static std::vector<CAddress> g_sources;
static std::vector<std::vector<CAddress>> g_addresses;

static void CreateAddresses()
{
    if (g_sources.size() > 0) { // already created
        return;
    }

    FastRandomContext rng(uint256(std::vector<unsigned char>(32, 123)));

    auto randAddr = [&rng]() {
        in6_addr addr;
        memcpy(&addr, rng.randbytes(sizeof(addr)).data(), sizeof(addr));

        uint16_t port;
        memcpy(&port, rng.randbytes(sizeof(port)).data(), sizeof(port));
        if (port == 0) {
            port = 1;
        }

        CAddress ret(CService(addr, port), NODE_NETWORK);

        ret.nTime = Now<NodeSeconds>();

        return ret;
    };

    for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
        g_sources.emplace_back(randAddr());
        g_addresses.emplace_back();
        for (size_t addr_i = 0; addr_i < NUM_ADDRESSES_PER_SOURCE; ++addr_i) {
            g_addresses[source_i].emplace_back(randAddr());
        }
    }
}

static void AddAddressesToAddrMan(AddrMan& addrman)
{
    for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
        addrman.Add(g_addresses[source_i], g_sources[source_i]);
    }
}

static void FillAddrMan(AddrMan& addrman)
{
    CreateAddresses();

    AddAddressesToAddrMan(addrman);
}

// Populate the tried table too (SelectWithNetgroup and the tried netgroup index
// only concern tried entries). The random IPv6 addresses give many distinct
// netgroups to draw from.
static void FillAddrManTried(AddrMan& addrman)
{
    FillAddrMan(addrman);
    for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
        for (size_t addr_i = 0; addr_i < NUM_ADDRESSES_PER_SOURCE; ++addr_i) {
            addrman.Good(g_addresses[source_i][addr_i]);
        }
    }
    addrman.ResolveCollisions();
}

/* Benchmarks */

static const NetGroupManager& AsmapNetGroupMan()
{
    static const auto ngm{NetGroupManager::WithEmbeddedAsmap(node::data::ip_asn)};
    return ngm;
}

static void AddrManAdd(benchmark::Bench& bench)
{
    CreateAddresses();

    bench.run([&] {
        AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};
        AddAddressesToAddrMan(addrman);
    });
}

static void AddrManAddAsmap(benchmark::Bench& bench)
{
    CreateAddresses();

    bench.run([&] {
        AddrMan addrman{AsmapNetGroupMan(), /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};
        AddAddressesToAddrMan(addrman);
    });
}

static void AddrManUnserializeImpl(benchmark::Bench& bench, const NetGroupManager& ngm)
{
    AddrMan addrman_source{ngm, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};
    // Populate the tried table so this measures rebuilding the tried netgroup
    // index on load, which is the only index work Unserialize does.
    FillAddrManTried(addrman_source);
    assert(addrman_source.Size(/*net=*/std::nullopt, /*in_new=*/false) > 0);
    DataStream stream{};
    stream << addrman_source;
    const std::string data{stream.str()};

    bench.run([&] {
        DataStream s{MakeUCharSpan(data)};
        AddrMan addrman{ngm, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};
        s >> addrman;
        assert(addrman.Size() > 0);
    });
}

static void AddrManUnserialize(benchmark::Bench& bench)
{
    AddrManUnserializeImpl(bench, EMPTY_NETGROUPMAN);
}

static void AddrManUnserializeAsmap(benchmark::Bench& bench)
{
    AddrManUnserializeImpl(bench, AsmapNetGroupMan());
}

static void AddrManSelect(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};

    FillAddrMan(addrman);

    bench.run([&] {
        const auto& address = addrman.Select();
        assert(address.first.GetPort() > 0);
    });
}

// The worst case performance of the Select() function is when there is only
// one address on the table, because it linearly searches every position of
// several buckets before identifying the correct bucket
static void AddrManSelectFromAlmostEmpty(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};

    // Add one address to the new table
    CService addr = Lookup("250.3.1.1", 8333, false).value();
    addrman.Add({CAddress(addr, NODE_NONE)}, addr);

    bench.run([&] {
        (void)addrman.Select();
    });
}

static void AddrManSelectByNetwork(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};

    // add single I2P address to new table
    CService i2p_service;
    i2p_service.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p");
    CAddress i2p_address(i2p_service, NODE_NONE);
    i2p_address.nTime = Now<NodeSeconds>();
    const CNetAddr source{LookupHost("252.2.2.2", false).value()};
    addrman.Add({i2p_address}, source);

    FillAddrMan(addrman);

    bench.run([&] {
        (void)addrman.Select(/*new_only=*/false, {NET_I2P});
    });
}

static void AddrManSelectWithNetgroup(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/true, ADDRMAN_CONSISTENCY_CHECK_RATIO};
    FillAddrManTried(addrman);

    bench.run([&] {
        const auto selection = addrman.SelectWithNetgroup();
        assert(selection.address.GetPort() > 0);
    });
}

// Master-equivalent baseline on the same tried-heavy fixture, to isolate the
// incremental cost of the hybrid replacement from ordinary Select().
static void AddrManSelectTriedBaseline(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/true, ADDRMAN_CONSISTENCY_CHECK_RATIO};
    FillAddrManTried(addrman);

    bench.run([&] {
        const auto selection = addrman.Select();
        assert(selection.first.GetPort() > 0);
    });
}

// Populate the worst case for the network filter: the tried table is full of
// IPv6 entries but only a handful of IPv4 entries match the requested family.
static void FillAddrManWrongFamilySkew(AddrMan& addrman)
{
    // Add a handful of IPv4 tried entries first, while tried slots are free, so
    // a (rare) match exists; if added after the table is full they would collide
    // and never reach tried, making the search early-out instead of exercising
    // the bounded loop.
    for (int i = 1; i <= 4; ++i) {
        const CService addr{in_addr{.s_addr = htonl((250u << 24) | (i << 16) | 1)}, 8333};
        addrman.Add({CAddress(addr, NODE_NONE)}, addr);
        addrman.Good(addr);
    }
    FillAddrManTried(addrman); // many IPv6 tried netgroups dominate the table
    assert(addrman.Size(NET_IPV4, /*in_new=*/false) > 0);
}

// Master-equivalent baseline for the same sparse-family fixture. The complete
// legacy selection is also the first stage of SelectWithNetgroup().
static void AddrManSelectWrongFamilySkew(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/true, ADDRMAN_CONSISTENCY_CHECK_RATIO};
    FillAddrManWrongFamilySkew(addrman);

    bench.run([&] {
        (void)addrman.Select(/*new_only=*/false, {NET_IPV4});
    });
}

// Hybrid cost for the same fixture. The by-netgroup replacement is bounded;
// comparing this with AddrManSelectWrongFamilySkew isolates its incremental cost
// from the legacy filtered selection that both paths must perform.
static void AddrManSelectWithNetgroupWrongFamily(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/true, ADDRMAN_CONSISTENCY_CHECK_RATIO};
    FillAddrManWrongFamilySkew(addrman);

    bench.run([&] {
        (void)addrman.SelectWithNetgroup({NET_IPV4});
    });
}

static void AddrManGetAddr(benchmark::Bench& bench)
{
    AddrMan addrman{EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO};

    FillAddrMan(addrman);

    bench.run([&] {
        const auto& addresses = addrman.GetAddr(/*max_addresses=*/2500, /*max_pct=*/23, /*network=*/std::nullopt);
        assert(addresses.size() > 0);
    });
}

static void AddrManAddThenGood(benchmark::Bench& bench)
{
    auto markSomeAsGood = [](AddrMan& addrman) {
        for (size_t source_i = 0; source_i < NUM_SOURCES; ++source_i) {
            for (size_t addr_i = 0; addr_i < NUM_ADDRESSES_PER_SOURCE; ++addr_i) {
                addrman.Good(g_addresses[source_i][addr_i]);
            }
        }
    };

    CreateAddresses();

    std::optional<AddrMan> addrman;
    bench.setup([&] {
            addrman.emplace(EMPTY_NETGROUPMAN, /*deterministic=*/false, ADDRMAN_CONSISTENCY_CHECK_RATIO);
            AddAddressesToAddrMan(*addrman);
        })
        .run([&] { markSomeAsGood(*addrman); });
}

BENCHMARK(AddrManAdd);
BENCHMARK(AddrManAddAsmap);
BENCHMARK(AddrManUnserialize);
BENCHMARK(AddrManUnserializeAsmap);
BENCHMARK(AddrManSelect);
BENCHMARK(AddrManSelectFromAlmostEmpty);
BENCHMARK(AddrManSelectByNetwork);
BENCHMARK(AddrManSelectTriedBaseline);
BENCHMARK(AddrManSelectWithNetgroup);
BENCHMARK(AddrManSelectWrongFamilySkew);
BENCHMARK(AddrManSelectWithNetgroupWrongFamily);
BENCHMARK(AddrManGetAddr);
BENCHMARK(AddrManAddThenGood);
