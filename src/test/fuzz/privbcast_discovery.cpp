// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/compat.h>
#include <netaddress.h>
#include <netbase.h>
#include <privbcast/assign.h>
#include <privbcast/discovery.h>
#include <privbcast/params.h>
#include <privbcast/plan.h>
#include <privbcast/stream.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <tinyformat.h>
#include <util/sock.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace privbcast;
using namespace std::chrono_literals;
using std::chrono::milliseconds;

namespace {

/** The I/O clock at job start. It moves with the plan clock, so no stage of an exchange runs out
 *  before the window does. */
constexpr SteadyMs STEADY{1h};

/** An IPv4 address from its value in host byte order. */
CNetAddr IPv4(uint32_t ip)
{
    in_addr addr;
    addr.s_addr = htonl(ip);
    return CNetAddr{addr};
}

/** What the proxy does with one query's stream. */
struct Script {
    enum class Connect {
        /** The connect completes at once. */
        Now,
        /** CreateSock fails, or the connect fails at once: the query is skipped. */
        NoSocket,
        Refused,
        /** The connect is in progress until the stream's turn, and then succeeds or fails. */
        Later,
        LaterFails,
    };
    enum class Reply { Address, Name, Error, Close, Silent };

    Connect connect{Connect::Now};
    /** What the proxy does at the stream's turn: answer the request with an address, a name or an
     *  error, close the stream, or stay silent. */
    Reply reply{Reply::Silent};
    /** The bound address of an Address reply: an IPv4 address, or else an IPv6 one. */
    std::vector<uint8_t> address;

    bool Opens() const { return connect != Connect::NoSocket && connect != Connect::Refused; }
    /** The query ends at its turn: with an answer, or failed. */
    bool Ends() const { return Opens() && (connect == Connect::LaterFails || reply != Reply::Silent); }
    /** The query is answered at its turn, with this address or a name. */
    bool Answers() const { return Opens() && connect != Connect::LaterFails && (reply == Reply::Address || reply == Reply::Name); }
    /** The address of an Address reply, as the client reads it. */
    CNetAddr Answer() const
    {
        if (address.size() == 4) {
            in_addr ipv4;
            std::memcpy(&ipv4, address.data(), sizeof(ipv4));
            return CNetAddr{ipv4};
        }
        in6_addr ipv6;
        std::memcpy(&ipv6, address.data(), sizeof(ipv6));
        return CNetAddr{ipv6};
    }
};

/** The proxy behind the sockets discovery creates through CreateSock, each stream as its script
 *  says. */
class FakeProxy
{
public:
    explicit FakeProxy(const std::vector<Script>& scripts) : m_scripts{scripts} {}

    std::unique_ptr<Sock> Create()
    {
        // Discovery creates one socket per query, the queries of each seed in turn.
        assert(m_streams.size() < m_scripts.size());
        Stream& stream{m_streams.emplace_back()};
        stream.script = &m_scripts[m_streams.size() - 1];
        switch (stream.script->connect) {
        case Script::Connect::Now: break;
        case Script::Connect::NoSocket: return nullptr;
        case Script::Connect::Refused: stream.connection->connect_error = ECONNREFUSED; break;
        case Script::Connect::Later:
        case Script::Connect::LaterFails: stream.connection->connect_error = WSAEINPROGRESS; break;
        } // no default case, so the compiler can warn about missing cases
        return std::make_unique<ConnectingSock>(stream.pipes, stream.connection);
    }

    /** Read what each stream's client wrote, and answer the greeting, the authentication and, once
     *  the stream's turn has come, the request. */
    void Serve()
    {
        for (Stream& stream : m_streams) {
            const std::vector<uint8_t> answer{stream.proxy.Received(ReadAll(stream.pipes->send))};
            if (!answer.empty()) stream.pipes->recv.PushBytes(answer.data(), answer.size());
            if (!stream.turn || stream.replied || !stream.proxy.GetRequest()) continue;
            stream.replied = true;
            std::vector<uint8_t> reply;
            switch (stream.script->reply) {
            case Script::Reply::Address:
                reply = {0x05, 0x00, 0x00, static_cast<uint8_t>(stream.script->address.size() == 4 ? 0x01 : 0x04)};
                reply.insert(reply.end(), stream.script->address.begin(), stream.script->address.end());
                reply.insert(reply.end(), {0x00, 0x00});
                break;
            case Script::Reply::Name: reply = Socks5Responder::ReplyName("seed.example"); break;
            case Script::Reply::Error: reply = Socks5Responder::ReplyError(0x04); break;
            case Script::Reply::Close:
            case Script::Reply::Silent: break;
            } // no default case, so the compiler can warn about missing cases
            stream.pipes->recv.PushBytes(reply.data(), reply.size());
        }
    }

    /** Stream i's turn: its connect completes, if it was in progress, and the proxy answers its
     *  request, or closes the stream, or stays silent. */
    void Turn(size_t i)
    {
        if (i >= m_streams.size()) return;
        Stream& stream{m_streams[i]};
        stream.turn = true;
        stream.connection->in_progress = false;
        if (stream.script->connect == Script::Connect::LaterFails) stream.connection->so_error = ECONNREFUSED;
        if (stream.script->reply == Script::Reply::Close) stream.pipes->recv.Eof();
    }

private:
    struct Stream {
        const Script* script{nullptr};
        std::shared_ptr<DynSock::Pipes> pipes{std::make_shared<DynSock::Pipes>()};
        std::shared_ptr<ConnectingSock::Connection> connection{std::make_shared<ConnectingSock::Connection>()};
        Socks5Responder proxy;
        bool turn{false};
        bool replied{false};
    };

    const std::vector<Script>& m_scripts;
    /** Every socket created, in order. */
    std::deque<Stream> m_streams;
};

/** What the job's loop does for discovery at plan clock time now: the deadlines, a wait that does
 *  not block, and the events. */
void Round(Discovery& discovery, FakeProxy& proxy, milliseconds now)
{
    const SteadyMs steady_now{STEADY + now};
    discovery.Tick(now, steady_now);
    proxy.Serve();
    const std::vector<ProxyStream*> active{discovery.ActiveStreams()};
    Sock::EventsPerSock events;
    for (ProxyStream* stream : active) events.emplace(stream->GetSock(), Sock::Events{stream->WantedEvents()});
    if (!events.empty()) assert(events.begin()->first->WaitMany(0ms, events));
    for (ProxyStream* stream : active) {
        const auto it{events.find(stream->GetSock())};
        discovery.OnStreamEvents(*stream, it == events.end() ? Sock::Event{0} : it->second.occurred, now, steady_now);
    }
}

/** A discovery, started at `start`, whose streams take their turns in this order and at these
 *  times, run until its window has passed. */
DiscoveryResult Discover(const Plan& plan, uint16_t port, const std::vector<Script>& scripts, milliseconds start,
                         const std::vector<std::pair<milliseconds, size_t>>& turns)
{
    FakeProxy proxy{scripts};
    const auto create_sock{CreateSock};
    CreateSock = [&](int, int, int) { return proxy.Create(); };
    // The credentials, which change nothing here.
    FastRandomContext rng{/*fDeterministic=*/true};
    Discovery discovery{plan, Proxy{CService{IPv4(INADDR_LOOPBACK), 9050}, /*tor_stream_isolation=*/true}, port, rng};
    discovery.Start(start, STEADY + start);
    // Each stream that connected at once gets as far as its request.
    for (int round{0}; round < 4; ++round) Round(discovery, proxy, start);
    for (const auto& [at, stream] : turns) {
        proxy.Turn(stream);
        for (int round{0}; round < 5; ++round) Round(discovery, proxy, at);
    }
    // The first step after the window's end has ended discovery (C3).
    Round(discovery, proxy, plan.timing.Scale(DISCOVERY_WINDOW) + 1ms);
    assert(discovery.Done() && discovery.ActiveStreams().empty());
    CreateSock = create_sock;
    return discovery.Result();
}

/** What two discoveries found is the same, whenever each ended. */
bool SameAnswers(const DiscoveryResult& a, const DiscoveryResult& b)
{
    return std::ranges::equal(a.seeds, b.seeds, [](const SeedAnswers& x, const SeedAnswers& y) {
        return x.name == y.name && x.queries == y.queries && x.skipped == y.skipped && x.answers == y.answers &&
               x.rejected == y.rejected && x.usable == y.usable;
    });
}

bool Contains(const std::vector<CService>& endpoints, const CService& endpoint)
{
    return std::ranges::find(endpoints, endpoint) != endpoints.end();
}

/** Assign()'s credit and draw rules (R4, R5b) and the assignment rules (R4, R5a-c) on its output. */
void CheckAssignment(const Plan& plan, const DiscoveryResult& result, const Assignment& assignment)
{
    // Each seed, in the plan's order, is credited with the distinct endpoints it returned that no
    // earlier seed did, and keeps up to ANSWERS_KEPT_PER_SEED of them, none kept by two seeds.
    assert(assignment.seeds.size() == result.seeds.size());
    std::set<CService> returned_before, kept_endpoints;
    std::map<std::string, int> kept_by_seed;
    int answers{0}, accepted{0}, kept{0};
    for (size_t i{0}; i < result.seeds.size(); ++i) {
        const SeedAnswers& seed{result.seeds[i]};
        const SeedSummary& summary{assignment.seeds[i]};
        assert(summary.name == seed.name && summary.queries == seed.queries && summary.skipped == seed.skipped && summary.answers == seed.answers);
        std::set<CService> credited;
        for (const CService& endpoint : seed.usable) {
            if (!returned_before.contains(endpoint)) credited.insert(endpoint);
        }
        assert(summary.accepted == static_cast<int>(credited.size()));
        assert(summary.kept == std::min(summary.accepted, ANSWERS_KEPT_PER_SEED));
        assert(summary.candidates.size() == static_cast<size_t>(summary.kept));
        for (const CService& candidate : summary.candidates) {
            assert(credited.contains(candidate));
            assert(kept_endpoints.insert(candidate).second);
        }
        returned_before.insert(seed.usable.begin(), seed.usable.end());
        answers += seed.answers;
        accepted += summary.accepted;
        kept += summary.kept;
        kept_by_seed[seed.name] = summary.kept;
    }
    // Every answer was accepted, a duplicate or rejected.
    assert(accepted + assignment.duplicates + assignment.rejected == answers);
    assert(assignment.exit_path_candidates == kept);
    assert(assignment.onion_candidates == static_cast<int>(plan.onions.size()));

    // R4: no endpoint in two opportunities. Exit-path slots never take an onion (R5c).
    std::set<CService> assigned;
    size_t filled{0};
    for (size_t slot{0}; slot < SLOTS; ++slot) {
        for (const std::optional<Candidate>& candidate : assignment.opportunities[slot]) {
            if (!candidate) continue;
            ++filled;
            assert(assigned.insert(candidate->endpoint).second);
            if (candidate->source == Source::Bundled) {
                assert(plan.slots[slot].cls == SlotClass::Onion && candidate->provenance == "bundled");
                assert(Contains(plan.onions, candidate->endpoint));
            } else {
                const auto seed{std::ranges::find(assignment.seeds, candidate->provenance, &SeedSummary::name)};
                assert(seed != assignment.seeds.end() && Contains(seed->candidates, candidate->endpoint));
            }
        }
    }
    // No candidate is left while an opportunity it may fill is: the onions fit the onion slots,
    // and the DNS seeds' candidates fill the rest.
    static_assert(ONIONS_KEPT <= OPPORTUNITIES_PER_SLOT * std::ranges::count(SLOT_LAYOUT, SlotClass::Onion, &SlotLayout::cls));
    assert(filled == std::min(plan.onions.size() + static_cast<size_t>(kept), SLOTS * OPPORTUNITIES_PER_SLOT));

    // R5a: a DNS seed's candidate in a backup means every slot's first opportunity is filled, and an
    // onion in a backup that every onion slot's first opportunity is.
    for (size_t layer{1}; layer < OPPORTUNITIES_PER_SLOT; ++layer) {
        for (size_t slot{0}; slot < SLOTS; ++slot) {
            const std::optional<Candidate>& candidate{assignment.opportunities[slot][layer]};
            if (!candidate) continue;
            for (size_t other{0}; other < SLOTS; ++other) {
                if (candidate->source == Source::DnsSeed || plan.slots[other].cls == SlotClass::Onion) assert(assignment.opportunities[other][0]);
            }
        }
    }
    // R5b: with four or more seeds that have candidates, the exit-path slots' first attempts come
    // from four seeds.
    if (std::ranges::count_if(kept_by_seed, [](const auto& seed) { return seed.second > 0; }) >= 4) {
        std::set<std::string> firsts;
        for (size_t slot{0}; slot < SLOTS; ++slot) {
            if (plan.slots[slot].cls == SlotClass::ExitPath) firsts.insert(assignment.opportunities[slot][0].value().provenance);
        }
        assert(firsts.size() == 4);
    }
    // R5c: the onion slots take the plan's onions alternately, layer by layer, while any remain, and
    // a DNS seed's candidate only once the exit-path slots at the same layer have drawn.
    size_t onions_left{plan.onions.size()};
    std::map<std::string, int> handed_out;
    for (size_t layer{0}; layer < OPPORTUNITIES_PER_SLOT; ++layer) {
        bool exit_path_filled{true};
        for (size_t slot{0}; slot < SLOTS; ++slot) {
            if (plan.slots[slot].cls == SlotClass::ExitPath && !assignment.opportunities[slot][layer]) exit_path_filled = false;
        }
        size_t onion_slots{0}, bundled{0};
        for (size_t slot{0}; slot < SLOTS; ++slot) {
            const std::optional<Candidate>& candidate{assignment.opportunities[slot][layer]};
            if (candidate && candidate->source == Source::DnsSeed) {
                ++handed_out[candidate->provenance];
                if (plan.slots[slot].cls == SlotClass::Onion) assert(exit_path_filled);
            }
            if (plan.slots[slot].cls != SlotClass::Onion) continue;
            ++onion_slots;
            if (candidate && candidate->source == Source::Bundled) ++bundled;
        }
        assert(bundled == std::min(onion_slots, onions_left));
        onions_left -= bundled;
    }
    assert(onions_left == 0);
    // R5b: a slot draws from a seed it has used only once no seed it has not used has a candidate
    // left. Every seed such a slot never drew from, then, has handed out every candidate it kept.
    for (size_t slot{0}; slot < SLOTS; ++slot) {
        std::multiset<std::string> used;
        for (const std::optional<Candidate>& candidate : assignment.opportunities[slot]) {
            if (candidate && candidate->source == Source::DnsSeed) used.insert(candidate->provenance);
        }
        if (std::set<std::string>(used.begin(), used.end()).size() == used.size()) continue;
        for (const auto& [name, kept] : kept_by_seed) {
            if (!used.contains(name)) assert(handed_out[name] == kept);
        }
    }
}

} // namespace

FUZZ_TARGET(privbcast_discovery)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    // The plan: DNS seed names and fixed seeds, onions and IPv4 addresses, each maybe listed twice,
    // with a time divisor.
    const Timing timing{provider.ConsumeIntegralInRange<int>(1, MAX_TIME_DIVISOR)};
    std::vector<std::string> dns_seeds;
    LIMITED_WHILE(provider.ConsumeBool(), 8) dns_seeds.push_back(strprintf("seed%d.example", provider.ConsumeIntegralInRange<int>(0, 9)));
    std::vector<CService> fixed_seeds;
    LIMITED_WHILE(provider.ConsumeBool(), 16) {
        const uint8_t n{provider.ConsumeIntegralInRange<uint8_t>(0, 31)};
        CNetAddr addr{IPv4(0x01020300 + n)};
        if (n % 2) {
            std::array<uint8_t, 32> pubkey{};
            pubkey[0] = n;
            const bool onion{addr.SetSpecial(OnionToString(pubkey))};
            assert(onion);
        }
        fixed_seeds.emplace_back(addr, 8333);
    }
    FastRandomContext rng{ConsumeUInt256(provider)};
    const Plan plan{DrawPlan(rng, timing, dns_seeds, fixed_seeds)};
    const uint16_t port{provider.ConsumeIntegral<uint16_t>()};

    // R1: the onions come from the fixed seeds alone, at most ONIONS_KEPT, each once.
    assert(plan.onions.size() <= ONIONS_KEPT);
    assert(std::set<CService>(plan.onions.begin(), plan.onions.end()).size() == plan.onions.size());
    for (const CService& onion : plan.onions) assert(onion.IsTor() && Contains(fixed_seeds, onion));

    // Answers come from a few addresses, so that seeds share some and repeat others: public and
    // private, IPv4 and IPv6, an IPv4 address mapped into IPv6, and fuzzed ones.
    std::vector<std::vector<uint8_t>> addresses{{1, 2, 3, 4}, {10, 0, 0, 1}, {127, 0, 0, 1}, {8, 8, 8, 8}};
    for (const char* text : {"2600::1", "fc00::1", "::ffff:1.2.3.4", "fd6b:88c0:8724::1"}) {
        std::vector<uint8_t> bytes(16);
        assert(inet_pton(AF_INET6, text, bytes.data()) == 1);
        addresses.push_back(bytes);
    }
    LIMITED_WHILE(provider.ConsumeBool(), 4) {
        std::vector<uint8_t> bytes{provider.ConsumeBytes<uint8_t>(provider.ConsumeBool() ? 4 : 16)};
        bytes.resize(bytes.size() <= 4 ? 4 : 16);
        addresses.push_back(bytes);
    }

    // Every query's script: an address of its own, or one of those, as its answer. Then the turns:
    // when each stream gets its answer, in the order the proxy gives them, at times in the window
    // and past it.
    const size_t queries{plan.seed_order.size() * QUERIES_PER_SEED};
    std::vector<Script> scripts(queries);
    for (size_t q{0}; q < queries; ++q) {
        Script& script{scripts[q]};
        script.connect = provider.PickValueInArray({Script::Connect::Now, Script::Connect::Now, Script::Connect::NoSocket, Script::Connect::Refused,
                                                    Script::Connect::Later, Script::Connect::LaterFails});
        script.reply = provider.PickValueInArray({Script::Reply::Address, Script::Reply::Address, Script::Reply::Name, Script::Reply::Error,
                                                  Script::Reply::Close, Script::Reply::Silent});
        // Only an address reply takes one from the input.
        const bool pick{script.reply == Script::Reply::Address && provider.ConsumeBool()};
        script.address = pick ? addresses[provider.ConsumeIntegralInRange<size_t>(0, addresses.size() - 1)] :
                                std::vector<uint8_t>{9, 9, static_cast<uint8_t>(q), 1};
    }
    const milliseconds window{timing.Scale(DISCOVERY_WINDOW)};
    const milliseconds start{provider.ConsumeBool() ? 0ms : milliseconds{provider.ConsumeIntegralInRange<int64_t>(0, timing.Scale(QUERY_GRACE).count() + 1)}};
    std::vector<size_t> order(queries);
    for (size_t i{0}; i < queries; ++i) order[i] = i;
    std::vector<std::pair<milliseconds, size_t>> turns;
    milliseconds at{start};
    for (size_t i{0}; i < queries; ++i) {
        std::swap(order[i], order[provider.ConsumeIntegralInRange<size_t>(i, queries - 1)]);
        // The turns span about one window, so that some answers come after it (C3).
        at += milliseconds{provider.ConsumeIntegralInRange<int64_t>(0, 2 * window.count() / static_cast<int64_t>(queries) + 1)};
        // Whether an answer at the window's end itself counts is not specified (the invariants hold
        // to the precision of a step): such a turn comes a millisecond later.
        if (at == window) at += 1ms;
        turns.emplace_back(at, order[i]);
    }

    const DiscoveryResult result{Discover(plan, port, scripts, start, turns)};

    // What discovery must have found: each seed, in the plan's order, with its queries launched at
    // job start unless the loop started too late (D1), its answers that came within the window
    // (C3), and of those the public routable IPv4 and IPv6 addresses, with the chain's port (R2).
    const bool launched{start < timing.Scale(QUERY_GRACE)};
    assert(result.seeds.size() == plan.seed_order.size());
    std::vector<int> opened(plan.seed_order.size());
    for (size_t q{0}; q < queries; ++q) {
        if (launched && scripts[q].Opens()) ++opened[q / QUERIES_PER_SEED];
    }
    for (size_t s{0}; s < plan.seed_order.size(); ++s) {
        const SeedAnswers& seed{result.seeds[s]};
        assert(seed.name == plan.seed_order[s]);
        assert(seed.queries == opened[s] && seed.skipped == QUERIES_PER_SEED - opened[s]);
        int answers{0}, rejected{0};
        std::vector<CService> usable;
        for (const auto& [time, q] : turns) {
            if (q / QUERIES_PER_SEED != s || !launched || time >= window || !scripts[q].Answers()) continue;
            ++answers;
            const CNetAddr answer{scripts[q].Answer()};
            if (scripts[q].reply == Script::Reply::Address && (answer.IsIPv4() || answer.IsIPv6()) && answer.IsRoutable()) {
                usable.emplace_back(answer, port);
            } else {
                ++rejected;
            }
        }
        assert(seed.answers == answers && seed.rejected == rejected);
        for (const CService& endpoint : seed.usable) assert((endpoint.IsIPv4() || endpoint.IsIPv6()) && endpoint.IsRoutable() && endpoint.GetPort() == port);
        std::sort(usable.begin(), usable.end());
        assert(seed.usable == usable);
    }
    // C3: discovery ended when its last query did, or else at the end of the window.
    milliseconds last_end{start};
    bool all_ended{true};
    for (size_t q{0}; q < queries && all_ended; ++q) {
        if (!launched || !scripts[q].Opens()) continue;
        const auto turn{std::ranges::find(turns, q, &std::pair<milliseconds, size_t>::second)};
        if (!scripts[q].Ends() || turn->first >= window) {
            all_ended = false;
        } else {
            last_end = std::max(last_end, turn->first);
        }
    }
    assert(result.duration == (all_ended ? last_end : window));

    const Assignment assignment{Assign(plan, result)};
    CheckAssignment(plan, result, assignment);

    // R5b: the order in which the answers arrive within the window changes nothing. The same
    // answers, and failures, at the same times but in another order give the same result, though
    // discovery may end at another time: when its last query ended.
    const auto in_window{std::ranges::count_if(turns, [&](const auto& turn) { return turn.first < window; })};
    std::vector<std::pair<milliseconds, size_t>> permuted{turns};
    for (ptrdiff_t i{in_window - 1}; i > 0; --i) {
        std::swap(permuted[i].second, permuted[provider.ConsumeIntegralInRange<ptrdiff_t>(0, i)].second);
    }
    const DiscoveryResult again{Discover(plan, port, scripts, start, permuted)};
    assert(SameAnswers(again, result));
    assert(Assign(plan, again) == assignment);
    // C3: nor do the turns after the end of the window, whose answers come too late.
    const std::vector<std::pair<milliseconds, size_t>> in_time{turns.begin(), turns.begin() + in_window};
    assert(SameAnswers(Discover(plan, port, scripts, start, in_time), result));
    // Nor does the order of a seed's answers in the result.
    DiscoveryResult shuffled{result};
    for (SeedAnswers& seed : shuffled.seeds) std::shuffle(seed.usable.begin(), seed.usable.end(), rng);
    assert(Assign(plan, shuffled) == assignment);
}
