// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <compat/compat.h>
#include <net_transport.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <primitives/transaction.h>
#include <privbcast/attempt.h>
#include <privbcast/discovery.h>
#include <privbcast/job.h>
#include <privbcast/timing.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/sock.h>
#include <util/time.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace privbcast;
using namespace std::chrono_literals;

namespace {

/** What a recipient, or the path to it, does with a connection. */
enum class Behavior : uint8_t {
    REFUSED,          //!< the SOCKS connect fails at once
    SLOW_REFUSED,     //!< the SOCKS connect fails after a while
    CLOSED,           //!< connects, then closes before a byte
    SILENT,           //!< connects, then says nothing at all
    BREAKS_AT_INV,    //!< completes the handshake, then refuses our INV's bytes: announced, not written
    CLOSES_AFTER_INV, //!< completes the handshake, takes our INV, then closes: announced and written
};

struct Recipient {
    Behavior behavior{Behavior::REFUSED};
    std::chrono::seconds delay{0}; //!< how long a SLOW_REFUSED connect takes
    std::chrono::seconds prep{0};  //!< how long preparing the dial took, on a loaded host
};

CTransactionRef Tx()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
    mtx.vin[0].scriptWitness.stack.push_back({1, 2, 3});
    mtx.vout.emplace_back(1000, CScript{} << OP_TRUE);
    return MakeTransactionRef(mtx);
}

CSerializedNetMsg PeerVersion()
{
    const int version{70016};
    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    return NetMsg::Make(NetMsgType::VERSION, version, services, int64_t{0}, uint64_t{0}, CNetAddr::V1(CService{}),
                        services, CNetAddr::V1(CService{}), uint64_t{42}, std::string{"/peer:1.0/"}, int{100}, true);
}

/** The far end of one connection, as its recipient's behavior says. Used by one slot thread. */
class PeerSock final : public ZeroSock
{
public:
    PeerSock(Behavior behavior, std::function<void()> on_close) : m_behavior{behavior}, m_on_close{std::move(on_close)} {}
    ~PeerSock() override { m_on_close(); }

    PeerSock& operator=(Sock&&) override
    {
        assert(false && "Move of Sock into PeerSock not allowed.");
        return *this;
    }

    ssize_t Recv(void* buf, size_t len, int flags) const override
    {
        if (m_behavior == Behavior::CLOSED || m_closed) return 0;
        Pump();
        if (m_to_tool.empty()) {
            errno = WSAEWOULDBLOCK;
            return -1;
        }
        const size_t n{std::min(len, m_to_tool.size())};
        std::memcpy(buf, m_to_tool.data(), n);
        if ((flags & MSG_PEEK) == 0) m_to_tool.erase(m_to_tool.begin(), m_to_tool.begin() + n);
        return static_cast<ssize_t>(n);
    }

    ssize_t Send(const void* data, size_t len, int) const override
    {
        if (m_behavior == Behavior::CLOSED || m_closed || (m_behavior == Behavior::BREAKS_AT_INV && m_app_seen >= 3)) {
            errno = ECONNRESET;
            return -1;
        }
        if (m_behavior == Behavior::SILENT) return static_cast<ssize_t>(len);
        std::span<const uint8_t> bytes{static_cast<const uint8_t*>(data), len};
        while (!bytes.empty()) {
            if (!m_peer->ReceivedBytes(bytes)) {
                errno = ECONNRESET;
                return -1;
            }
            if (!m_peer->ReceivedMessageComplete()) continue;
            bool reject{false};
            const CNetMessage msg{m_peer->GetReceivedMessage(NodeClock::now(), reject)};
            ++m_app_seen;
            if (reject) continue;
            if (msg.m_type == NetMsgType::VERSION) {
                m_pending.push_back(PeerVersion());
                m_pending.push_back(NetMsg::Make(NetMsgType::WTXIDRELAY));
                m_pending.push_back(NetMsg::Make(NetMsgType::VERACK));
            } else if (msg.m_type == NetMsgType::INV && m_behavior == Behavior::CLOSES_AFTER_INV) {
                m_closed = true;
            }
        }
        return static_cast<ssize_t>(len);
    }

private:
    void Pump() const
    {
        if (m_behavior == Behavior::SILENT) return;
        while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
        while (true) {
            const auto [bytes, more, type] = m_peer->GetBytesToSend(!m_pending.empty());
            if (bytes.empty()) break;
            m_to_tool.insert(m_to_tool.end(), bytes.begin(), bytes.end());
            m_peer->MarkBytesSent(bytes.size());
            while (!m_pending.empty() && m_peer->SetMessageToSend(m_pending.front())) m_pending.pop_front();
        }
    }

    const Behavior m_behavior;
    const std::function<void()> m_on_close;
    const std::unique_ptr<Transport> m_peer{std::make_unique<V2Transport>(NodeId{2}, /*initiating=*/false)};
    mutable std::vector<uint8_t> m_to_tool;
    mutable std::deque<CSerializedNetMsg> m_pending;
    mutable size_t m_app_seen{0};
    mutable bool m_closed{false};
};

/** Candidates as discovery would freeze them: exit-path ones per seed, in any tie order, and bundled onions. */
DiscoveryResult MakeDiscovery(FuzzedDataProvider& fdp)
{
    DiscoveryResult d;
    const size_t seeds{fdp.ConsumeIntegralInRange<size_t>(1, 4)};
    d.per_seed.resize(seeds);
    d.seeds.resize(seeds);
    for (size_t i = 0; i < seeds; ++i) {
        d.seeds[i].name = strprintf("seed%u.", i);
        d.tie_order.push_back(i);
    }
    for (size_t i = seeds; i > 1; --i) std::swap(d.tie_order[i - 1], d.tie_order[fdp.ConsumeIntegralInRange<size_t>(0, i - 1)]);
    uint32_t next{1};
    for (size_t i = 0; i < seeds; ++i) {
        const uint32_t kept{fdp.ConsumeIntegralInRange<uint32_t>(0, disc::MAX_PER_SEED)};
        for (uint32_t j = 0; j < kept; ++j) {
            d.per_seed[i].push_back(Candidate{LookupNumeric(strprintf("1.2.3.%u", next++), 8333), Source::DNS_SEED, d.seeds[i].name});
        }
        d.seeds[i].answers = d.seeds[i].accepted = d.seeds[i].kept = kept;
    }
    const uint32_t onions{fdp.ConsumeIntegralInRange<uint32_t>(0, disc::MAX_BUNDLED)};
    for (uint32_t i = 0; i < onions; ++i) {
        CNetAddr addr;
        assert(addr.SetSpecial(OnionToString(std::vector<uint8_t>(32, static_cast<uint8_t>(i + 1)))));
        d.onion.push_back(Candidate{CService{addr, 8333}, Source::BUNDLED, "bundled"});
    }
    return d;
}

/**
 * Reseed the global PRNG as at the start of the input. A job draws its schedule from it, so each run
 * of the same job draws the same schedule; the fuzz framework only lets an unused PRNG be seeded.
 */
void Reseed()
{
    g_used_g_prng = false;
    SeedRandomStateForTest(SeedRand::ZEROS);
}

struct Dial {
    CService addr;
    Clock::time_point at;
};

struct JobRun {
    JobReport report;
    std::vector<Dial> dials;
};

/**
 * One job on the mocked clock, driven as the unit tests drive it: time moves only while every job
 * thread waits, and then straight to the next wait due, so the job runs the same at any host speed.
 */
JobRun Run(const DiscoveryResult& discovery, const std::map<CService, Recipient>& recipients, std::optional<std::chrono::seconds> cancel_after)
{
    static const CTransactionRef TX{Tx()};
    JobRun out;
    Reseed();
    mocktime::Start();
    const auto t0{Clock::now()};
    std::mutex dials_mutex;
    // A slot's connections follow one another: the previous one is closed before the next is dialled.
    std::map<CService, uint32_t> slot_of;
    const Assignment assignment{AssignCandidates(discovery)};
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        for (const auto& cand : assignment[s]) {
            if (cand) slot_of.emplace(cand->addr, s);
        }
    }
    std::array<int, plan::SLOTS> open{};
    std::atomic<bool> cancelled{false};
    JobConfig cfg;
    cfg.tx = TX;
    cfg.chain = "regtest";
    cfg.tor = Proxy{LookupNumeric("127.0.0.1", 9050), /*tor_stream_isolation=*/true};
    cfg.interrupted = [&] { return cancelled.load(); };
    cfg.discover = [&] { return discovery; };
    cfg.connector = [&](const Candidate& cand, const Socks5Params&) -> Connector {
        // Preparing the attempt can stall; past the start grace, the opportunity is missed, not dialled late.
        if (const auto prep{recipients.at(cand.addr).prep}; prep > 0s) WaitUntil(Clock::now() + prep, [&] { return cancelled.load(); });
        return [&, cand](bool& proxy_failed) -> std::unique_ptr<Sock> {
            proxy_failed = false;
            // Cancellation is raised only while every job thread waits, and a dial checks for it last.
            assert(!cancelled.load());
            {
                std::lock_guard lock{dials_mutex};
                out.dials.push_back({cand.addr, Clock::now()});
            }
            const Recipient& r{recipients.at(cand.addr)};
            switch (r.behavior) {
            case Behavior::REFUSED:
                return nullptr;
            case Behavior::SLOW_REFUSED:
                WaitUntil(Clock::now() + r.delay, [&] { return cancelled.load(); });
                return nullptr;
            default: {
                const uint32_t slot{slot_of.at(cand.addr)};
                {
                    std::lock_guard lock{dials_mutex};
                    assert(open[slot]++ == 0);
                }
                return std::make_unique<PeerSock>(r.behavior, [&, slot] {
                    std::lock_guard lock{dials_mutex};
                    --open[slot];
                });
            }
            }
        };
    };
    std::optional<JobReport> report;
    std::atomic<bool> done{false};
    std::thread runner([&] {
        report.emplace(RunJob(cfg));
        done = true;
    });
    bool parked{true};
    while (!done) {
        if (!mocktime::Settle(30s, [&] { return done.load(); })) {
            parked = false;
            cancelled = true;
            WakeWaiters();
            break;
        }
        if (done) break;
        if (cancel_after && !cancelled && Clock::now() >= t0 + *cancel_after) {
            cancelled = true;
            WakeWaiters();
            continue;
        }
        if (const auto next{mocktime::NextWait()}) {
            auto step{std::max(*next, std::chrono::seconds{1})};
            if (cancel_after && !cancelled) step = std::min(step, std::max(std::chrono::duration_cast<std::chrono::seconds>(t0 + *cancel_after - Clock::now()), std::chrono::seconds{1}));
            mocktime::Advance(step);
        } else {
            std::this_thread::sleep_for(1ms); // only unbounded waits are pending: nothing needs time
        }
    }
    runner.join();
    mocktime::Stop();
    // Every job thread waits only on the clock or on its cancellation: nothing hangs.
    assert(parked);
    out.report = std::move(*report);
    return out;
}

int64_t Ms(Clock::duration d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); }

using Where = std::map<CService, std::pair<uint32_t, uint32_t>>;

/** The job against its fixed schedule and its report; returns each slot's dials in order. */
std::array<std::vector<Dial>, plan::SLOTS> Check(const JobRun& o, const Schedule& schedule, const Where& where)
{
    std::array<std::vector<Dial>, plan::SLOTS> per_slot;
    std::set<CService> dialled;
    for (const Dial& d : o.dials) {
        // Only an assigned candidate, never twice, at its own opportunity within the start grace.
        assert(dialled.insert(d.addr).second);
        const auto [s, k] = where.at(d.addr);
        const auto start{schedule.OpportunityStart(s, k)};
        assert(d.at >= start && d.at <= start + Scaled(plan::START_GRACE));
        per_slot[s].push_back(d);
    }
    const UniValue& json{o.report.json};
    const UniValue& summary{json["summary"]};
    assert(summary["connections"].getInt<int64_t>() == static_cast<int64_t>(o.dials.size()));
    const UniValue& slots{json["slots"]};
    assert(slots.size() == plan::SLOTS);
    int64_t written{0};
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        const UniValue& slot{slots[s]};
        assert(slot["slot"].getInt<uint32_t>() == s);
        const UniValue& attempts{slot["attempts"]};
        // Each dial is one reported attempt, in order, at its scheduled start.
        assert(attempts.size() == per_slot[s].size());
        bool announced{false};
        for (size_t i = 0; i < attempts.size(); ++i) {
            const UniValue& a{attempts[i]};
            // Nothing in a slot follows an announcement.
            assert(!announced);
            const Dial& d{per_slot[s][i]};
            assert(a["endpoint"].get_str() == d.addr.ToStringAddrPort());
            const auto k{where.at(d.addr).second};
            if (i > 0) assert(where.at(per_slot[s][i - 1].addr).second < k);
            assert(a["scheduled_start_ms"].getInt<int64_t>() == Ms(schedule.OpportunityStart(s, k) - schedule.t0));
            if (!a["inv_handed_ms"].isNull()) announced = true;
            if (!a["inv_written_ms"].isNull()) ++written;
        }
        // A slot that neither announced nor was cut short accounts for every opportunity.
        const int64_t accounted{static_cast<int64_t>(attempts.size()) + slot["missed_opportunities"].getInt<int64_t>() + slot["empty_opportunities"].getInt<int64_t>()};
        assert(accounted <= plan::OPPORTUNITIES_PER_SLOT);
        if (!announced && !slot["interrupted"].get_bool() && slot["error"].isNull()) assert(accounted == plan::OPPORTUNITIES_PER_SLOT);
    }
    assert(summary["announcements_written"].getInt<int64_t>() == written);
    assert(o.report.exit_code == (written > 0 ? 0 : 2));
    // Whatever the recipients do, the job is over by its scheduled bound.
    assert(summary["duration_ms"].getInt<int64_t>() <= Ms(Scaled(plan::SCHEDULED_BOUND)));
    return per_slot;
}

void initialize_privbcast_job()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

} // namespace

/**
 * Whole jobs, with every recipient's behavior chosen upfront (the job's threads cannot share the
 * fuzz input). The job must dial only at its fixed opportunities, never after an announcement in
 * the same slot or after cancellation, and report exactly what it did. It is then run again with
 * one slot's recipients behaving otherwise: every other slot must dial the same candidates at the
 * same times, as each slot follows only its own pre-drawn schedule.
 */
FUZZ_TARGET(privbcast_job, .init = initialize_privbcast_job)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const DiscoveryResult discovery{MakeDiscovery(fdp)};
    const Assignment assignment{AssignCandidates(discovery)};
    Where where;
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        for (uint32_t k = 0; k < plan::OPPORTUNITIES_PER_SLOT; ++k) {
            // A candidate is used by exactly one opportunity.
            if (assignment[s][k]) assert(where.emplace(assignment[s][k]->addr, std::pair{s, k}).second);
        }
    }
    const auto consume_recipient = [&] {
        Recipient r;
        r.behavior = static_cast<Behavior>(fdp.ConsumeIntegralInRange<uint8_t>(0, 5));
        r.delay = std::chrono::seconds{fdp.ConsumeIntegralInRange<int>(1, 40)};
        if (fdp.ConsumeIntegralInRange<int>(0, 3) == 0) r.prep = std::chrono::seconds{fdp.ConsumeIntegralInRange<int>(1, 10)};
        return r;
    };
    std::map<CService, Recipient> recipients;
    for (const auto& [addr, _] : where) recipients[addr] = consume_recipient();
    std::optional<std::chrono::seconds> cancel_after;
    if (fdp.ConsumeIntegralInRange<int>(0, 3) == 0) cancel_after = std::chrono::seconds{fdp.ConsumeIntegralInRange<int>(0, 600)};
    const uint32_t changed{fdp.ConsumeIntegralInRange<uint32_t>(0, plan::SLOTS - 1)};
    std::map<CService, Recipient> twin_recipients{recipients};
    for (const auto& [addr, sk] : where) {
        if (sk.first == changed) twin_recipients[addr] = consume_recipient();
    }

    // The schedule the job draws: the same global PRNG state and the same start time.
    Reseed();
    mocktime::Start();
    FastRandomContext rng;
    const Schedule schedule{Schedule::Draw(Clock::now(), rng)};
    mocktime::Stop();

    const JobRun real{Run(discovery, recipients, cancel_after)};
    const auto real_dials{Check(real, schedule, where)};
    const JobRun twin{Run(discovery, twin_recipients, cancel_after)};
    const auto twin_dials{Check(twin, schedule, where)};
    // Only the changed slot may differ.
    for (uint32_t s = 0; s < plan::SLOTS; ++s) {
        if (s == changed) continue;
        assert(real_dials[s].size() == twin_dials[s].size());
        for (size_t i = 0; i < real_dials[s].size(); ++i) {
            assert(real_dials[s][i].addr == twin_dials[s][i].addr && real_dials[s][i].at == twin_dials[s][i].at);
        }
        const UniValue& a{real.report.json["slots"][s]};
        const UniValue& b{twin.report.json["slots"][s]};
        for (const char* key : {"missed_opportunities", "empty_opportunities", "interrupted", "error"}) assert(a[key].write() == b[key].write());
        for (size_t i = 0; i < a["attempts"].size(); ++i) {
            for (const char* key : {"endpoint", "outcome", "reason", "scheduled_start_ms", "started_ms", "connected_ms", "inv_handed_ms", "inv_written_ms", "ended_ms"}) {
                assert(a["attempts"][i][key].write() == b["attempts"][i][key].write());
            }
        }
    }
}
