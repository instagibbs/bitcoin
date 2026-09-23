// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/compat.h>
#include <netaddress.h>
#include <netbase.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/threadinterrupt.h>
#include <util/time.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

extern std::chrono::milliseconds g_socks5_recv_timeout;

namespace {
decltype(g_socks5_recv_timeout) default_socks5_recv_timeout;
};

void initialize_socks5()
{
    static const auto testing_setup = MakeNoLogFileContext<const BasicTestingSetup>();
    default_socks5_recv_timeout = g_socks5_recv_timeout;
}

FUZZ_TARGET(socks5, .init = initialize_socks5)
{
    g_socks5_interrupt.reset();
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fuzzed_data_provider)};
    FakeSteadyClock steady_clock;
    ProxyCredentials proxy_credentials;
    proxy_credentials.username = fuzzed_data_provider.ConsumeRandomLengthString(512);
    proxy_credentials.password = fuzzed_data_provider.ConsumeRandomLengthString(512);
    const bool interrupted{fuzzed_data_provider.ConsumeBool()};
    if (interrupted) {
        g_socks5_interrupt();
    }
    // Set FUZZED_SOCKET_FAKE_LATENCY=1 to exercise recv timeout code paths. This
    // will slow down fuzzing.
    g_socks5_recv_timeout = (fuzzed_data_provider.ConsumeBool() && std::getenv("FUZZED_SOCKET_FAKE_LATENCY") != nullptr) ? 1ms : default_socks5_recv_timeout;
    FuzzedSock fuzzed_sock = ConsumeSock(fuzzed_data_provider, steady_clock);
    // This Socks5(...) fuzzing harness would have caught CVE-2017-18350 within
    // a few seconds of fuzzing.
    auto str_dest = fuzzed_data_provider.ConsumeRandomLengthString(512);
    auto port = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
    auto* auth = fuzzed_data_provider.ConsumeBool() ? &proxy_credentials : nullptr;
    // An absolute exchange deadline: none, already past, or ahead (the per-stage timeout then
    // still applies; the fuzzed socket answers immediately, so this never waits).
    Socks5Deadline deadline;
    if (fuzzed_data_provider.ConsumeBool()) {
        deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{fuzzed_data_provider.ConsumeIntegralInRange<int>(-1000, 10000)};
    }
    // Nothing succeeds once interrupted or past its deadline.
    const bool doomed{interrupted || (deadline && *deadline <= std::chrono::steady_clock::now())};
    if (fuzzed_data_provider.ConsumeBool()) {
        const auto addr{Socks5Resolve(str_dest, proxy_credentials, fuzzed_sock, deadline)};
        // A RESOLVE answer is a usable IPv4 or IPv6 address, or nothing.
        if (addr) assert(!doomed && addr->IsValid() && (addr->IsIPv4() || addr->IsIPv6()));
    } else {
        const bool connected{Socks5(str_dest, port, auth, fuzzed_sock, /*require_auth=*/auth != nullptr && fuzzed_data_provider.ConsumeBool(), deadline)};
        assert(!(connected && doomed));
    }
}

/**
 * Socks5Resolve() against a proxy whose every reply field the fuzzer chooses, right or wrong, and
 * whose reply may end early. A model of the exchange (RFC 1928, RFC 1929 and Tor's RESOLVE
 * extension) predicts both the result and exactly what the client sends: in particular the name
 * goes out only after the proxy has accepted username/password credentials, which isolate the
 * stream.
 */
FUZZ_TARGET(socks5_resolve, .init = initialize_socks5)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    FakeNodeClock clock{ConsumeTime(fdp)};
    FakeSteadyClock steady_clock;
    const std::string name{fdp.ConsumeRandomLengthString(300)};
    ProxyCredentials auth;
    auth.username = fdp.ConsumeRandomLengthString(300);
    auth.password = fdp.ConsumeRandomLengthString(300);
    // Each reply field is right, or any byte.
    const auto field = [&](uint8_t right) { return fdp.ConsumeBool() ? right : fdp.ConsumeIntegral<uint8_t>(); };
    const uint8_t ver{field(0x05)}, method{field(0x02)};
    const uint8_t auth_ver{field(0x01)}, auth_status{field(0x00)};
    const uint8_t rver{field(0x05)}, rep{field(0x00)}, rsv{field(0x00)};
    const uint8_t atyp{fdp.PickValueInArray<uint8_t>({0x01, 0x03, 0x04, fdp.ConsumeIntegral<uint8_t>()})};
    const size_t addr_len{atyp == 0x01 ? 4U : atyp == 0x04 ? 16U : atyp == 0x03 ? 1U + fdp.ConsumeIntegral<uint8_t>() : fdp.ConsumeIntegralInRange<size_t>(0, 32)};
    std::vector<uint8_t> addr_bytes{fdp.ConsumeBytes<uint8_t>(addr_len)};
    addr_bytes.resize(addr_len);
    if (atyp == 0x03) addr_bytes[0] = addr_len - 1;

    // The proxy's side: it answers the method selection, then the credentials if it chose them,
    // then the request, and may stop anywhere.
    std::vector<uint8_t> reply{ver, method};
    if (method == 0x02) reply.insert(reply.end(), {auth_ver, auth_status});
    const size_t request_reply_at{reply.size()};
    reply.insert(reply.end(), {rver, rep, rsv, atyp});
    reply.insert(reply.end(), addr_bytes.begin(), addr_bytes.end());
    reply.insert(reply.end(), {0x12, 0x34});
    reply.resize(fdp.ConsumeBool() ? reply.size() : fdp.ConsumeIntegralInRange<size_t>(0, reply.size()));

    Socks5Params params;
    params.stage_timeout = std::chrono::seconds{10};
    CThreadInterrupt interrupt;
    params.interrupt = &interrupt;
    const uint8_t mode{fdp.ConsumeIntegralInRange<uint8_t>(0, 7)};
    const bool interrupted{mode == 1}, expired{mode == 2};
    if (interrupted) interrupt();
    if (expired) params.deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds{1};

    auto pipes{std::make_shared<DynSock::Pipes>()};
    pipes->recv.PushBytes(reply.data(), reply.size());
    pipes->recv.Eof();
    const auto addr{Socks5Resolve(name, auth, DynSock{pipes}, params)};
    std::vector<uint8_t> sent;
    for (uint8_t buf[1024];;) {
        const ssize_t n{pipes->send.GetBytes(buf, sizeof(buf))};
        if (n <= 0) break;
        sent.insert(sent.end(), buf, buf + n);
    }

    // The model: what the client must send, and what it may return.
    std::vector<uint8_t> expected_sent;
    std::optional<CNetAddr> expected;
    [&] {
        if (name.size() > 255 || expired) return;
        expected_sent.insert(expected_sent.end(), {0x05, 0x02, 0x00, 0x02}); // SOCKS5, offering no auth and username/password
        if (interrupted || reply.size() < 2 || ver != 0x05 || method != 0x02) return;
        if (auth.username.size() > 255 || auth.password.size() > 255) return;
        expected_sent.push_back(0x01);
        expected_sent.push_back(auth.username.size());
        expected_sent.insert(expected_sent.end(), auth.username.begin(), auth.username.end());
        expected_sent.push_back(auth.password.size());
        expected_sent.insert(expected_sent.end(), auth.password.begin(), auth.password.end());
        if (reply.size() < 4 || auth_ver != 0x01 || auth_status != 0x00) return;
        expected_sent.insert(expected_sent.end(), {0x05, 0xF0, 0x00, 0x03, uint8_t(name.size())}); // RESOLVE, by name
        expected_sent.insert(expected_sent.end(), name.begin(), name.end());
        expected_sent.insert(expected_sent.end(), {0x00, 0x00});
        if (reply.size() < request_reply_at + 4 + addr_len + 2) return;
        if (rver != 0x05 || rep != 0x00 || rsv != 0x00) return;
        CNetAddr answer;
        if (atyp == 0x01) {
            in_addr a;
            std::memcpy(&a, addr_bytes.data(), sizeof(a));
            answer = CNetAddr{a};
        } else if (atyp == 0x04) {
            in6_addr a;
            std::memcpy(&a, addr_bytes.data(), sizeof(a));
            answer = CNetAddr{a};
        } else {
            return; // a name, or an unknown address type: not a usable answer
        }
        if (answer.IsValid() && (answer.IsIPv4() || answer.IsIPv6())) expected = answer;
    }();
    // Once interrupted, the client may have sent its method selection before noticing, never more.
    if (interrupted) assert(sent.empty() || sent == expected_sent);
    else assert(sent == expected_sent);
    assert(addr == expected);
}
