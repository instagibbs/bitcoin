// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/compat.h>
#include <netaddress.h>
#include <privbcast/socks5.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

using privbcast::Socks5Client;

namespace {

bool SameState(const Socks5Client& a, const Socks5Client& b)
{
    return a.Done() == b.Done() && a.Failed() == b.Failed() && a.Reason() == b.Reason() &&
           a.Answer() == b.Answer() && std::ranges::equal(a.BytesToSend(), b.BytesToSend());
}

/**
 * The exchange as RFC 1928, RFC 1929 and Tor's RESOLVE extension describe it: what the client
 * writes, given its credentials and request, and how it takes each byte of the proxy's replies. A
 * reply byte that comes before the message it answers is written in full fails the exchange.
 */
class Model
{
public:
    Model(Socks5Client::Command cmd, const std::string& host, uint16_t port, const std::string& username, const std::string& password)
        : m_cmd{cmd}
    {
        // A host that SOCKS5 cannot carry fails the exchange before anything is written.
        if (host.empty() || host.size() > 255 || host.find('\0') != std::string::npos) {
            m_failed = true;
            return;
        }
        // The greeting offers username and password authentication alone (B2), then come the
        // credentials.
        m_messages[0] = {0x05, 0x01, 0x02};
        m_messages[1] = {0x01, static_cast<uint8_t>(username.size())};
        m_messages[1].insert(m_messages[1].end(), username.begin(), username.end());
        m_messages[1].push_back(static_cast<uint8_t>(password.size()));
        m_messages[1].insert(m_messages[1].end(), password.begin(), password.end());
        // The request carries a numeric address as one, and any other host as a domain name.
        std::vector<uint8_t>& request{m_messages[2]};
        request = {0x05, static_cast<uint8_t>(cmd), 0x00};
        std::array<uint8_t, 16> addr;
        if (inet_pton(AF_INET, host.c_str(), addr.data()) == 1) {
            request.push_back(0x01);
            request.insert(request.end(), addr.begin(), addr.begin() + 4);
        } else if (inet_pton(AF_INET6, host.c_str(), addr.data()) == 1) {
            request.push_back(0x04);
            request.insert(request.end(), addr.begin(), addr.end());
        } else {
            request.push_back(0x03);
            request.push_back(static_cast<uint8_t>(host.size()));
            request.insert(request.end(), host.begin(), host.end());
        }
        request.push_back(static_cast<uint8_t>(port >> 8));
        request.push_back(static_cast<uint8_t>(port & 0xFF));
    }

    /** What the client writes next. */
    std::span<const uint8_t> ToSend() const
    {
        if (m_done || m_failed) return {};
        return std::span{m_messages.at(m_stage)}.subspan(m_written);
    }
    void Written(size_t n) { m_written += n; }
    /** The proxy's next bytes. Returns how many the client takes: up to the end of the exchange,
     *  the byte that fails it included. */
    size_t Received(std::span<const uint8_t> bytes)
    {
        size_t used{0};
        for (const uint8_t byte : bytes) {
            if (m_done || m_failed) break;
            ++used;
            if (m_written < m_messages.at(m_stage).size()) {
                m_failed = true;
                break;
            }
            Take(byte);
        }
        return used;
    }
    bool Done() const { return m_done; }
    bool Failed() const { return m_failed; }
    std::optional<CNetAddr> Answer() const { return m_answer; }

private:
    const Socks5Client::Command m_cmd;
    std::array<std::vector<uint8_t>, 3> m_messages;
    /** The message being written, and the reply that answers it. */
    size_t m_stage{0};
    size_t m_written{0};
    std::vector<uint8_t> m_reply;
    bool m_done{false};
    bool m_failed{false};
    std::optional<CNetAddr> m_answer;

    void Take(uint8_t byte)
    {
        m_reply.push_back(byte);
        const size_t pos{m_reply.size() - 1};
        // VER METHOD, then VER STATUS: the version, and username and password authentication
        // selected, then accepted.
        if (m_stage < 2) {
            const std::array<uint8_t, 2> right{m_stage == 0 ? std::array<uint8_t, 2>{0x05, 0x02} : std::array<uint8_t, 2>{0x01, 0x00}};
            if (byte != right[pos]) {
                m_failed = true;
            } else if (pos == 1) {
                ++m_stage;
                m_written = 0;
                m_reply.clear();
            }
            return;
        }
        // VER REP RSV ATYP BND.ADDR BND.PORT: success, and an IPv4 address, a name of at least one
        // byte or an IPv6 address.
        if ((pos == 0 && byte != 0x05) || (pos == 1 && byte != 0x00) || (pos == 2 && byte != 0x00) ||
            (pos == 3 && byte != 0x01 && byte != 0x03 && byte != 0x04) || (pos == 4 && m_reply[3] == 0x03 && byte == 0)) {
            m_failed = true;
            return;
        }
        if (pos < 4) return;
        const uint8_t atyp{m_reply[3]};
        const size_t addr_size{atyp == 0x01 ? size_t{4} : atyp == 0x04 ? size_t{16} : 1 + size_t{m_reply[4]}};
        if (m_reply.size() < 4 + addr_size + 2) return;
        m_done = true;
        // A RESOLVE answer is the address in the reply; a name gives none.
        if (m_cmd != Socks5Client::Command::Resolve || atyp == 0x03) return;
        if (atyp == 0x01) {
            in_addr ipv4;
            std::memcpy(&ipv4, m_reply.data() + 4, sizeof(ipv4));
            m_answer = CNetAddr{ipv4};
        } else {
            in6_addr ipv6;
            std::memcpy(&ipv6, m_reply.data() + 4, sizeof(ipv6));
            m_answer = CNetAddr{ipv6};
        }
    }
};

} // namespace

FUZZ_TARGET(privbcast_socks5)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    FastRandomContext rng{ConsumeUInt256(provider)};
    const auto cmd{provider.ConsumeBool() ? Socks5Client::Command::Connect : Socks5Client::Command::Resolve};
    const std::string host{provider.ConsumeBool() ? ConsumeNetAddr(provider).ToStringAddr() : provider.ConsumeRandomLengthString(300)};
    const uint16_t port{provider.ConsumeIntegral<uint16_t>()};
    Socks5Client client{cmd, host, port, rng};
    assert(client.Username().size() == 32 && IsHex(client.Username()));
    assert(client.Password().size() == 32 && IsHex(client.Password()));
    Model model{cmd, host, port, client.Username(), client.Password()};

    // The proxy's replies: the method selection, the authentication status and the reply to the
    // request, each field right or any byte, the bound address of any type and length, then the
    // destination's first bytes. They may stop anywhere.
    const auto field{[&](uint8_t right) { return provider.ConsumeBool() ? right : provider.ConsumeIntegral<uint8_t>(); }};
    std::vector<uint8_t> replies{field(0x05), field(0x02), field(0x01), field(0x00), field(0x05), field(0x00), field(0x00)};
    const uint8_t atyp{provider.ConsumeBool() ? provider.PickValueInArray<uint8_t>({0x01, 0x03, 0x04}) : provider.ConsumeIntegral<uint8_t>()};
    replies.push_back(atyp);
    if (atyp == 0x03) {
        const std::string name{provider.ConsumeRandomLengthString(255)};
        replies.push_back(field(static_cast<uint8_t>(name.size())));
        replies.insert(replies.end(), name.begin(), name.end());
    } else {
        const size_t size{atyp == 0x01 ? size_t{4} : atyp == 0x04 ? size_t{16} : provider.ConsumeIntegralInRange<size_t>(0, 32)};
        std::vector<uint8_t> addr{provider.ConsumeBytes<uint8_t>(size)};
        addr.resize(size);
        replies.insert(replies.end(), addr.begin(), addr.end());
    }
    replies.push_back(provider.ConsumeIntegral<uint8_t>());
    replies.push_back(provider.ConsumeIntegral<uint8_t>());
    // Where each reply ends.
    const std::array<size_t, 3> ends{2, 4, replies.size()};
    const std::vector<uint8_t> after{ConsumeRandomLengthByteVector(provider, 16)};
    replies.insert(replies.end(), after.begin(), after.end());
    if (provider.ConsumeBool()) replies.resize(provider.ConsumeIntegralInRange<size_t>(0, replies.size()));
    size_t next{0};

    const auto write{[&](size_t n) {
        client.MarkSent(n);
        model.Written(n);
    }};

    LIMITED_WHILE(provider.remaining_bytes() > 0, 10'000) {
        CallOneOf(
            provider,
            [&] {
                write(provider.ConsumeIntegralInRange<size_t>(0, client.BytesToSend().size()));
            },
            [&] {
                write(client.BytesToSend().size());
            },
            [&] {
                // The proxy sends its next bytes: as many as it likes, or the rest of a reply.
                size_t size{provider.ConsumeIntegralInRange<size_t>(0, replies.size() - next)};
                if (provider.ConsumeBool()) {
                    const auto end{std::ranges::find_if(ends, [&](size_t reply_end) { return reply_end > next; })};
                    size = std::min(end == ends.end() ? replies.size() : *end, replies.size()) - next;
                }
                const std::span<const uint8_t> chunk{std::span{replies}.subspan(next, size)};
                next += chunk.size();
                const bool ended_before{client.Done() || client.Failed()};
                Socks5Client copy{client};
                const size_t used{client.Received(chunk)};
                assert(used == model.Received(chunk));
                if (ended_before) assert(used == 0);
                // Until the exchange ends, every byte is consumed.
                if (!client.Done() && !client.Failed()) assert(used == chunk.size());
                // Nothing past the consumed bytes was read: they alone lead to the same state.
                assert(copy.Received(chunk.first(used)) == used);
                assert(SameState(copy, client));
            });
        assert(!(client.Done() && client.Failed()));
        // The outcome is the model's, and so is what the client offers to write.
        assert(client.Done() == model.Done() && client.Failed() == model.Failed());
        assert(std::ranges::equal(client.BytesToSend(), model.ToSend()));
        // Nothing is sent once failed, and nothing is left to send once done.
        if (client.Done() || client.Failed()) assert(client.BytesToSend().empty());
        if (client.Failed()) assert(!client.Reason().empty());
        // Only a RESOLVE answered with an IPv4 or IPv6 address has an answer: that address. Whether
        // it is usable is for discovery to judge (R2).
        assert(client.Answer() == model.Answer());
        if (client.Answer()) assert(client.Done() && cmd == Socks5Client::Command::Resolve);
    }
}
