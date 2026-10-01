// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privbcast/input.h>

#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <netaddress.h>
#include <netbase.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <array>
#include <cstddef>
#include <ios>
#include <istream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef WIN32
#include <cerrno>
#include <climits>
#include <poll.h>
#include <unistd.h>
#endif

namespace privbcast {
namespace {

/** The longest name a SOCKS5 request carries: its length is one byte. */
constexpr size_t MAX_SOCKS5_NAME_SIZE{255};

/** 127.0.0.0/8 or ::1. */
bool IsLoopback(const CService& addr)
{
    if (addr.IsIPv4()) return (addr.GetLinkedIPv4() >> 24) == 127;
    return addr.IsIPv6() && addr.IsLocal();
}

} // namespace

util::Result<std::vector<CTransactionRef>> ParseTransactions(std::string_view text)
{
    std::vector<std::string_view> tokens;
    size_t pos{0};
    while (pos < text.size()) {
        while (pos < text.size() && IsSpace(text[pos])) ++pos;
        const size_t start{pos};
        while (pos < text.size() && !IsSpace(text[pos])) ++pos;
        if (pos > start) tokens.push_back(text.substr(start, pos - start));
    }
    if (tokens.empty()) return util::Error{Untranslated("no transaction given")};
    if (tokens.size() > 1) return util::Error{Untranslated(strprintf("%d transactions given, expected one", tokens.size()))};

    std::vector<CTransactionRef> txs;
    for (const std::string_view token : tokens) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, std::string{token})) {
            return util::Error{Untranslated("the transaction is not hex or does not decode")};
        }
        txs.push_back(MakeTransactionRef(std::move(mtx)));
    }
    return txs;
}

util::Result<void> CheckForBroadcast(const CTransaction& tx, CAmount max_burn)
{
    TxValidationState state;
    if (!CheckTransaction(tx, state)) {
        return util::Error{Untranslated(strprintf("the transaction is invalid: %s", state.ToString()))};
    }
    if (tx.IsCoinBase()) return util::Error{Untranslated("the transaction is a coinbase")};
    const int32_t weight{GetTransactionWeight(tx)};
    if (weight > MAX_STANDARD_TX_WEIGHT) {
        return util::Error{Untranslated(strprintf("the transaction weighs %d, more than %d", weight, MAX_STANDARD_TX_WEIGHT))};
    }
    for (size_t i{0}; i < tx.vout.size(); ++i) {
        const CTxOut& out{tx.vout[i]};
        if ((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps()) && out.nValue > max_burn) {
            return util::Error{Untranslated(strprintf("output %d burns %s, more than the %s allowed",
                                                      i, FormatMoney(out.nValue), FormatMoney(max_burn)))};
        }
    }
    return {};
}

util::Result<std::string> ReadBounded(std::istream& in, size_t bound)
{
    std::string text;
    std::array<char, 64 * 1024> chunk;
    while (text.size() <= bound) {
        // Up to one byte past the bound, to tell whether there is more.
        const size_t room{bound - text.size()};
        in.read(chunk.data(), static_cast<std::streamsize>(room < chunk.size() ? room + 1 : chunk.size()));
        text.append(chunk.data(), static_cast<size_t>(in.gcount()));
        if (!in) break;
    }
    if (text.size() > bound) return util::Error{Untranslated(strprintf("the input is longer than %d bytes", bound))};
    // A stream that failed before its end: what was read is not the whole input.
    if (in.bad() || (in.fail() && !in.eof())) return util::Error{Untranslated("reading the input failed")};
    return text;
}

util::Result<void> CheckSeedName(std::string_view name)
{
    if (name.empty()) return util::Error{Untranslated("a DNS seed name is empty")};
    if (name.size() > MAX_SOCKS5_NAME_SIZE) {
        return util::Error{Untranslated(strprintf("a DNS seed name of %d bytes is longer than SOCKS5 can carry (%d)", name.size(), MAX_SOCKS5_NAME_SIZE))};
    }
    if (name.find('\0') != std::string_view::npos) return util::Error{Untranslated("a DNS seed name contains a NUL byte")};
    return {};
}

util::Result<Proxy> ParseTor(const std::string& value, uint16_t default_port)
{
    if (value.starts_with(ADDR_PREFIX_UNIX)) {
        if (value.size() == ADDR_PREFIX_UNIX.size() || !IsUnixSocketPath(value)) {
            return util::Error{Untranslated(strprintf("-tor=%s is not a usable unix socket path", value))};
        }
        return Proxy{value};
    }
    const CService service{LookupNumeric(value, default_port)};
    if (!service.IsValid() || service.GetPort() == 0) {
        return util::Error{Untranslated(strprintf("-tor=%s is neither an ip:port nor a unix:<path>", value))};
    }
    if (!IsLoopback(service)) {
        return util::Error{Untranslated(strprintf("-tor=%s is not a loopback address: a remote proxy would see every destination in plaintext", value))};
    }
    return Proxy{service};
}

#ifndef WIN32
bool WriteIfReady(int fd, std::string_view text)
{
    if (text.size() > PIPE_BUF) return false;
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, /*timeout=*/0) != 1 || !(pfd.revents & POLLOUT)) return false;
    ssize_t written;
    do {
        written = write(fd, text.data(), text.size());
    } while (written < 0 && errno == EINTR);
    return written == static_cast<ssize_t>(text.size());
}
#endif

} // namespace privbcast
