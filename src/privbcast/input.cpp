// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <privbcast/input.h>

#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <netaddress.h>
#include <netbase.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/string.h>

#include <algorithm>
#include <array>
#include <utility>

namespace privbcast {

static_assert(MAX_STDIN_BYTES >= 2 * MAX_BLOCK_SERIALIZED_SIZE);

bool ReadBounded(std::istream& in, size_t max_bytes, std::string& out, std::string& error)
{
    std::string input;
    std::array<char, 65536> chunk;
    while (in.good()) {
        // Ask for no more than the allowance plus one byte: a producer that stays open after
        // sending too much is rejected as soon as the excess byte arrives, not at EOF.
        const size_t want{std::min(chunk.size(), max_bytes + 1 - input.size())};
        in.read(chunk.data(), want);
        const auto got{static_cast<size_t>(in.gcount())};
        if (got == 0) break;
        if (input.size() + got > max_bytes) {
            error = "stdin too large";
            return false;
        }
        input.append(chunk.data(), got);
    }
    if (in.bad() || (in.fail() && !in.eof())) {
        error = "reading stdin failed";
        return false;
    }
    out = util::TrimString(input);
    if (out.empty()) {
        error = "no transaction on stdin";
        return false;
    }
    return true;
}

namespace {

bool IsLoopback(const CNetAddr& addr)
{
    const auto bytes{addr.GetAddrBytes()};
    // GetAddrBytes() yields the 16-byte v1 form for IPv4 (::ffff:a.b.c.d); octet 12 is the first octet.
    if (addr.IsIPv4()) return bytes.size() == 16 && bytes[12] == 127;
    if (addr.IsIPv6()) {
        if (bytes.size() != 16 || bytes[15] != 1) return false;
        return std::all_of(bytes.begin(), bytes.end() - 1, [](unsigned char b) { return b == 0; });
    }
    return false;
}

} // namespace

std::optional<Proxy> ParseTor(const std::string& str, std::string& error)
{
    if (IsUnixSocketPath(str)) return Proxy{str, /*tor_stream_isolation=*/true};
    const CService service{LookupNumeric(str, TOR_SOCKS_PORT_DEFAULT)};
    if (!service.IsValid()) {
        error = strprintf("-tor=%s is not a numeric address with port or a unix socket path", str);
        return std::nullopt;
    }
    if (!IsLoopback(service)) {
        error = strprintf("-tor=%s is not a loopback address; a remote SOCKS listener would carry destinations and isolation credentials in plaintext", str);
        return std::nullopt;
    }
    return Proxy{service, /*tor_stream_isolation=*/true};
}

std::vector<CService> DecodeFixedSeeds(std::span<const uint8_t> data)
{
    std::vector<CService> out;
    SpanReader reader{data};
    ParamsStream s{reader, CAddress::V2_NETWORK};
    try {
        while (!reader.empty()) {
            CService endpoint;
            s >> endpoint;
            out.push_back(endpoint);
        }
    } catch (const std::ios_base::failure&) {
        // Release material is well formed; a truncated list yields what could be decoded.
    }
    return out;
}

std::optional<CTransactionRef> ParseAndCheckTransaction(const std::string& hex, CAmount max_burn, std::string& error)
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex)) {
        error = "transaction decode failed";
        return std::nullopt;
    }
    CTransactionRef tx{MakeTransactionRef(std::move(mtx))};
    TxValidationState state;
    if (!CheckTransaction(*tx, state)) {
        error = strprintf("transaction is invalid: %s", state.GetRejectReason());
        return std::nullopt;
    }
    if (tx->IsCoinBase()) {
        error = "transaction is a coinbase";
        return std::nullopt;
    }
    if (GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT) {
        error = "transaction weight exceeds the standard maximum";
        return std::nullopt;
    }
    for (const CTxOut& out : tx->vout) {
        if ((out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps()) && out.nValue > max_burn) {
            error = strprintf("output to an unspendable script of %s exceeds -maxburnamount", FormatMoney(out.nValue));
            return std::nullopt;
        }
    }
    return tx;
}

} // namespace privbcast
