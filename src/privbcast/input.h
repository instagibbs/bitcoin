// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_INPUT_H
#define BITCOIN_PRIVBCAST_INPUT_H

#include <consensus/amount.h>
#include <netbase.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <cstdint>
#include <istream>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace privbcast {

/** Largest input accepted on stdin: two maximum-size transactions in hex plus whitespace. */
inline constexpr size_t MAX_STDIN_BYTES{2 * 4'000'000 + 4096};
/** Port assumed when -tor gives a bare loopback address. */
inline constexpr uint16_t TOR_SOCKS_PORT_DEFAULT{9050};

/**
 * Read at most `max_bytes` from the stream, failing (rather than buffering more) if the
 * producer offers more than that. Trims surrounding whitespace.
 */
bool ReadBounded(std::istream& in, size_t max_bytes, std::string& out, std::string& error);

/**
 * Parse -tor: a unix socket path, or a numeric loopback address (127.0.0.0/8 or ::1) with an
 * optional port. Anything else is refused: a remote SOCKS listener would carry destinations
 * and isolation credentials in plaintext before Tor.
 */
std::optional<Proxy> ParseTor(const std::string& str, std::string& error);

/** Decode the release fixed-seed list (BIP155-serialized endpoints). */
std::vector<CService> DecodeFixedSeeds(std::span<const uint8_t> data);

/**
 * Stateless checks on the final transaction: consensus sanity, not a coinbase, standard
 * weight, and no output to an unspendable script above `max_burn`. Acceptance is the
 * caller's preflight, not this tool's.
 */
std::optional<CTransactionRef> ParseAndCheckTransaction(const std::string& hex, CAmount max_burn, std::string& error);

/** What one job broadcasts: the announced transaction and, for a package, its unconfirmed parent. */
struct Package {
    CTransactionRef tx;
    CTransactionRef parent; //!< null unless two transactions were given
};

/**
 * One transaction, or a parent and its child in either order, separated by whitespace. Each gets
 * the checks of ParseAndCheckTransaction; two must be exactly one spending an output of the other.
 * Whether the child has other unconfirmed parents, or the parent needs the child at all, is the
 * caller's package preflight, not this tool's.
 */
std::optional<Package> ParseAndCheckPackage(const std::string& text, CAmount max_burn, std::string& error);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_INPUT_H
