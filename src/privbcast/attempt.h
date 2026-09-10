// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_PRIVBCAST_ATTEMPT_H
#define BITCOIN_PRIVBCAST_ATTEMPT_H

#include <net_transport.h>
#include <netbase.h>
#include <primitives/transaction.h>
#include <privbcast/discovery.h>
#include <privbcast/session.h>
#include <random.h>
#include <util/sock.h>
#include <util/time.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace privbcast {

/** Everything recorded about one physical connection attempt. */
struct AttemptResult {
    Candidate candidate;
    Outcome outcome{Outcome::PENDING};
    std::string reason;
    Session::Evidence evidence;
    size_t bytes_sent{0};
    size_t bytes_recv{0};
    SteadyClock::time_point scheduled_start;
    SteadyClock::time_point started;
    std::optional<SteadyClock::time_point> connected; //!< SOCKS connection to the peer established
    SteadyClock::time_point ended;
};

/**
 * Opens the connection to the candidate. Returns the connected socket or nullptr; sets
 * `proxy_failed` when the proxy itself was unreachable. Injectable so tests can supply a mock.
 */
using Connector = std::function<std::unique_ptr<Sock>(bool& proxy_failed)>;

/**
 * The production connector: through the Tor proxy with fresh isolation credentials, auth
 * required, the whole SOCKS exchange bounded by `socks_deadline` (the TCP connect to the
 * proxy is bounded separately by the connect timeout).
 */
Connector TorConnector(const Proxy& tor, const Candidate& candidate, SteadyClock::time_point socks_deadline);

/**
 * Drive an already connected socket: pump bytes through the transport, feed complete
 * messages to the session, send what the session emits, report transport handover and
 * completion back to the session. Returns when the session has finished, the hard deadline
 * has passed, or the job is interrupted. Exposed for tests with mock sockets.
 */
void RunSession(Sock& sock, Transport& transport, Session& session, AttemptResult& result,
                SteadyClock::time_point hard_deadline, const std::function<bool()>& interrupted);

/**
 * One connection attempt at a scheduled opportunity. Everything is prepared first; then, as the
 * last step before the connector is invoked, the attempt is abandoned if the job is cancelled or
 * `dial_deadline` (the opportunity's start grace) has passed, and nullopt is returned: nothing was
 * dialled. The pre-announcement budget counts from `scheduled_start`, not from when the connection
 * opened, so a slow proxy cannot push a failure past the slot's next scheduled opportunity; an
 * announced attempt may live on to `hard_deadline` while that slot's backups are suppressed.
 * The transport is always BIP324 (v2); there is no v1 fallback.
 */
std::optional<AttemptResult> RunAttempt(const Connector& connect, const Candidate& candidate, const CTransactionRef& tx,
                                        SteadyClock::time_point scheduled_start, SteadyClock::time_point dial_deadline,
                                        SteadyClock::time_point hard_deadline, const std::function<bool()>& interrupted);

} // namespace privbcast

#endif // BITCOIN_PRIVBCAST_ATTEMPT_H
