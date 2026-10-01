// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_PRIVBCAST_H
#define BITCOIN_TEST_UTIL_PRIVBCAST_H

#include <key.h>
#include <net_transport.h>
#include <privbcast/attempt.h>
#include <random.h>
#include <uint256.h>

/** A key source that draws each attempt's BIP324 key, entropy and garbage from rng, which must
 *  outlive it, so that the attempt's bytes are a function of rng. */
inline privbcast::KeySource KeysFrom(FastRandomContext& rng)
{
    return [&rng] {
        privbcast::TransportKeys keys;
        do {
            const uint256 secret{rng.rand256()};
            keys.key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
        } while (!keys.key.IsValid());
        keys.ellswift_entropy = rng.rand256();
        keys.garbage = rng.randbytes(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1));
        return keys;
    };
}

#endif // BITCOIN_TEST_UTIL_PRIVBCAST_H
