// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_NET_TRANSPORT_H
#define BITCOIN_NET_TRANSPORT_H

#include <bip324.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <key.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/time.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

typedef int64_t NodeId;

#endif // BITCOIN_NET_TRANSPORT_H
