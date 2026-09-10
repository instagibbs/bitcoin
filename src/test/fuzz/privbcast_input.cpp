// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <netaddress.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <privbcast/input.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <cassert>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

using namespace privbcast;

namespace {

void initialize_privbcast_input()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

} // namespace

FUZZ_TARGET(privbcast_input, .init = initialize_privbcast_input)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    std::string error;

    // -tor parsing: only loopback numeric addresses and unix socket paths get through.
    {
        std::string str;
        switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
        case 0: str = fdp.ConsumeRandomLengthString(64); break;
        case 1: str = ConsumeService(fdp).ToStringAddrPort(); break;
        case 2: str = ConsumeNetAddr(fdp).ToStringAddr(); break;
        default: str = "unix:" + fdp.ConsumeRandomLengthString(40); break;
        }
        const auto tor{ParseTor(str, error)};
        if (tor) {
            assert(tor->m_tor_stream_isolation);
            if (!tor->m_is_unix_socket) {
                assert(tor->proxy.IsValid());
                const auto bytes{tor->proxy.GetAddrBytes()};
                assert(bytes.size() == 16);
                if (tor->proxy.IsIPv4()) {
                    assert(bytes[12] == 127);
                } else {
                    assert(tor->proxy.IsIPv6() && bytes[15] == 1);
                    for (size_t i = 0; i < 15; ++i) assert(bytes[i] == 0);
                }
            }
        } else {
            assert(!error.empty());
        }
    }

    // Bounded stdin reading.
    {
        // Caps and inputs on both sides of the 64 KiB read chunk, so the incremental bound is exercised.
        const size_t cap{fdp.ConsumeBool() ? fdp.ConsumeIntegralInRange<size_t>(0, 4096) : fdp.ConsumeIntegralInRange<size_t>(60000, 140000)};
        std::string input{fdp.ConsumeRandomLengthString(6000)};
        if (fdp.ConsumeBool()) input.append(fdp.ConsumeIntegralInRange<size_t>(0, 150000), 'x');
        std::istringstream in{input};
        std::string out;
        const bool ok{ReadBounded(in, cap, out, error)};
        if (ok) {
            assert(!out.empty() && out.size() <= cap && out.size() <= input.size());
            assert(!std::isspace(static_cast<unsigned char>(out.front())) && !std::isspace(static_cast<unsigned char>(out.back())));
        } else {
            assert(error == "stdin too large" || error == "no transaction on stdin");
            if (input.size() > cap) assert(error == "stdin too large");
        }
    }

    // Fixed-seed decoding never throws and returns only what decoded.
    {
        const auto bytes{ConsumeRandomLengthByteVector(fdp, 256)};
        (void)DecodeFixedSeeds(bytes);
    }

    // Transaction checks: whatever passes must satisfy every stated rule.
    {
        std::string hex;
        switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
        case 0:
            hex = fdp.ConsumeRandomLengthString(512);
            break;
        case 1: {
            // A coinbase: a single null prevout. Must be rejected as such.
            CMutableTransaction cb;
            cb.vin.emplace_back(COutPoint{}, CScript{} << OP_0 << OP_0);
            cb.vout.emplace_back(50 * COIN, CScript{} << OP_TRUE);
            DataStream ds; ds << TX_WITH_WITNESS(CTransaction{cb}); hex = HexStr(ds);
            break;
        }
        case 2: {
            // An over-weight transaction: one output with a script past the standard weight cap.
            CMutableTransaction big;
            big.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{1}), 0});
            const std::vector<unsigned char> nops(MAX_STANDARD_TX_WEIGHT, OP_NOP);
            big.vout.emplace_back(1000, CScript(nops.begin(), nops.end()));
            DataStream ds; ds << TX_WITH_WITNESS(CTransaction{big}); hex = HexStr(ds);
            break;
        }
        default:
            if (const auto mtx{ConsumeDeserializable<CMutableTransaction>(fdp, TX_WITH_WITNESS)}) {
                DataStream ds;
                ds << TX_WITH_WITNESS(CTransaction{*mtx});
                hex = HexStr(ds);
            }
            break;
        }
        const CAmount max_burn{fdp.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY)};
        const auto tx{ParseAndCheckTransaction(hex, max_burn, error)};
        if (tx) {
            TxValidationState state;
            assert(CheckTransaction(**tx, state));
            assert(!(*tx)->IsCoinBase());
            assert(GetTransactionWeight(**tx) <= MAX_STANDARD_TX_WEIGHT);
            for (const CTxOut& out : (*tx)->vout) {
                if (out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps()) assert(out.nValue <= max_burn);
            }
        } else {
            assert(!error.empty());
        }
    }
}
