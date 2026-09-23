// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key.h>
#include <logging.h>
#include <netbase.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <privbcast/discovery.h>
#include <privbcast/job.h>
#include <privbcast/input.h>
#include <privbcast/timing.h>
#include <protocol.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#ifndef WIN32
#include <poll.h>
#include <unistd.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

std::atomic<bool> g_interrupted{false};

void HandleSignal(int)
{
    g_interrupted.store(true);
}

void SetupArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);
    SetupChainParamsBaseOptions(argsman);
    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-tor=<ip:port|path>", "Tor SOCKS5 listener: a loopback address with port, or a unix socket path (default: 127.0.0.1:9050). Seeds are resolved and recipients reached only through it.", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-maxburnamount=<amt>", strprintf("Refuse a transaction with an output to an unspendable script above this amount (default: %s)", FormatMoney(0)), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-progress", "Print one-line progress events to stderr, best effort: on a pipe (not on Windows) a line that does not fit is dropped rather than waited for (default: 1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-seed=<name>", "Regtest only: DNS seed name to resolve instead of the release list; may be given more than once", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-timedivisor=<n>", "Regtest only: divide every plan duration by n so tests run quickly", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-fixedseed=<addr:port>", "Regtest only: bundled address to use instead of the release list; may be given more than once", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-debug=<category>", "Output debug information to stderr (default: 0). Use -debug=1 for all categories. "
                   "Useful ones: privatebroadcast (job, slots and attempts), net and proxy (SOCKS5 exchanges and Tor's reply codes).", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddCommand("send", "Read a final transaction in hex from stdin and announce it to a bounded set of peers through Tor");
    argsman.AddCommand("discover", "Run discovery only and print the frozen candidate set");
}

} // namespace

MAIN_FUNCTION
{
    ArgsManager args;
    SetupEnvironment();
    if (!SetupNetworking()) {
        tfm::format(std::cerr, "Error: initializing networking failed\n");
        return EXIT_FAILURE;
    }
    // The BIP324 (v2) handshake performs elliptic-curve key operations, which need the
    // secp256k1 context, as bitcoin-wallet's ECC_Context does.
    ECC_Context ecc_context{};
    SetupArgs(args);

    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\nRun 'bitcoin-privbcast -help' for usage.\n", error);
        return EXIT_FAILURE;
    }
    if (argc < 2 || HelpRequested(args) || args.GetBoolArg("-version", false)) {
        std::string usage{CLIENT_NAME " bitcoin-privbcast utility version " + FormatFullVersion() + "\n"};
        if (args.GetBoolArg("-version", false)) {
            usage += FormatParagraph(LicenseInfo());
        } else {
            usage += "\n"
                     "bitcoin-privbcast announces one final transaction to a bounded set of peers over Tor,\n"
                     "sharing nothing with a running node. Check the transaction first with\n"
                     "'bitcoin-cli testmempoolaccept' and watch for receipt with 'bitcoin-cli getmempoolentry'.\n"
                     "\n"
                     "Usage:  bitcoin-privbcast [options] send < tx.hex\n"
                     "or:     bitcoin-privbcast [options] discover\n"
                     "\n"
                     "send exits 0 if the announcement was written to at least one peer, 2 if it reached\n"
                     "none, and 1 on a usage or input error.\n";
            usage += "\n" + args.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", usage);
        return argc < 2 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
    const bool regtest{args.GetChainType() == ChainType::REGTEST};

    const auto cmd{args.GetCommand()};
    if (!cmd || (cmd->command != "send" && cmd->command != "discover") || !cmd->args.empty()) {
        tfm::format(std::cerr, "Error: expected exactly one command, 'send' or 'discover'. Run 'bitcoin-privbcast -help' for usage.\n");
        return EXIT_FAILURE;
    }

    std::string tor_str{args.GetArg("-tor", strprintf("127.0.0.1:%u", privbcast::TOR_SOCKS_PORT_DEFAULT))};
    if (tor_str.empty()) {
        tfm::format(std::cerr, "Error: -tor=<ip:port|path> must not be empty\n");
        return EXIT_FAILURE;
    }
    const auto tor{privbcast::ParseTor(tor_str, error)};
    if (!tor) {
        tfm::format(std::cerr, "Error: %s\n", error);
        return EXIT_FAILURE;
    }

    if (!regtest && (args.IsArgSet("-seed") || args.IsArgSet("-fixedseed") || args.IsArgSet("-timedivisor"))) {
        tfm::format(std::cerr, "Error: -seed, -fixedseed and -timedivisor are only accepted on regtest\n");
        return EXIT_FAILURE;
    }
    if (args.IsArgSet("-timedivisor")) {
        const int64_t divisor{args.GetIntArg("-timedivisor", 1)};
        if (divisor < 1 || divisor > 1000) {
            tfm::format(std::cerr, "Error: -timedivisor must be between 1 and 1000\n");
            return EXIT_FAILURE;
        }
        privbcast::SetTimeDivisor(static_cast<uint32_t>(divisor));
    }

    CAmount max_burn{0};
    if (args.IsArgSet("-maxburnamount")) {
        const auto parsed{ParseMoney(args.GetArg("-maxburnamount", ""))};
        if (!parsed) {
            tfm::format(std::cerr, "Error: invalid -maxburnamount\n");
            return EXIT_FAILURE;
        }
        max_burn = *parsed;
    }

    // Progress lines and any -debug output go through the logger to stderr; stdout carries the report.
    // The logger calls back under its lock from whichever thread logs, so a write that waited would
    // hold every thread that logs next: on a pipe a line that does not fit is dropped instead, since
    // POLLOUT there promises room for a write of up to PIPE_BUF bytes (one writer assumed). On a
    // terminal POLLOUT only promises some room, so a paused terminal can still hold the line that
    // met the pause; Windows writes blocking. Both are accepted: progress is best effort.
    const auto write_stderr = [](const std::string& line) {
#ifndef WIN32
        pollfd pfd{STDERR_FILENO, POLLOUT, 0};
        if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLOUT) || line.size() > PIPE_BUF) return;
#endif
        fwrite(line.data(), 1, line.size(), stderr);
    };
    // The library logs progress under the node's private broadcast category; the tool shows it by default.
    LogInstance().EnableCategory(BCLog::PRIVBROADCAST);
    for (const std::string& cat : args.GetArgs("-debug")) {
        if (cat == "0" || cat == "none") {
            LogInstance().DisableCategory(BCLog::ALL);
        } else if (cat.empty() || cat == "1") {
            LogInstance().EnableCategory(BCLog::ALL);
        } else if (!LogInstance().EnableCategory(cat)) {
            tfm::format(std::cerr, "Error: unsupported logging category -debug=%s\n", cat);
            return EXIT_FAILURE;
        }
    }
    if (args.GetBoolArg("-progress", true)) LogInstance().PushBackCallback(write_stderr);
    LogInstance().StartLogging();

    privbcast::DiscoveryPlan discovery;
    discovery.port = Params().GetDefaultPort();
    if (regtest && (args.IsArgSet("-seed") || args.IsArgSet("-fixedseed"))) {
        discovery.dns_seeds = args.GetArgs("-seed");
        for (const std::string& s : args.GetArgs("-fixedseed")) {
            const auto service{Lookup(s, discovery.port, /*fAllowLookup=*/false)};
            if (!service) {
                tfm::format(std::cerr, "Error: invalid -fixedseed=%s\n", s);
                return EXIT_FAILURE;
            }
            discovery.bundled.push_back(*service);
        }
    } else {
        discovery.dns_seeds = Params().DNSSeeds();
        discovery.bundled = privbcast::DecodeFixedSeeds(Params().FixedSeeds());
    }

    // The transaction is read before the signal handlers are installed: an interrupt while
    // waiting for input simply terminates the process, nothing has happened yet.
    CTransactionRef tx;
    if (cmd->command == "send") {
        std::string hex;
        if (!privbcast::ReadBounded(std::cin, privbcast::MAX_STDIN_BYTES, hex, error)) {
            tfm::format(std::cerr, "Error: %s\n", error);
            return EXIT_FAILURE;
        }
        const auto parsed{privbcast::ParseAndCheckTransaction(hex, max_burn, error)};
        if (!parsed) {
            tfm::format(std::cerr, "Error: %s\n", error);
            return EXIT_FAILURE;
        }
        tx = *parsed;
    }

#ifndef WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);
#ifdef WIN32
    std::signal(SIGBREAK, HandleSignal); // Ctrl-Break: the console event that can be sent to one process group
#endif
    const auto interrupted = [] { return g_interrupted.load(); };

    if (cmd->command == "discover") {
        FastRandomContext rng;
        const auto result{privbcast::Discover(*tor, discovery, privbcast::Clock::now(), rng, interrupted)};
        tfm::format(std::cout, "%s\n", privbcast::DiscoveryJson(result, /*addresses=*/true).write(2));
        return EXIT_SUCCESS;
    }

    privbcast::JobConfig cfg;
    cfg.tx = tx;
    cfg.tor = *tor;
    cfg.discovery = std::move(discovery);
    cfg.chain = Params().GetChainTypeString();
    cfg.interrupted = interrupted;
    const privbcast::JobReport report{privbcast::RunJob(cfg)};
    tfm::format(std::cout, "%s\n", report.json.write(2));
    return report.exit_code;
}
