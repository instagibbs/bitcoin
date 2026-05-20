#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a private-broadcast v2->v1 reconnect to a clearnet destination
preserves the proxy override and does NOT fall back to a direct connection.

Background
----------
`-privatebroadcast` selects (via PickNetwork) an addrman destination. For
clearnet IPv4/IPv6 destinations it forces the connection through the Tor
proxy by passing a proxy_override into OpenNetworkConnection so the
clearnet peer never learns the originator's IP.

The bug fixed in net.cpp 65c790e84: when the v2 BIP324 handshake to such a
destination failed and triggered a v1 reconnect, the v1 retry re-entered
OpenNetworkConnection WITHOUT proxy_override and so used GetProxy(IPV4)
(typically empty when only -onion is set) — connecting DIRECTLY to the
clearnet peer and leaking the user's IP.

Test design
-----------
* A mock SOCKS5 server plays the role of the Tor proxy.
* tx_originator runs with -privatebroadcast, -v2transport=1 and
  -onion=<socks5> (and no -proxy). Under that configuration the only proxy
  for clearnet destinations is the one supplied through proxy_override.
* tx_receiver (nodes[1]) is bound on an onion-tagged port; the SOCKS5 mock
  routes every .onion CONNECT to tx_receiver so the v2 handshake completes
  and m_outbound_tor_ok_at_least_once flips. After that flip PickNetwork
  starts choosing IPv4/IPv6 too.
* For each IPv4/IPv6 CONNECT the SOCKS5 mock forwards to a local "swallow"
  socket that reads >= CMessageHeader::HEADER_SIZE garbage bytes (enough to
  set V2Transport::m_sent_v1_header_worth) and then closes. With
  m_recv_buffer empty this makes ShouldReconnectV1() return true on the
  initiating bitcoind, which queues a v1 retry.
* Addrman is populated via the hidden test-only `addpeeraddress` RPC, with
  an explicit `services` argument so the planted entries advertise
  NODE_P2P_V2 (required for private-broadcast to initiate v2 in the first
  place).
* Two assertions; the first is portable and catches this bug on every
  platform, the second is a Linux-only supplementary check:
  1. POSITIVE (application-layer, all platforms) — the swallow classifies
     each arriving connection: v1 carrying bitcoind's hardcoded
     PRIVATE_BROADCAST subver "/pynode:0.0.1/" (see
     net_processing.cpp PushNodeVersion), v1 without it (should never
     happen with -maxconnections=0), or non-v1 (the initial v2
     attempt). At least one PRIVATE_BROADCAST v1 must reach the
     swallow, confirming the v1 retry traversed the proxy. This is
     sufficient on its own to detect the regression: under the bug,
     the v1 retry bypasses SOCKS5 entirely and zero v1 with the
     subver ever arrives.
  2. NEGATIVE (direct observation, Linux only) — a background thread
     polls /proc/<bitcoind pid>/net/tcp{,6} for any TCP socket whose
     remote address matches a planted clearnet target. Supplementary
     guard against a hybrid-leak failure mode where a retry happens
     to traverse the proxy AND also opens a direct socket (no such
     codepath exists today; this is defense in depth for future
     regressions). Soft-skipped on non-Linux — leak_records stays
     empty, the assertion is trivially true, and the positive signal
     alone carries the bug-detection.

  Under the fix: (1) sees v1 with the subver, (2) sees zero direct
  clearnet sockets. Under the bug: (1) sees zero v1 with the subver
  and the test fails on every platform; on Linux (2) additionally
  observes the SYN_SENT entries.
"""

import socket
import sys
import threading
import time

from test_framework.messages import NODE_P2P_V2
from test_framework.p2p import P2P_SERVICES
from test_framework.socks5 import (
    Socks5Configuration,
    Socks5Server,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    p2p_port,
    tor_port,
)
from test_framework.wallet import MiniWallet


PORT = 8333

# Clearnet IPv4 + IPv6 destinations to plant in addrman. They are unreachable
# directly; private-broadcast can only get to them via the SOCKS5 mock.
#
# IPv4: 100.0.0.0/8 (RFC 6598 shared address space) — routed but unreachable in
#       a regtest harness; SYN_SENT lives for tens of seconds before TCP gives
#       up, giving the /proc leak poller a wide window to observe a leak.
# IPv6: 2001:db8::/32 (RFC 3849 documentation range). NOT fc00::/7 — addrman's
#       MaybeFlipIPv6toCJDNS reclassifies that range as NET_CJDNS, which
#       PrivateBroadcast::PickNetwork would never select unless -cjdnsreachable
#       is set, making the IPv6 path silently dead.
IPV4_TARGETS = [(f"100.{i}.0.1", PORT) for i in range(20)]
IPV6_TARGETS = [(f"2001:db8::{i + 1:x}", PORT) for i in range(20)]

# TORv3 addresses for the success path that flips
# m_outbound_tor_ok_at_least_once. The SOCKS5 mock routes them all to nodes[1].
# The strings are arbitrary valid-base32 56-character sequences; bitcoind only
# uses the first 32 decoded bytes as the pubkey and recomputes the checksum.
ONION_TARGETS = [
    ("testonlyad777777777777777777777777777777777777777775b6qd.onion", PORT),
    ("testonlyah77777777777777777777777777777777777777777z7ayd.onion", PORT),
    ("testonlyal77777777777777777777777777777777777777777vp6qd.onion", PORT),
    ("testonlyap77777777777777777777777777777777777777777r5qad.onion", PORT),
    ("testonlyat77777777777777777777777777777777777777777udsid.onion", PORT),
    ("testonlyax77777777777777777777777777777777777777777yciid.onion", PORT),
]

# Regtest network magic — present at the start of every v1 P2P message.
REGTEST_MAGIC = b"\xfa\xbf\xb5\xda"

# First 16 bytes of every v1 VERSION message in regtest: magic + the 12-byte
# null-padded command "version". Anchoring on this full prefix rather than just
# the 4-byte magic makes false-positive misclassification of v2 ellswift garbage
# (which is uniformly random) effectively impossible: 2^-128 vs 2^-32.
V1_VERSION_HEADER = REGTEST_MAGIC + b"version\x00\x00\x00\x00\x00"

# Hardcoded subver bitcoind sends in the v1 version message on
# PRIVATE_BROADCAST connections (net_processing.cpp PushNodeVersion).
PRIVBCAST_SUBVER = b"/pynode:0.0.1/"


def _parse_proc_v4(hex_addr):
    """'0100007F:1F90' -> ('127.0.0.1', 8080)."""
    ip_hex, port_hex = hex_addr.split(":")
    ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
    return ip, int(port_hex, 16)


def _parse_proc_v6(hex_addr):
    """'<32 hex>:<4 hex>' -> ('ipv6str', port). /proc/net/tcp6 stores the
    address as four little-endian 32-bit words; convert each word to BE."""
    ip_hex, port_hex = hex_addr.split(":")
    raw_le = bytes.fromhex(ip_hex)
    be = b"".join(raw_le[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, be), int(port_hex, 16)


def _v4mapped_to_v4(ip_str):
    """Return the IPv4 form of an IPv4-mapped-IPv6 address, else None."""
    try:
        b = socket.inet_pton(socket.AF_INET6, ip_str)
    except OSError:
        return None
    if b[:10] == b"\x00" * 10 and b[10:12] == b"\xff\xff":
        return socket.inet_ntoa(b[12:])
    return None


class P2PPrivateBroadcastV2V1Proxy(BitcoinTestFramework):
    def set_test_params(self):
        self.disable_autoconnect = False
        self.num_nodes = 2

    def setup_nodes(self):
        socks5_conf = Socks5Configuration()
        socks5_conf.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        socks5_conf.unauth = True
        socks5_conf.auth = True
        self.socks5_server = Socks5Server(socks5_conf)
        self.socks5_server.start()

        # Swallow listener: read enough bytes to (a) set
        # V2Transport::m_sent_v1_header_worth on the initiator side and
        # (b) inspect the leading 4 bytes to classify the connection as v1
        # (regtest magic) or v2 (ellswift garbage). Then close to trigger
        # ShouldReconnectV1().
        self.swallow_running = True
        self.swallow_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.swallow_listener.bind(("127.0.0.1", 0))
        self.swallow_listener.listen(16)
        self.swallow_port = self.swallow_listener.getsockname()[1]

        self.swallow_lock = threading.Lock()
        self.swallow_v2 = 0
        self.swallow_v1_pynode = 0  # v1 with the PRIVATE_BROADCAST subver
        self.swallow_v1_other = 0   # any other v1 (should be 0 in this test)

        def swallow_handle(conn):
            try:
                conn.settimeout(5)
                buf = bytearray()
                # Read up to 256 bytes: covers the full v1 VERSION message
                # (header 24B + payload ~80B + subver var_str ~15B) and is more
                # than enough for v2 to have sent its ellswift bytes (≥24 trips
                # m_sent_v1_header_worth on the initiator).
                while len(buf) < 256:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buf.extend(data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if len(buf) < 16:
                return
            with self.swallow_lock:
                if bytes(buf[:16]) != V1_VERSION_HEADER:
                    # Not a regtest v1 VERSION header — must be v2 ellswift.
                    self.swallow_v2 += 1
                elif PRIVBCAST_SUBVER in buf:
                    self.swallow_v1_pynode += 1
                else:
                    self.swallow_v1_other += 1

        def swallow_accept_loop():
            while self.swallow_running:
                try:
                    conn, _ = self.swallow_listener.accept()
                except OSError:
                    return
                threading.Thread(
                    target=swallow_handle, args=(conn,), daemon=True
                ).start()

        threading.Thread(target=swallow_accept_loop, daemon=True).start()

        def destinations_factory(requested_to_addr, requested_to_port):
            if requested_to_addr.endswith(".onion"):
                return {
                    "actual_to_addr": "127.0.0.1",
                    "actual_to_port": tor_port(1),
                }
            return {
                "actual_to_addr": "127.0.0.1",
                "actual_to_port": self.swallow_port,
            }

        self.socks5_server.conf.destinations_factory = destinations_factory

        self.extra_args = [
            [
                "-test=addrman",
                "-privatebroadcast",
                "-v2transport=1",
                f"-onion={socks5_conf.addr[0]}:{socks5_conf.addr[1]}",
                # -maxconnections=0 disables ThreadOpenConnections' automatic
                # outbound. Private-broadcast has its own connection budget,
                # so it keeps working — this is the exact pairing init.cpp
                # documents. Without it, normal outbound would dial the
                # planted IPv4 addrman entries directly and pollute the
                # /proc leak check with non-private-broadcast traffic.
                "-maxconnections=0",
            ],
            [
                "-v2transport=1",
                f"-bind=127.0.0.1:{tor_port(1)}=onion",
            ],
        ]
        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()
        self._start_leak_poller()

    def teardown_network(self):
        self.swallow_running = False
        self.leak_running = False
        try:
            self.swallow_listener.close()
        except OSError:
            pass
        try:
            self.socks5_server.stop()
        except Exception:
            pass
        super().teardown_network()

    def _start_leak_poller(self):
        """Watch /proc/<bitcoind pid>/net/tcp{,6} for any socket to a planted
        clearnet target. Linux-only — soft-skips on other platforms."""
        self.leak_records = []
        self.leak_lock = threading.Lock()
        self.leak_running = True
        self.planted_v4 = set(IPV4_TARGETS)
        self.planted_v6 = set(IPV6_TARGETS)

        if sys.platform != "linux":
            # The /proc poller is supplementary; the primary bug-detection
            # is the application-layer positive signal (v1-with-subver at
            # the swallow), which runs on every platform.
            self.log.info(
                "Supplementary /proc clearnet leak check skipped on "
                f"{sys.platform}; positive signal (v1-with-subver) is "
                "sufficient to detect this regression."
            )
            return

        pid = self.nodes[0].process.pid

        def poll():
            seen = set()  # dedupe by inode
            while self.leak_running:
                try:
                    with open(f"/proc/{pid}/net/tcp") as f:
                        v4_lines = f.readlines()[1:]
                except OSError:
                    return
                try:
                    with open(f"/proc/{pid}/net/tcp6") as f:
                        v6_lines = f.readlines()[1:]
                except OSError:
                    v6_lines = []

                for line in v4_lines:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    inode = fields[9]
                    if inode in seen:
                        continue
                    try:
                        ip, port = _parse_proc_v4(fields[2])
                    except (ValueError, OSError):
                        continue
                    state = fields[3]
                    if (ip, port) in self.planted_v4:
                        seen.add(inode)
                        with self.leak_lock:
                            self.leak_records.append({
                                "ip": ip, "port": port,
                                "state": state, "source": "tcp"})

                for line in v6_lines:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    inode = fields[9]
                    if inode in seen:
                        continue
                    try:
                        ip, port = _parse_proc_v6(fields[2])
                    except (ValueError, OSError):
                        continue
                    state = fields[3]
                    if (ip, port) in self.planted_v6:
                        seen.add(inode)
                        with self.leak_lock:
                            self.leak_records.append({
                                "ip": ip, "port": port,
                                "state": state, "source": "tcp6"})
                        continue
                    mapped = _v4mapped_to_v4(ip)
                    if mapped and (mapped, port) in self.planted_v4:
                        seen.add(inode)
                        with self.leak_lock:
                            self.leak_records.append({
                                "ip": mapped, "port": port,
                                "state": state, "source": "tcp6-mapped"})

                # 50ms cadence: well below the ~75s SYN_SENT lifetime for the
                # planted IPs (RFC 6598 100.0.0.0/8 and RFC 3849 2001:db8::/32,
                # both routed-but-unanswered). If anyone changes the planted
                # IPs to ones that fail-fast (RST instead of SYN-timeout), the
                # window shrinks and this cadence will need to shrink with it.
                time.sleep(0.05)

        self.leak_thread = threading.Thread(target=poll, daemon=True)
        self.leak_thread.start()

    def _inject_addrs(self, node):
        services = P2P_SERVICES | NODE_P2P_V2
        for entries in (ONION_TARGETS, IPV4_TARGETS, IPV6_TARGETS):
            for ip, port in entries:
                node.addpeeraddress(
                    address=ip, port=port, tried=False, services=services
                )

    def _swallow_counts(self):
        with self.swallow_lock:
            return (
                self.swallow_v1_pynode,
                self.swallow_v1_other,
                self.swallow_v2,
            )

    def run_test(self):
        tx_originator = self.nodes[0]

        self._inject_addrs(tx_originator)

        ipv4_known = tx_originator.getnodeaddresses(count=0, network="ipv4")
        assert any(a["services"] & NODE_P2P_V2 for a in ipv4_known), (
            "no IPv4 addrman entry advertises NODE_P2P_V2"
        )

        wallet = MiniWallet(tx_originator)

        # Submit several transactions so the broadcast thread queues
        # plenty of attempts. Each tx queues NUM_PRIVATE_BROADCAST_PER_TX
        # connections; the first few will be NET_ONION (only candidate
        # before the Tor-ok flag flips), and subsequent picks include
        # NET_IPV4/NET_IPV6 (~1/3 each).
        for _ in range(4):
            tx = wallet.create_self_transfer()
            tx_originator.sendrawtransaction(
                hexstring=tx["hex"], maxfeerate=0.1
            )

        # Wait until at least one PRIVATE_BROADCAST v1 retry lands at
        # the destination with bitcoind's '/pynode:0.0.1/' subver. With
        # the fix this happens within a second or two; without the fix
        # it never does and we fall through to the explicit assertions.
        deadline = time.time() + 60 * self.options.timeout_factor

        def signature_seen():
            v1_pb, _v1_other, _v2 = self._swallow_counts()
            return v1_pb > 0

        try:
            self.wait_until(signature_seen, timeout=deadline - time.time())
        except AssertionError:
            pass  # Defer to the explicit assertion below for a clearer message.

        v1_pb, v1_other, v2 = self._swallow_counts()

        assert v2 > 0, (
            "No v2 attempts reached the destination via the SOCKS5 proxy; "
            "the proxy_override codepath was not exercised — test "
            "infrastructure issue."
        )
        assert v1_other == 0, (
            f"Destination saw {v1_other} v1 connection(s) without the "
            "PRIVATE_BROADCAST subver '/pynode:0.0.1/'. Unexpected — "
            "should not happen with -maxconnections=0."
        )

        # POSITIVE (all platforms): application-layer proof the v1 retry
        # traversed the proxy, identified by bitcoind's hardcoded
        # PRIVATE_BROADCAST subver '/pynode:0.0.1/'. This is the bug-
        # detection assertion — under the regression, v1 retries bypass
        # SOCKS5 entirely and zero of them ever reach the swallow.
        assert v1_pb > 0, (
            f"Destination saw {v2} v2 PRIVATE_BROADCAST attempts but "
            "zero v1 retries carrying bitcoind's PRIVATE_BROADCAST subver "
            "'/pynode:0.0.1/'. Every v1 retry should arrive via the proxy."
        )

        # NEGATIVE (Linux only): direct observation that bitcoind never
        # opened a socket to any planted clearnet target. Soft-skipped on
        # non-Linux (leak_records stays empty, assertion trivially holds).
        # Catches hybrid-leak modes the positive signal would miss.
        with self.leak_lock:
            leaks = list(self.leak_records)
        assert not leaks, (
            f"Observed {v2} v2 PRIVATE_BROADCAST attempts through the "
            f"SOCKS5 proxy AND {len(leaks)} direct clearnet socket(s) to "
            f"planted targets in /proc/<bitcoind>/net/tcp{{,6}}: {leaks}. "
            "Private-broadcast traffic must NEVER go clearnet — privacy leak."
        )

        platform_note = (
            "" if sys.platform == "linux"
            else f" (/proc check skipped on {sys.platform})"
        )
        self.log.info(
            f"OK: destination saw {v2} v2 + {v1_pb} v1 PRIVATE_BROADCAST "
            "attempts via the SOCKS5 proxy; /proc inspection saw zero "
            f"direct clearnet sockets to planted targets{platform_note}."
        )


if __name__ == "__main__":
    P2PPrivateBroadcastV2V1Proxy(__file__).main()
