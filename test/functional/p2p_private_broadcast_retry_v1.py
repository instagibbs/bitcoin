#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Ensure that when a v2 private broadcast connection to a clearnet (IPv4 or IPv6)
address fails, the v1 retry is also made through the Tor proxy.

The test does:
* Add a bunch of IPv4 and IPv6 addresses to the node's addrman (they will be
  added without the P2P_V2 flag).
* Get them to report P2P_V2 in their service flags and connect to each one, so
  that the flags in addrman are updated to contain P2P_V2.
* Get one successful connection to a Tor peer (.onion) so that bitcoind assumes
  the configured Tor proxy works and is indeed a proxy to the Tor network. This
  will make it open private broadcast connections also to IPv4/IPv6 addresses
  via that proxy.
* Start some private broadcast connections.
* Fail the v2 transport of every clearnet connection made via the Tor proxy
  (the listener disconnects right after the transport version is determined).
* For each clearnet network, expect, via the Tor proxy, both an initial v2
  connection and a subsequent v1 connection, i.e. the v2->v1 downgrade retry.
"""

import threading

from test_framework.netutil import (
    format_addr_port
)
from test_framework.p2p import (
    P2PConnection,
    P2PInterface,
    P2P_SERVICES,
    start_p2p_listener,
)
from test_framework.messages import (
    CAddress,
    NODE_P2P_V2,
)
from test_framework.socks5 import (
    start_socks5_server,
)
from test_framework.test_framework import (
    BitcoinTestFramework,
)
from test_framework.wallet import (
    MiniWallet,
)

# Clearnet networks that private broadcast can reach via the Tor proxy and which
# we exercise the v2->v1 downgrade retry for.
CLEARNET_NETWORKS = ["ipv4", "ipv6"]


def network_of(addr):
    """Classify a destination address (as a SOCKS5 DOMAINNAME string) by network."""
    if addr.endswith(".onion"):
        return "onion"
    if ":" in addr:
        return "ipv6"
    return "ipv4"


class P2PDetermineV2or1AndClose(P2PConnection):
    def __init__(self, on_v2or1_determined):
        super().__init__()
        self.on_v2or1_determined = on_v2or1_determined

    # https://docs.python.org/3/library/asyncio-protocol.html#asyncio.Protocol.data_received
    def data_received(self, data):
        self.recvbuf += data
        if len(self.recvbuf) >= 4:
            self.on_v2or1_determined(1 if self.recvbuf[0:4] == self.magic_bytes else 2)
            self.peer_disconnect()

    def on_open(self):
        pass

    def on_close(self):
        pass

class P2PPrivateBroadcastRetryV1(BitcoinTestFramework):
    def set_test_params(self):
        self.disable_autoconnect = False
        self.num_nodes = 1

    def setup_nodes(self):
        # Synchronizes access to the bookkeeping populated from the SOCKS5 server
        # threads (one thread per redirected connection).
        self.state_lock = threading.Lock()
        # Per clearnet network: the transport versions (1 or 2) seen on connections via the Tor proxy.
        self.clearnet_via_tor_versions = {net: [] for net in CLEARNET_NETWORKS}

        def destinations_factory_all_proxy(requested_to_addr, requested_to_port):
            """
            Redirect all connections to newly created P2PInterface listeners. These speak only
            the v1 transport, but advertise the NODE_P2P_V2 service flag in their version message.
            Connecting to them (over v1) is therefore enough to make the node record the addrman
            entries as v2-capable, without these listeners having to implement the v2 transport.
            """
            listener = P2PInterface()
            listener.peer_connect_helper(dstaddr="0.0.0.0", dstport=0, net=self.chain, timeout_factor=self.options.timeout_factor)
            listener.peer_connect_send_version(services=P2P_SERVICES | NODE_P2P_V2)

            actual_to_addr, actual_to_port = start_p2p_listener(self.network_thread, listener)

            self.log.debug("Instructing the common proxy to redirect connection for "
                           f"{format_addr_port(requested_to_addr, requested_to_port)} to "
                           f"{format_addr_port(actual_to_addr, actual_to_port)} (Python {type(listener).__name__})")

            return {
                "actual_to_addr": actual_to_addr,
                "actual_to_port": actual_to_port,
            }

        self.all_proxy = start_socks5_server(destinations_factory_all_proxy)

        def append_version(net, v2or1):
            with self.state_lock:
                self.clearnet_via_tor_versions[net].append(v2or1)

        def destinations_factory_tor_proxy(requested_to_addr, requested_to_port):
            """
            Redirect every clearnet (IPv4/IPv6) connection to a P2PDetermineV2or1AndClose
            listener, which records the transport version and immediately disconnects. Because
            such a connection never completes a private broadcast, the node keeps opening new
            connections (picking a random reachable network each time) until we have observed
            the v2->v1 downgrade retry for every clearnet network, rather than stopping after a
            few successful broadcasts. Onion connections are served by a normal P2PInterface so
            that the manual connection used to mark the Tor proxy as working can complete.
            """
            requested_to = format_addr_port(requested_to_addr, requested_to_port)
            net = network_of(requested_to_addr)

            if net in CLEARNET_NETWORKS:
                # This is either an initial (v2) or a downgrade-retry (v1) connection.
                listener = P2PDetermineV2or1AndClose(lambda v2or1, net=net: append_version(net, v2or1))
                listener.peer_connect_helper(dstaddr="0.0.0.0", dstport=0, net=self.chain, timeout_factor=self.options.timeout_factor)
            else:
                listener = P2PInterface()
                listener.peer_connect_helper(dstaddr="0.0.0.0", dstport=0, net=self.chain, timeout_factor=self.options.timeout_factor)
                listener.peer_connect_send_version(services=P2P_SERVICES | NODE_P2P_V2)

            actual_to_addr, actual_to_port = start_p2p_listener(self.network_thread, listener)

            self.log.debug(f"Instructing the Tor proxy to redirect connection for {requested_to} to "
                           f"{format_addr_port(actual_to_addr, actual_to_port)} (Python {type(listener).__name__})")

            return {
                "actual_to_addr": actual_to_addr,
                "actual_to_port": actual_to_port,
            }

        self.tor_proxy = start_socks5_server(destinations_factory_tor_proxy)

        self.extra_args = [
            [
                "-privatebroadcast=1",
                f"-proxy={self.all_proxy.conf.addr[0]}:{self.all_proxy.conf.addr[1]}",
                f"-onion={self.tor_proxy.conf.addr[0]}:{self.tor_proxy.conf.addr[1]}",
                "-test=addrman",
                "-v2transport=0",
            ],
        ]

        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0 = self.nodes[0]

        self.log.info("Filling node0's addrman with IPv4 and IPv6 addresses")
        self.fill_node_addrman(node_index=0, address_types_to_add=[CAddress.NET_IPV4, CAddress.NET_IPV6])

        # Connect over the v1 transport (v2transport=False): the peers behind the default proxy
        # only speak v1, but their version message advertises the NODE_P2P_V2 service flag. It is
        # that advertised flag (independent of the transport actually used here) that addrman
        # records, and that later makes private broadcast attempt v2 to these peers and then
        # downgrade to v1 - the behaviour under test.
        self.log.info("Opening manual connections to all clearnet addresses to add the P2P_V2 flag to addrman entries")
        for net in CLEARNET_NETWORKS:
            for a in node0.getnodeaddresses(count=0, network=net):
                node0.addnode(node=format_addr_port(a["address"], a["port"]), command="onetry", v2transport=False)

        self.log.info("Waiting for all clearnet addresses to get P2P_V2 as a result of peers advertising support")
        self.wait_until(lambda: all(
            a["services"] & NODE_P2P_V2 != 0
            for net in CLEARNET_NETWORKS
            for a in node0.getnodeaddresses(count=0, network=net)))

        # The destinations behind the -proxy= don't actually support v2. When bitcoind runs with -v2transport=1
        # and tries v2 on them they would print benign "magic byte mismatch" warnings.
        # Disable those since none of them are needed anymore.
        self.all_proxy.conf.destinations_factory = None

        self.restart_node(0, extra_args=self.extra_args[0] + ["-v2transport=1"])

        self.log.info("Opening a connection to a Tor address, so bitcoind considers -onion= a real Tor proxy")
        node0.addnode(node="testonlyad777777777777777777777777777777777777777775b6qd.onion:1234", command="onetry", v2transport=False)

        self.log.info("Waiting for at least one Tor connection")
        self.wait_until(lambda: any(p["network"] == "onion" for p in node0.getpeerinfo()))

        self.log.info("Starting private broadcast connections")
        wallet = MiniWallet(node0)
        tx = wallet.create_self_transfer()
        node0.sendrawtransaction(hexstring=tx["hex"])

        def versions_seen(net):
            with self.state_lock:
                return list(self.clearnet_via_tor_versions[net])

        # For each clearnet network, expect (via the Tor proxy) both an initial v2 connection and
        # the subsequent v1 downgrade retry.
        for net in CLEARNET_NETWORKS:
            self.log.info(f"Tor proxy: waiting for a v2 {net} connection")
            self.wait_until(lambda net=net: 2 in versions_seen(net))
            self.log.info(f"Tor proxy: got v2 {net}, waiting for the v1 {net} retry")
            self.wait_until(lambda net=net: 1 in versions_seen(net))
            self.log.info(f"Tor proxy: got v2 and v1 for {net}")

        self.stop_node(0)
        self.all_proxy.stop()
        self.tor_proxy.stop()


if __name__ == "__main__":
    P2PPrivateBroadcastRetryV1(__file__).main()
