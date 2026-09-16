Tools and Utilities
-------------------

- A new `bitcoin-privbcast` utility announces one final transaction to a small,
  fixed number of peers over Tor without involving a running node. It resolves
  the release DNS seeds through the Tor proxy, connects to a bounded set of
  exit-path and onion peers on a schedule fixed when the job starts, serves the
  transaction once per peer, and prints a JSON report. Given a child and its
  unconfirmed parent it announces the child and serves the parent to a peer that
  asks for it, for one-parent-one-child package relay. It shares no address
  manager, ban list, connection table or caches with `bitcoind`, so nothing a
  recipient observes can be tied to the node. Check the transaction with
  `testmempoolaccept` first and watch for receipt with `getmempoolentry`; see
  `doc/design/private-broadcast-tool.md`. The tool is built when the
  `BUILD_PRIVBCAST` CMake option is enabled, which follows `BUILD_TESTS` by
  default. (TODO: PR number)

P2P and network changes
-----------------------

- `-privatebroadcast` now runs the same bounded, fixed-schedule jobs as
  `bitcoin-privbcast`, inside the node: each transaction submitted with
  `sendrawtransaction` becomes one job that announces it to a few peers found
  through the release DNS seeds (resolved through Tor) and the fixed onion
  seeds, over the node's Tor SOCKS5 proxy, and then stops. The node no longer
  opens `private-broadcast` connections through its connection manager, does
  not pick recipients from its address manager, does not reattempt until the
  transaction is seen back, and no longer uses I2P for private broadcast; a
  Tor SOCKS5 proxy on the local host is required. `-connect` is no longer
  incompatible with `-privatebroadcast`. Jobs run at most two at a time, with a
  bounded queue. (TODO: PR number)

Updated RPCs
------------

- `getprivatebroadcastinfo` now lists private broadcast jobs (`jobs`), each
  with an `id`, `state` (queued, running, done, aborted), timestamps, whether
  the node's own mempool has since seen the transaction, and the finished
  job's full report. `abortprivatebroadcast` takes a job `id` instead of a
  transaction hash. (TODO: PR number)

- `testmempoolaccept` leaves the node's validation caches and its coins cache
  exactly as it found them: the coins fetched for the check are uncached again,
  no signature or script cache entries are stored, and entries already present
  are not marked for eviction. A transaction that was only test-accepted is
  therefore no faster to validate when it is later submitted or received.
  Package test-accepts already behaved this way for the coins cache. Reading the
  inputs still warms the database's own caches and the operating system's page
  cache, as any UTXO lookup does. (TODO: PR number)
