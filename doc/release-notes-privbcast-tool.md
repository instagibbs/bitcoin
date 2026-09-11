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

Updated RPCs
------------

- `testmempoolaccept` leaves the node's validation caches and its coins cache
  exactly as it found them: the coins fetched for the check are uncached again,
  no signature or script cache entries are stored, and entries already present
  are not marked for eviction. A transaction that was only test-accepted is
  therefore no faster to validate when it is later submitted or received.
  Package test-accepts already behaved this way for the coins cache. Reading the
  inputs still warms the database's own caches and the operating system's page
  cache, as any UTXO lookup does. (TODO: PR number)
