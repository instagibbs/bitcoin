Updated settings
----------------

- The experimental `-privatebroadcast` option has been removed. Starting with
  `-privatebroadcast=1` is now an error. `sendrawtransaction` always adds the
  transaction to the local mempool and relays it to all peers.

Updated RPCs
------------

- The `getprivatebroadcastinfo` and `abortprivatebroadcast` RPCs have been
  removed, and `getpeerinfo` no longer reports the `private-broadcast`
  connection type. The `RPC_LIMIT_EXCEEDED` (-37) error code is no longer used.

Logging
-------

- The `privatebroadcast` logging category has been removed. Configurations
  like `-debug=privatebroadcast` will log a deprecation warning and be ignored.
