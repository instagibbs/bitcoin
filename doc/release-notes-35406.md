P2P and network changes
-----------------------

- The private-broadcast queue (transactions submitted via `sendrawtransaction`
when `-privatebroadcast` is enabled) is bounded. When full, new submissions are
rejected. It is up to the caller to inspect the jobs via
`getprivatebroadcastinfo` and free up space when stuck via
`abortprivatebroadcast`. (#35406)
