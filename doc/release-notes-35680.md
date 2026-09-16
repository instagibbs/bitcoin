P2P and network changes
-----------------------

- Each transaction sent via private broadcast (`-privatebroadcast`) is one
  bounded job with a fixed number of connection attempts. After it ends,
  broadcasting stops; call `sendrawtransaction` again to run another job. Finished
  jobs remain available through `getprivatebroadcastinfo`. (#35680)
