P2P and network changes
-----------------------

- Transactions are now only processed if they were requested from the peer that sent them, i.e.
  sent in response to a `getdata` following an `inv` announcement. Unrequested transactions are
  ignored without disconnecting the peer. Peers with the `relay` or `forcerelay` permission (see
  `-whitelist` and `-whitebind`) are exempt. Software that broadcasts by sending `tx` messages
  without a prior `inv` needs to announce transactions first, or connect to a node that grants it
  the `relay` permission.
