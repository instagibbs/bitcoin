# bitcoin-privbcast: design notes

`bitcoin-privbcast` announces one final transaction to a small, bounded set of peers over
Tor. It is a separate program from `bitcoind`, and that separation is the design: the tool
shares nothing with a running node, so nothing a recipient learns from the tool can be
tied to the node's public identity, and nothing the network does can steer the tool.

## The principle

Two rules, both enforced by construction rather than by careful coding:

1. **The tool creates no state a node can be read through.** It has no address manager,
   no ban or discouragement list, no connection table shared with ordinary peers, no
   upload accounting and no validation caches. A recipient that misbehaves ends only its
   own connection. When the tool exits, nothing it did persists anywhere but in its own
   report. The companion change to `testmempoolaccept` keeps the recommended preflight
   from leaving a trace in the node's validation caches and coins cache; reading the
   inputs still warms the database and page caches, like any UTXO lookup does.

2. **The schedule is drawn when the job starts, and nothing observed on a connection moves
   it.** At job start the tool draws every connection opportunity's time and hard lifetime
   limit. After discovery it assigns every candidate before contacting any recipient. Nothing
   received from a recipient reschedules or reassigns an opportunity. A failure before we
   announced enables only the same slot's next pre-assigned opportunity, at its scheduled
   time; an announcement suppresses that slot's remaining opportunities. Protocol responses
   follow fixed rules on the current connection. Late opportunities are skipped rather than
   shifted, and cancellation stops the whole job. The tool never reacts to a transaction being
   seen back on the network, because it has no way to see the network at all.

A consequence worth stating plainly: users of one release all look the same to a
recipient. Being recognised as "the tool" is accepted. What is protected is the link
between a job and a particular node, and between one connection and the outcome of
another.

## What a recipient sees

One connection, one fixed profile. The tool sends a VERSION with constant fields, answers
VERACK, announces the transaction by txid, serves it exactly once when asked for it in the
form its advertised services make possible, sends one PING, and closes on the matching
PONG. Every other message is read and ignored; the tool never answers it. A peer that
declines the transaction, never asks, or never answers the PING sees nothing different from
a peer that does everything promptly, except that the connection ends at a fixed deadline
instead of earlier.

## The schedule, in plain words

- **Discovery, 18 s.** The tool asks Tor to resolve the release DNS seeds, several times
  each on separate Tor streams, and adds onion peers from the release fixed-seed list. Queries
  are cut off at 15 s; the candidate set is frozen once every query has answered or been cut
  off, and delivery starts at 18 s regardless. Slow or missing answers do not delay anything.
- **Delivery from 18 s: six slots.** A slot is one delivery target with a first peer and three
  pre-chosen backups. Three prompt slots open together at 18 s, two to peers reached through
  Tor exits and one to an onion peer, racing three paths for the first announcement. The
  other three open at times drawn at job start: one onion slot somewhere between 35 s and
  180 s after that, and two exit-path slots between 185 s and 240 s, at least 5 s apart. A
  slot's class is a preference: an onion slot whose onion list has run out falls back to
  exit-path peers, so with few onions known every connection can be exit-path; exit-path slots
  never take onions.
  Each connection has a fixed budget to connect, complete the encrypted-transport handshake
  and announce. If it fails before announcing, the slot tries its next pre-chosen peer 50 to
  60 s (drawn at job start) after the previous scheduled time, at most three times. Once a slot has
  announced it is done, whatever happens next. There is no retry triggered by an unanswered
  PING, and no slot ever waits for another. The one shared resource is progress output, which
  is best effort (see End): a stderr write that blocks is held under the logger's lock and
  delays whichever slot logs next, and with it cancellation and the report.
- **End.** Every slot's network work ends within 310 s of its first scheduled time, so all of
  it is over by 568 s at the latest and usually much earlier; writing the report follows. These
  are scheduled bounds: host scheduling can delay a step, never reschedule one. Exit status 0 means at least one announcement was fully written; 2 means none
  was; 1 means bad input or arguments. Progress lines go to stderr through the ordinary Core
  logger, each with a UTC timestamp. They are best effort: on a pipe, a line that does not fit
  is dropped rather than waited for, so a reader that stops draining never holds a slot; a
  terminal that has been paused can hold the line that met the pause, and with it the slot that
  logged it, until output resumes (on Windows every line is written blocking). Redirect stderr
  to a file if that matters. The JSON report has no wall-clock value and is the record. Both
  are local evidence that a broadcast happened and should be treated as such.

All durations are compile-time constants (`src/privbcast/*.h`). There are no knobs: a
tunable would make its users distinguishable.

The schedule makes no claim about hiding the user's address: that comes entirely from the
tool being nodeless and reaching everything through Tor. What the schedule buys is delivery
that survives failed connections, a peer that can move nothing, and only marginal, unpromised
privacy on top: the later slots open at random offsets within fixed windows, in a fixed order
and at least five seconds apart, and there is no regular grid to recognise. The prompt trio is deliberately simultaneous, and
backups can still cluster; bursts are not eliminated.

## One parent, one child

A transaction whose fee is too low to enter mempools on its own can be carried by a child
that spends it, when the recipient evaluates the two together (Bitcoin Core 28 and later do
this for exactly one parent and one child). Give the tool both transactions, in either order,
and it works out which is which.

- Only the child is announced. Announcing the parent would invite a request for it before
  the child; a low-fee parent received alone is rejected, and the tool would then have to
  serve it a second time, which it never does.
- The child is served once, on request. The tool then holds for a fixed 30 s for the peer to
  ask for the parent, which a recipient that lacks it does within a few seconds (after its
  orphan-resolution delay and a Tor round trip). That request may batch the parent with the
  child's other inputs, so the tool serves the parent and, like any node, answers the entries
  it does not have with `notfound`; it never says that about its own two transactions. The parent is
  served once, only if asked for after the child, and only if it is the parent given; then
  PING as usual. If no request for the parent arrives within the hold, PING goes out anyway;
  the tool cannot tell whether the peer already had the parent, was still waiting on a request
  to another peer, or will not take the package.
- One request window still bounds the whole exchange; the second request restarts nothing,
  and the announcement point and the replacement rules are unchanged.
- The tool cannot check that the child has no other unconfirmed parent, or that the child pays
  enough for both, and there is no dry run for a package: `testmempoolaccept` checks each
  transaction on its own and does not apply the child's fee to the parent, so it reports a
  low-fee parent as "min relay fee not met" even when the package would be accepted, and
  stops there without evaluating the child at all, so that rejection says nothing about the
  child's validity. Work out the package feerate yourself. Nor can the tool see whether the
  recipient accepted the package; a PONG means only that the recipient processed what we sent. A recipient older than
  Core 28 asks for the parent, rejects it alone and keeps the child as an orphan only until we disconnect.
- Serving a second transaction on request is something the node's own private broadcast never
  does, so a recipient that asks for the parent knows it is talking to this tool. That the two
  transactions belong together is already visible on the chain.

## What the tool deliberately does not do

- Retry a slot after it has announced, however the peer behaved.
- Keep any state between jobs, or learn from earlier jobs.
- Talk to a node, read its mempool or wallet, or reuse its Tor circuits.
- Accept a SOCKS proxy that is not on this machine: the destinations and the per-stream
  credentials would cross the network in the clear before reaching Tor.
- Fall back to the unencrypted v1 transport. A peer that closes the encrypted handshake is a
  failed attempt like any other; the slot's next pre-assigned peer is tried at the next fixed
  time. A peer that only speaks the old transport is therefore never served; that
  compatibility loss is accepted.
- Guarantee delivery. Announcing to six peers is bounded effort, not a propagation
  promise.

## Using it

1. Check the transaction with `bitcoin-cli testmempoolaccept` first. The tool does only
   stateless sanity checks itself. The check leaves the node's validation and coins caches
   untouched, but reading the inputs warms the node's database and page caches like any
   UTXO lookup; if even that matters to you, run the check on a node that is not your
   public one.
2. Feed the final hex on stdin: `bitcoin-privbcast -tor=127.0.0.1:9050 send < tx.hex`.
   Progress lines go to stderr; the report, as JSON, to stdout.
3. Watch for receipt with `bitcoin-cli getmempoolentry` if you want to know it worked.
   Do not also broadcast the same transaction the ordinary way.

Tor must allow SOCKS authentication (the tool uses fresh credentials per stream for
isolation), the RESOLVE extension, and IPv6. The tool refuses to run if the proxy will not
authenticate. The progress stream and the report are local evidence that the job ran; keep
them where you would keep a wallet log.

## Limits

- The tool and the node still share a host and, usually, a Tor daemon. Load, Tor's own
  caches and the client's guard are common to both; the design does not separate them.
- DNS seeds, resolvers and Tor exits are untrusted. They can lie, tag their answers, or
  act as the peer themselves on an exit-path connection, since the encrypted transport
  authenticates nobody. The onion slot has no exit in the path.
- Recipients can recognise the release by its profile and probe it. They learn that
  someone used the tool, not who.
- Tor's own timing and reachability vary between users; the schedule fixes when the tool
  acts, not how fast the network answers.
- In package mode, a recipient that already holds the child as an orphan learned from another
  peer will not ask us for the parent, because we announce by txid, not wtxid; a parent it is
  missing then stays unfilled from us. Covering that would need wtxid-relay announcement and
  serving the parent to a peer that never took the child from us, so it is left as a known
  limitation.
