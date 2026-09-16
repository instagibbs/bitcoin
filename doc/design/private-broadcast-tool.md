# bitcoin-privbcast: design notes

The goal is to broadcast a transaction without revealing the sender's IP address, onion
address or long-term node identity. A job is one run of that broadcast. `bitcoin-privbcast`
announces one final transaction, or one parent and its child, to a bounded set of peers over
Tor, makes at most 24 connections, finishes within ten minutes and keeps nothing but its
report. The tool is a separate program. With `-privatebroadcast`, `bitcoind` does not launch
it; RPC submissions queue jobs, and worker threads in `bitcoind` run the same job code
directly instead of the node's connection manager.

Two rules govern a job, and the rest of this document follows from them. A job touches no
node state, so nothing a recipient sees at the P2P layer can be tied to the node. A job draws
its schedule before its first connection, and nothing a peer does moves it. The tool does not
promise delivery and does not do additional retries on its own.

**Terms.** A *job* is one run of the broadcast: one transaction, or one parent and its
child, from submission to report. A job has six *slots*, each a delivery target with its
own times and its own peers, all drawn and assigned at job start. A slot has up to four
*opportunities*: a first peer at the slot's opening time and up to three backups at drawn
intervals after it. An opportunity that is dialled is an *attempt*: one Tor stream, one
BIP324 connection, one session of the fixed protocol profile on it. An opportunity with no
peer left to assign is empty, and one the host could not dial within 5 s of its time is
missed; neither is an attempt. A slot makes at most one announcement, and after it the
slot's remaining opportunities lapse. So: job, slot, opportunity, attempt, and the report
is shaped the same way, `slots[].attempts[]`.

## Who sees what

Every party sees a Tor circuit rather than the sender.

- A recipient sees an exit or an onion circuit, a constant wire profile, and the transaction
  (a child and, on request, its parent). The job has no IP address, onion address, peer set,
  address manager, mempool or validation cache to leak.
- A Tor exit on an exit-path connection sees the transaction and the recipient. It can drop
  or alter that one connection. Onion connections do not pass through an exit.
- A DNS seed, or the resolver an exit uses, sees a query for the seed's name from a Tor exit.
  It can answer falsely. It learns only that a job ran.
- A network observer sees the transaction appear at several peers within seconds, which
  reveals use of the tool and nothing about where the sender is.
- The node's own peers see the transaction once it has come back from the network, relayed
  like any other.

The design does not hide that a job ran, that it ran from a release with this profile, or
anything that correlates the job with other traffic through the same Tor daemon (see Limits).

## Compared with `-privatebroadcast` before this change

The entry points stay: `sendrawtransaction` and the `getprivatebroadcastinfo` and
`abortprivatebroadcast` RPCs. What runs behind them is new.

| | Before (in `CConnman` and `PeerManager`) | Now (a job) |
|---|---|---|
| Peers | from the node's address manager | discovered per job: the release DNS seeds resolved through Tor (`RESOLVE`), plus onion peers from the release fixed-seed list |
| Networks | Tor, I2P, IPv4/IPv6 through the proxy | Tor only: onion peers, and IPv4/IPv6 peers through Tor exits |
| Transport | v2 or v1 | v2 (BIP324) only |
| Connections at once | 3 per transaction when it is submitted (all private broadcasts share a cap of 64), each up to 3 min | 3 at start, never more than 6 (one per slot) |
| Connections in total | more with every re-send | at most 24: 6 slots of 4 opportunities, a first peer and up to 3 backups each |
| Retries | re-sent to new peers until seen back in the node's mempool (after 1 min), up to 1000 times | none after an announcement; the schedule is drawn at job start and nothing seen on the network changes it |
| Duration | open-ended | every job's network work ends within 568 s |
| Peer profile | `NODE_NONE`, no wtxid relay, announces by txid | `NODE_WITNESS`, protocol 70017, requires wtxid relay (BIP339) and announces by wtxid |
| Packages | no | one parent and its child, in the program |
| Without a node | no | the `bitcoin-privbcast` program |

The right column describes a smaller feature. It gives up I2P, peers that speak only the old
transport, the node's address manager, and re-sending when the transaction does not come
back. Each is given up for the two rules below and for a bounded cost: at most 24
connections, over within 568 s, with a report of every attempt.

**Delivery depends on recipients; privacy does not.** A hostile recipient learns no more
about the sender's IP address or long-term identity than an honest one. Recipients are chosen
at random across three paths for robustness: a recipient that drops the transaction, or an
exit that interferes with it, costs one slot.

## The two rules

Both are enforced by construction rather than by careful coding.

1. **The job creates no state a node can be read through.** It has no address manager, ban
   or discouragement list, connection table shared with ordinary peers, upload accounting or
   validation caches. A recipient that misbehaves ends only its own connection. When the job
   ends, only its report remains. The companion change to `testmempoolaccept` keeps the
   recommended preflight from leaving a trace in the node's validation caches and coins
   cache; reading the inputs still warms the database and page caches, like any UTXO lookup.

2. **The schedule is drawn when the job starts, and nothing observed on a connection moves
   it.** At job start the job draws the time and hard lifetime limit of every
   opportunity. After discovery it assigns every candidate before contacting any recipient.
   Nothing received from a recipient reschedules or reassigns an opportunity. A failure
   before an announcement enables only the same slot's next pre-assigned opportunity, at its
   scheduled time. An announcement suppresses that slot's remaining opportunities. Protocol
   responses follow fixed rules on the current connection. An opportunity that cannot start
   within 5 s of its time is missed. Cancellation stops the whole job. Seeing the
   transaction come back through the network changes nothing.

## What a recipient sees

Each connection uses the same profile. The job sends a VERSION with constant fields: protocol
70017, `NODE_WITNESS`, no relay, no height, no time, and user agent `/pynode:0.0.1/`. It
answers the peer's VERSION with WTXIDRELAY and VERACK, announces the transaction by wtxid,
serves it once when asked for it by wtxid, sends one PING, and closes on the matching PONG.

The protocol version is Core's current one, so the profile tracks the release rather than
marking the tool. The user agent is the one the previous implementation sent, a constant
other than the node's own (see bitcoin/bitcoin#27509); keeping it adds no second profile.

The job requires a peer at protocol 70016 or later that offers `NODE_WITNESS`, accepts relay
and sends WTXIDRELAY before its VERACK. It leaves any other peer before announcing anything.
It reads and ignores every other message. A peer that declines the transaction, does not ask
for it, or does not answer the PING sees nothing different from a peer that does everything
promptly, except that the connection ends at its fixed deadline instead of earlier.

## The schedule

Times are from job start.

- **Discovery, 0-18 s.** The job asks Tor to resolve each release DNS seed four times, each
  query on its own Tor stream, and keeps up to three answers per seed. It adds up to eight
  onion peers from the release fixed-seed list. Queries stop at 15 s, and delivery starts at
  18 s whether or not answers arrived.
- **Delivery, six slots.** A slot is one delivery target with four opportunities: a first
  peer and up to three pre-chosen backups. Three prompt slots open together at 18 s: two
  to peers reached through Tor exits and one to an onion peer, so the first announcement
  comes from whichever path connects first. The other three open at times drawn at job
  start. One onion slot opens 35-180 s after delivery starts, which is 53-198 s from job
  start. Two exit-path slots open 185-240 s after delivery starts, which is 203-258 s from
  job start, at least 5 s apart. A slot's class is a preference. An onion slot whose onion
  list has run out falls back to exit-path peers, so with few onions known every attempt
  can be exit-path. Exit-path slots do not take onions.
- **Each attempt.** From its opportunity's time, an attempt has 45 s to connect, complete
  the encrypted handshake and announce. The peer then has 75 s to ask for the transaction,
  and 10 s to answer the PING after it is written. If the attempt fails before announcing,
  the slot's next opportunity opens 50-60 s after the previous one's time, at most three
  times; that interval is drawn at job start. Failure includes a peer closing the
  encrypted handshake because it speaks only v1; there is no v1 fallback. Once a slot
  announces via INV it makes no more attempts, whatever happens next. Slots do not wait
  for each other.
- **End.** A slot's network work ends within 310 s of its first opportunity's time, so the job's
  ends by 568 s at the latest, with a hard cap of 10 min behind that. These are scheduled
  bounds: host scheduling can delay a step but cannot reschedule one.

All durations are compile-time constants in `src/privbcast/*.h`. There are no knobs, because
a tunable would make its users distinguishable.

The numbers have three sources. The 50 s backup floor, the 310 s slot and the 568 s bound are
derived from the per-attempt budgets. The 18 s discovery window and the 30 s parent hold
are measured: RESOLVE bursts finished within 8 s nine times in ten on one Tor client, and
orphan resolution asks within about 4 s on signet. The onion reachability under Limits comes
from probing each release's fixed-seed list. Six slots, three of them prompt, three backups
each, and the two windows are design choices: enough that losing a path or a few peers does
not lose the job, few enough that a job stays small. None is a privacy parameter; changing
one changes cost and robustness for every user of a release alike.

The schedule makes no claim about hiding the user's address. That comes from the job having
no node state and reaching everything through Tor. The schedule buys two things: delivery
that survives failed attempts, and a fixed plan that no peer can move. Any privacy on top
is marginal and unpromised. The later slots open at random offsets within fixed windows, in a
fixed order and at least 5 s apart, so there is no regular grid to recognize. The three
prompt slots open together on purpose, and backups can still cluster, so bursts remain.

## One parent, one child

A transaction whose fee is too low to enter mempools on its own can be carried by a child
that spends it, when the recipient evaluates the two together. Bitcoin Core 28 and later do
this for exactly one parent and one child. Give the tool both transactions in either order;
it works out which is which.

- Only the child is announced. Announcing the parent would invite a request for it before
  the child. A low-fee parent received alone is rejected, and the job does not serve a
  transaction a second time.
- The child is served once, on the exact single-entry request for it by wtxid. The job
  then holds its PING for 30 s for the peer to ask for the parent. A recipient that lacks
  the parent asks about 4 s later, measured on signet, because of its orphan-resolution
  delays. That request may batch the parent with the child's other inputs, so the job
  serves the parent and, like any node, answers the entries it does not have with
  `notfound`. It does not say that about its own two transactions.
- The parent is served once, only if it is the parent given, and only on one of two requests:
  - after the child was served, a request naming the parent by txid (orphan resolution);
  - before the child was served, a request naming the parent and not the child, from a
    recipient that already held the child as an orphan learned from another peer. The job's
    wtxid announcement adds it as an announcer of that orphan, so the recipient asks it only
    for the parent.
  Before the child has been served, a request that names both child and parent is ignored
  outright, with no `notfound` either. The peer cannot have learned the child's inputs from
  the job at that point, so the announcement did not cause that request. The connection
  stays open, and a later request for the child alone is still answered. Once the parent is
  served, PING goes out and nothing more is served on that connection.
- If no request for the parent arrives within the hold, PING goes out anyway. The job cannot
  tell whether the peer already had the parent, was still waiting on a request to another
  peer, or will not take the package.
- One request window still bounds the whole exchange. The second request restarts nothing,
  and the announcement point and the replacement rules are unchanged.
- Which recipients accept the package depends on the parent. A parent below the minimum
  relay feerate is accepted as part of a package by Bitcoin Core 28 and later only if it is
  TRUC (version 3). A non-TRUC parent below that feerate needs Bitcoin Core 31 or later;
  older recipients drop it. Whether the package reaches miners depends on what they run.
- The tool cannot check that the child has no other unconfirmed parent or that it pays
  enough for both, and there is no dry run for a package. `testmempoolaccept` checks each
  transaction on its own and does not apply the child's fee to the parent, so it reports a
  low-fee parent as "min relay fee not met" even when the package would be accepted, and it
  stops there without evaluating the child. That rejection says nothing about the child's
  validity. Work out the package feerate yourself. The tool also cannot see whether the
  recipient accepted the package; a PONG means only that the recipient processed what it was
  sent. A recipient older than Bitcoin Core 28 asks for the parent, rejects it alone and
  keeps the child as an orphan only until the job disconnects.
- A second transaction is served on request only in package mode, that is, when the tool is
  given two transactions. A recipient that asks for the parent therefore learns the sender
  used package mode. That the two transactions belong together is already visible on the
  chain.

## Using it

1. Check the transaction with `bitcoin-cli testmempoolaccept` first. The tool itself does
   only stateless sanity checks. The check leaves the node's validation and coins caches
   untouched, but reading the inputs warms the node's database and page caches like any
   UTXO lookup. If that matters, run the check on a node that is not your public one. For a
   parent and child the check rejects a low-fee parent on its own; see "One parent, one
   child".
2. Feed the final hex on stdin: `bitcoin-privbcast send < tx.hex`. Tor is expected at
   127.0.0.1:9050; pass `-tor=` for another listener. The JSON report goes to stdout and
   progress lines go to stderr.
3. Watch for receipt with `bitcoin-cli getmempoolentry`. Do not also broadcast the same
   transaction the ordinary way.

`send` exits 0 if at least one announcement was fully written, 2 if none was, and 1 on bad
input or arguments. Status 0 does not mean a peer requested the transaction, received its
bytes or accepted it: a peer can ignore the announcement, and the slot has already given
up its remaining opportunities, because after an INV the peer may hold the transaction and
further attempts could only add exposure. The report's per-attempt outcome and its
`tx_written` and `pongs` counts are the stronger evidence. The JSON report has no
wall-clock value and is the record. Progress lines on stderr are best effort: a line a
pipe cannot take is dropped rather than waited for (see `-help`). Both are local evidence
of the attempt, so keep them where you would keep a wallet log.

The proxy must run on this machine, because a remote one would carry destinations and
credentials in the clear. It must accept SOCKS authentication, Tor's RESOLVE extension and
IPv6. The tool cannot verify that a proxy is Tor and does not need to. A proxy that is not
Tor delivers nothing: every stream requires fresh username/password credentials, which
`ssh -D` and most VPN clients do not offer; exit-path candidates come only from RESOLVE
answers; and the bundled list is onion only. Such a proxy learns only that a job ran.

When the node and a job share a SocksPort, circuit separation requires `IsolateSOCKSAuth`,
Tor's default; fresh credentials alone cannot enforce it. With `NoIsolateSOCKSAuth`, Tor may
put several of a job's streams on one circuit, so one exit can see the transaction reach
several recipients. It may also put a job's stream on a circuit that carries other traffic
through the same SocksPort, such as the node's own connections and whatever they reveal
about it, its advertised onion address for one. Nothing at the SOCKS interface can detect
this; Tor accepts the credentials either way. The operator must ensure the SocksPort keeps
stream isolation.

## Inside the node

With `-privatebroadcast`, `sendrawtransaction` queues a job in `bitcoind`'s
`PrivateBroadcastManager`. A worker calls `privbcast::RunJob()` in the node's
process, the same function the standalone program calls. A job uses none of the node's peer
machinery: no address manager, connection manager, peer manager or ban list. Its discovery,
schedule and wire profile are the tool's. The transaction does not enter the node's mempool
until it comes back from the network, and the node then treats it like any other. Submitting
the same transaction again queues another job, even one the node's mempool already holds;
jobs are not deduplicated.

Node settings that choose peers (`-onlynet`, `-dnsseed`, `-fixedseeds`, `-connect`,
`-seednode`, `-addnode`) do not apply to jobs. Even with `-onlynet=onion`, a job can connect
through Tor exits: the fixed-seed onions alone age with the release (see Limits), Tor hides
the user's address on either path, and an exit can only drop or alter its own connection,
which cannot control the other slots. There is no switch to change this, for the same reason
there are no other knobs.

A job shares five things with the node.

- **The proxy.** The node's Tor proxy, trusted as the node's other proxy settings are. Every
  stream carries fresh credentials regardless of `-proxyrandomize`.
- **The queue.** At most two jobs run at once, in submission order. A job ends when its last
  connection ends, so a recipient that holds a connection open can delay the start of the
  next queued job. That job's own schedule is fixed once it starts, but its start time is not
  independent of earlier recipients: an observer of both jobs may link their transactions by
  the delay. The link alone does not identify the node.
- **An observation.** The report records when the node's mempool first sees the transaction.
  The observation is not fed back into a job.
- **The log.** `debug.log` records job progress only with `-debug=privatebroadcast`. SOCKS
  failures that mention a destination appear only with `-debug=proxy` or `-debug=net`.
- **The process.** Shutdown and `setnetworkactive false` cancel jobs.

Wallet sends are not private broadcasts. The wallet submits to the node's mempool and
rebroadcasts from there, which a private broadcast must not do. Making wallet sends private
is a separate change.

## Limits

- The tool and the node still share a host and, usually, a Tor daemon. Load, Tor's caches
  and the client's guard are common to both; the design does not separate them.
- DNS seeds, resolvers and Tor exits are untrusted. They can lie, tag their answers, or act
  as the peer themselves on an exit-path connection, since the encrypted transport
  authenticates nobody. Onion connections do not pass through an exit.
- Onion peers come only from the fixed-seed list shipped with the release, which ages with
  it. A year after a list is generated, roughly one onion in six still accepts the encrypted
  transport. On an old release most onion slots fall back to exit-path peers, and the job
  loses its paths without an exit.
- Recipients can recognize the release by its profile and probe it. They learn only that
  someone used the tool.
- Discovery does not exclude the node's own addresses. A filter on node state is the coupling
  rule 1 forbids, and it is not wanted anyway: excluding some addresses would bias the
  sampling of recipients, and self-delivery is indistinguishable from delivery to any other
  recipient. A job that draws the node's own onion or IP makes the node one of that job's
  first relayers.
- Tor's timing and reachability vary between users. The schedule fixes when the job acts;
  the network decides how fast it answers.
- A job stops when its schedule ends and does not retry on its own. Retrying because the
  transaction did not come back would act on exactly the signal a network adversary
  controls. A recipient can accept an announcement and then withhold the transaction; that
  slot will not try its backups. To censor a job, an adversary must do that in every slot,
  onion slots included, or make all of a slot's opportunities fail before an announcement.
  The remedy is another job, submitted by the user after watching `getmempoolentry`; it
  discovers and schedules independently.
