# bitcoin-privbcast: design notes

The goal is to broadcast a transaction without revealing the sender's IP address, onion
address or long-term node identity. A job is one run of that broadcast. `bitcoin-privbcast`
announces one final transaction to a bounded set of peers over Tor, makes at most 24
connections, finishes within ten minutes and keeps nothing but its report. The tool is a
separate program from `bitcoind`.

Two rules govern a job, and the rest of this document follows from them. A job touches no
node state, so nothing a recipient sees at the P2P layer can be tied to the node. A job draws
its schedule before its first connection, and nothing a peer does moves it. The tool does not
promise delivery and does not do additional retries on its own.

**Terms.** A *job* is one run of the broadcast: one transaction, from submission to
report. A job has six *slots*, each a delivery target with its own times and its own
peers, all drawn and assigned at job start. A slot has up to four *opportunities*: a first
peer at the slot's opening time and up to three backups at drawn intervals after it. An
opportunity that is dialled is an *attempt*: one Tor stream, one BIP324 connection, one
session of the fixed protocol profile on it. An opportunity with no peer left to assign is
empty, and one the host could not dial within 5 s of its time is missed; neither is an
attempt. A slot makes at most one announcement, and after it the slot's remaining
opportunities lapse. So: job, slot, opportunity, attempt, and the report is shaped the
same way, `slots[].attempts[]`.

## Who sees what

Every party sees a Tor circuit rather than the sender.

- A recipient sees an exit or an onion circuit, a constant wire profile, and the transaction.
  The job has no IP address, onion address, peer set, address manager, mempool or validation
  cache to leak.
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
marking the tool. The user agent is a constant that no node sends (see bitcoin/bitcoin#27509).

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
derived from the per-attempt budgets. The 18 s discovery window is measured: RESOLVE
bursts finished within 8 s nine times in ten on one Tor client. The onion reachability under
Limits comes from probing each release's fixed-seed list. Six slots, three of them prompt,
three backups each, and the two windows are design choices: enough that losing a path or a
few peers does not lose the job, few enough that a job stays small. None is a privacy
parameter; changing one changes cost and robustness for every user of a release alike.

The schedule makes no claim about hiding the user's address. That comes from the job having
no node state and reaching everything through Tor. The schedule buys two things: delivery
that survives failed attempts, and a fixed plan that no peer can move. Any privacy on top
is marginal and unpromised. The later slots open at random offsets within fixed windows, in a
fixed order and at least 5 s apart, so there is no regular grid to recognize. The three
prompt slots open together on purpose, and backups can still cluster, so bursts remain.

## Using it

1. Check the transaction with `bitcoin-cli testmempoolaccept` first. The tool itself does
   only stateless sanity checks. The check leaves the node's validation and coins caches
   untouched, but reading the inputs warms the node's database and page caches like any
   UTXO lookup. If that matters, run the check on a node that is not your public one.
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
- Tor's timing and reachability vary between users. The schedule fixes when the job acts;
  the network decides how fast it answers.
- A job stops when its schedule ends and does not retry on its own. Retrying because the
  transaction did not come back would act on exactly the signal a network adversary
  controls. A recipient can accept an announcement and then withhold the transaction; that
  slot will not try its backups. To censor a job, an adversary must do that in every slot,
  onion slots included, or make all of a slot's opportunities fail before an announcement.
  The remedy is another job, submitted by the user after watching `getmempoolentry`; it
  discovers and schedules independently.
