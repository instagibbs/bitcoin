# Private broadcast: specification

`bitcoin-privbcast` and `bitcoind -privatebroadcast` broadcast a transaction without revealing the
sender. This document states what a job must guarantee (invariants), the values peers and observers
see (parameters), what the design relies on (assumptions) and what it does not attempt (non-goals).
How to use it is in [private-broadcast.md](../private-broadcast.md).
The base specifies one transaction per job. The section "Extension: one parent, one child" adds
package mode on top of it and changes nothing for a job without a parent. The rationale at the end
is not normative.

## Goals

- **GOAL-1.** A job does not reveal the sender's IP address, onion address or long-term node
  identity to any party.
- **GOAL-2.** A hostile recipient, DNS seed or Tor exit learns no more about the sender than an
  honest one. It can only affect delivery.

The invariants are the testable form of these goals.

## Terms

- **Job**: one broadcast of one transaction, from submission to report.
- **Slot**: one of a job's six delivery targets. Each has a fixed class, onion or exit-path, and
  its own times and candidates.
- **Opportunity**: one of a slot's four scheduled connection times, a first attempt and up to three
  backups, each with a pre-assigned candidate or none.
- **Attempt**: an opportunity that is dialled: one proxy stream, one BIP324 connection, one session.
- **Announcement point**: the moment the transport accepts the job's INV for sending.
- **Exit-path candidate**: an IPv4 or IPv6 address from a DNS seed, reached through a Tor exit.
  **Onion candidate**: an onion service from the release fixed-seed list.
- **Delivery start**: job start plus the discovery window.

## Threat model

- A **recipient** sees a Tor exit or an onion circuit, the constant profile (E1) and the
  transaction it is sent.
- A **Tor exit** on an exit-path connection sees the recipient's address. BIP324 authenticates
  nobody, so the exit can also act as the peer: see the transaction, and drop or alter that one
  connection. Onion connections pass through no exit.
- A **DNS seed**, or the resolver an exit uses, sees queries for the seed names from Tor exits. It
  can answer falsely. It learns that a job ran.
- A **network observer** sees the transaction appear at several peers within seconds. That reveals
  that the tool was used, not where the sender is.
- An **observer between the sender and its Tor guard** (the ISP, or the guard) sees a burst of new
  circuits when a job starts and single circuits at its scheduled times, not their destinations.
- The **node's own peers** (node mode) see the transaction only after it has come back from the
  network, relayed like any other.

## Invariants

### A. Separation from the node and from other jobs

- **A1.** A job's only inputs are the transaction, the proxy endpoint, the chain's release seed
  material (DNS seed names, fixed-seed list, default port), a cancel signal, the clock and fresh
  randomness.
- **A2.** Every byte a job sends on a connection is a function of the transaction, per-attempt
  randomness (BIP324 keys and garbage, VERSION and PING nonces), the messages that peer sent on that
  connection and when they arrived against the attempt's fixed deadlines, and cancellation. So a
  peer that declines, never asks or never answers the PING sees the same bytes as a cooperative one
  up to that point; only when the connection closes differs.
- **A3.** No state written by the node or by another job changes what a job sends or when. A job
  keeps no state of its own on disk and leaves the node's peers, address manager and ban list as
  they were.
- **A4.** Apart from the transaction and the release profile, nothing a job sends or presents is
  shared between two attempts or two jobs: BIP324 keys and garbage, VERSION and PING nonces and
  proxy credentials are fresh per attempt or stream, and the schedule is fresh per job.

### B. Network path

- **B1.** Every stream a job opens goes through the SOCKS5 proxy. There is no direct connection and
  no local DNS lookup.
- **B2.** Every stream, each RESOLVE query and each attempt, carries fresh random isolation
  credentials, whatever the node's proxy settings. A proxy that does not accept username and
  password authentication gets no stream.
- **B3.** The tool accepts only a loopback address or a unix socket as its proxy. The node uses its
  configured onion proxy, local or not, trusted like its other proxy settings; the path to a remote
  proxy sees every destination and can tell job streams from the node's by their credentials.
- **B4.** Every attempt is BIP324 v2 as initiator. There is no v1 fallback.

### C. Fixed plan

- **C1.** The schedule, every opportunity's start and deadline, is drawn at job start, before any
  network activity, independently of anything the job observes.
- **C2.** Every opportunity's candidate is fixed when discovery ends, before any recipient is
  contacted, as a function of the discovery result alone.
- **C3.** Discovery ends when every query has completed or when the discovery window ends, whichever
  comes first. Delivery starts at job start plus the discovery window, whatever discovery did.
  Answers arriving after the window are discarded.
- **C4.** Nothing received on a connection and nothing seen of the transaction's propagation
  changes any time, any assignment or which opportunities run. The only exceptions: a slot's
  failure before the announcement point lets its next pre-assigned opportunity run at its scheduled
  time, and an announcement stops the slot's remaining opportunities. So a recipient can affect
  only its own slot, whether the slot's remaining opportunities run and when it ends, and through
  that when the job ends. There are no retries beyond the pre-drawn opportunities.
- **C5.** An opportunity that has a candidate is dialled within START_GRACE of its scheduled time,
  unless its slot has already announced (C6) or the job has been cancelled (C8). One the job cannot
  dial by then is missed, never dialled late.
- **C6.** Before the announcement point an attempt is replaceable; after it nothing else in that
  slot runs. Reports count an announcement only once the INV is fully written (H2); the difference
  is presentation only.
- **C7.** Slots run independently. No slot waits for, or is limited by, another slot.
- **C8.** Cancellation stops the whole job without waiting for any deadline: blocked proxy exchanges
  are abandoned, and no opportunity starts after it is seen. The only wait allowed is for a TCP
  connect to the proxy already under way, which may finish or time out first.

### D. Bounds

- **D1.** A job makes at most SLOTS × OPPORTUNITIES_PER_SLOT recipient connections, at most SLOTS
  at once, and at most QUERIES_PER_SEED RESOLVE streams per DNS seed, all launched at job start.
- **D2.** An attempt ends by its scheduled start plus ATTEMPT_MAX. A slot ends by its last
  opportunity's scheduled start plus ATTEMPT_MAX, its scheduled end, which is at most SLOT_MAX after
  its first opportunity. The job ends when its last slot has ended, at most SCHEDULED_BOUND after
  job start. Nothing is acted on at or after a phase deadline. These bounds are on the wall clock,
  so a clock set back mid-run stretches what remains. The node stops a job still running JOB_CAP
  after it started, measured on a steady clock.
- **D3.** A connection that has received more than MAX_RECV_BYTES, counting every byte read from it
  after the proxy connected it, is ended. This is a sanity bound, not part of the privacy model.
  The tool's read of stdin is bounded. The node queues at most
  MAX_QUEUED_JOBS jobs and refuses further submissions; the bound is on the number of jobs, not
  their size. It keeps at most MAX_FINISHED_JOBS reports.

### E. Wire behaviour on every connection

- **E1.** The job's VERSION is identical for every job of a release except its nonce (see
  Parameters).
- **E2.** The job announces only after the peer's VERSION shows a version of at least
  MIN_PEER_PROTOCOL_VERSION, NODE_WITNESS and relay, and the peer has sent WTXIDRELAY before its
  VERACK. After such a VERSION the job sends WTXIDRELAY, then VERACK; after any other it sends
  nothing more. A peer that fails any of these is left before the announcement.
- **E3.** The job sends exactly one INV, with one entry: MSG_WTX for the announced transaction's
  wtxid.
- **E4.** No transaction bytes are sent before the announcement point. A GETDATA that arrives before
  it is ignored.
- **E5.** The announced transaction is served at most once, and only for a single-entry MSG_WTX
  GETDATA naming its wtxid.
- **E6.** After serving, the job sends one PING and ends on a PONG carrying its nonce, or PONG_WAIT
  after the PING was written. The TX and the PING are written by the end of the request window, or
  the attempt ends there. Nothing more is served.
- **E7.** The job sends only VERSION, WTXIDRELAY, VERACK, INV, TX and PING, each only as E1-E6 say,
  and nothing once the attempt has ended, not even the rest of a partly written message. It ends a
  connection only as E2 and E6 say, or on the receive cap, a malformed message of a kind it acts on
  in its current state, a transport or socket error, the peer closing, a deadline or cancellation.
- **E8.** With a peer that passes E2 before the handshake deadline, the job announces at once. It
  serves the transaction on the first request E5 allows and then sends the PING. Against a Bitcoin
  Core recipient as in Assumptions, an announced attempt ends with the PONG, and the recipient ends
  up with the transaction when its policy accepts it.

### R. Recipients and discovery

- **R1.** Recipients come only from release material: the DNS seed names, resolved through the
  proxy, and the onion entries of the fixed-seed list.
- **R2.** A seed answer counts only if it is a public, routable IPv4 or IPv6 address; it gets the
  chain's default port. Seeds cannot supply onions. The fixed-seed list supplies only onions.
- **R3.** Which onions are chosen does not depend on what the seeds answered.
- **R4.** An endpoint is assigned to at most one opportunity per job. An endpoint returned by several
  seeds counts once.
- **R5.** Candidates are assigned so that a single lying DNS seed, returning endpoints it controls or
  dead ones, reaches as little of the job as possible, and so that scarce candidates go to first
  attempts:
  - **R5a.** When there are fewer candidates than opportunities, every slot's first opportunity that
    a remaining candidate may fill (R5c) is filled before any slot gets a backup.
  - **R5b.** Exit-path candidates are handed out across seeds in an order drawn before any query.
    While other seeds still have candidates, no two of a slot's opportunities come from the same
    seed. With four or more seeds answering, one seed supplies at most one of the exit-path slots'
    first attempts. The order in which answers arrive within the window changes nothing.
  - **R5c.** Onion slots take onion candidates while any remain, then exit-path candidates after
    the exit-path slots at the same layer have drawn. Exit-path slots never take onions. Onions go
    to the two onion slots alternately, layer by layer. The fallback happens on running out of
    onions, not on an onion failing.
- **R6.** Discovery excludes nothing based on node state. The node's own addresses can be drawn.

### H. Outputs

- **H1.** The job report contains no wall-clock time. Every time in it is an offset from job start.
  The tool's progress lines on stderr are a live log and carry the logger's timestamps.
- **H2.** The tool exits with status 0 if at least one INV was fully written, 2 if the job ran and
  none was, and 1 on a usage, input or internal error.
- **H3.** The report names every endpoint dialled, with each peer's protocol version and user agent,
  and contains no transaction bytes.

### U. Uniformity

- **U1.** The only settings that change a job's timing, counts or seed material are the regtest test
  overrides, and they are refused on other chains.
- **U2.** Node settings that choose peers (`-onlynet`, `-dnsseed`, `-fixedseeds`, `-connect`,
  `-seednode`, `-addnode`) and `-proxyrandomize` do not affect jobs. `-privatebroadcast` is refused
  at startup if onion cannot become reachable.
- **U3.** A node-mode job is the same as a tool job: same discovery, schedule, assignment and wire
  behaviour. The node adds only its proxy (B3) and the real-time cap (D2).

### N. Node integration

- **N1.** Submitting under `-privatebroadcast` never adds the transaction to the node's mempool and
  never relays it to the node's peers. It enters the mempool only when received from the network.
- **N2.** A job sends the bytes the caller submitted, never the mempool's copy, even when the
  mempool holds the same txid with another witness.
- **N3.** Jobs start in submission order. Each start opens a window whose length is drawn at that
  start from [START_SPACING_MIN, START_SPACING_MAX). A job submitted inside the window starts when
  it closes; one submitted after it closes, with nothing waiting, starts at once. The window runs
  from the previous start even if that job was aborted early. After the clock steps back, the next
  start comes between START_SPACING_MIN and START_SPACING_MAX after the step. Start times depend on
  no recipient and on no earlier job's end: the node runs enough jobs at once that a start waits for
  a running job only if that job outlives its cap or the clock has jumped forward.
- **N4.** Two jobs' discovery windows never overlap.
- **N5.** A submission whose wtxid has a job that is queued, or running and not being aborted,
  queues nothing. Otherwise it queues a new job. The key is the wtxid: a witness variant of a queued
  transaction gets its own job.
- **N6.** Cancellation is final. `abortprivatebroadcast`, shutdown and disabling networking cancel
  running jobs and drop queued ones; enabling networking again revives nothing. Nothing is queued
  while networking is off or the node is stopping. Networking off for less than a second can go
  unseen. Queued jobs are dropped within a second of networking going off or, while the node runs
  as many jobs as it can (N3), when one of them ends.
- **N7.** The node's observation of the transaction in its mempool is recorded for the report only
  and never reaches a job.
- **N8.** The node's default log names no transaction and no peer. A SOCKS failure line at the
  default level can show that a job ran.
- **N9.** Job records and reports are held in memory only. A job's transactions are dropped when it
  finishes; its hashes stay.
- **N10.** The file descriptors jobs can use are reserved at startup, after those of the node's
  ordinary connections and files. If not enough remain, the node refuses to start with
  `-privatebroadcast` rather than lower `-maxconnections`.
- **N11.** Only `sendrawtransaction` queues jobs. Wallet sends, `submitpackage` and every other way
  into the mempool work as without `-privatebroadcast`.

## Parameters

Normative values, the same for every user of a release.

| Parameter | Value | Seen by |
|---|---|---|
| QUERIES_PER_SEED, answers kept per seed, onions kept | 4, 3, 8 | seeds, exits |
| Seed query | RESOLVE of the bare seed name (no service-bit subdomain), one per stream | seeds, exits |
| Discovery window | 18 s from job start | seeds, observers |
| Slots | 6, fixed per release: slots 0-2 open at delivery start (exit-path, exit-path, onion); slot 3 (onion) at a time drawn in [35, 180] s after delivery start; slots 4-5 (exit-path) at times drawn in [185, 240] s, at least 5 s apart | observers, recipients |
| OPPORTUNITIES_PER_SLOT | 4: a first attempt and 3 backups | observers |
| Backup interval | drawn in [50, 60] s after the previous opportunity's scheduled time | observers |
| START_GRACE | 5 s | |
| Handshake budget: scheduled start to announcement point | 45 s | recipients |
| Request window: announcement point to the peer's request | 75 s | recipients |
| PONG_WAIT: after the PING is written | 10 s | recipients |
| MAX_RECV_BYTES | 128 KiB | recipients |
| VERSION | protocol 70017; services NODE_WITNESS; time 0; addr_recv null with services 0; addr_from null with services NODE_WITNESS; random nonce; user agent `/pynode:0.0.1/`; start height 0; relay false | recipients |
| MIN_PEER_PROTOCOL_VERSION | 70016 (BIP339) | recipients |
| JOB_CAP | 10 min | |
| START_SPACING_MIN, START_SPACING_MAX | 35 s, 55 s | recipients, in aggregate |
| MAX_QUEUED_JOBS, MAX_FINISHED_JOBS | 10,000, 100 | local |

Derived: ATTEMPT_MAX = 45 + 75 + 10 = 130 s; SLOT_MAX = 3 × 60 + 130 = 310 s; SCHEDULED_BOUND =
18 + 240 + 310 = 568 s; at most 24 connections per job, 6 at once.

Not normative, constrained only by C3, C5, D2, N3 and N6: the RESOLVE deadline, query grace, SOCKS
timeouts, handshake reserve, how often the node reads its clock and networking state, the number of
jobs it can run at once and the descriptors it reserves.

## Interface

What users' scripts and the functional tests rely on. Commands, options, JSON field names and
values, exit statuses and RPC error codes are part of it. Error messages and the report's `reason`
field are text for people and are not.

### Proxy

The job speaks SOCKS5 (RFC 1928) with username and password authentication (RFC 1929), which it
requires. It reaches recipients with CONNECT and resolves DNS seed names with Tor's RESOLVE
extension (command 0xF0), one name per stream.

### bitcoin-privbcast

- `bitcoin-privbcast [options] send` reads one transaction on stdin, a single hex string with
  nothing but whitespace around it (at most 8,004,096 bytes in all), runs one job and prints the
  report on stdout. The transaction must decode, pass the consensus checks that need no coins, not
  be a coinbase, weigh at most 400,000 weight units and send no more than `-maxburnamount` to any
  output whose script cannot be spent. Anything else is an input error.
- `bitcoin-privbcast [options] discover` runs discovery only and prints the discovery object with
  the candidates added (`seeds[].candidates`, `onion`).
- Options: `-tor=<ip:port|path>` (default `127.0.0.1:9050`), `-maxburnamount=<amt>` (refuse an
  output to an unspendable script above this amount; default 0), `-progress` (default on;
  `-noprogress` turns it off), `-debug=<category>` (`1` for all), the usual chain options, `-help`
  and `-version`.
- Regtest only, refused on other chains: `-seed=<name>` and `-fixedseed=<addr:port>` (each
  repeatable) replace the DNS seed list and the fixed-seed list; `-timedivisor=<n>` (1 to 1000)
  divides every duration of the plan, the internal timeouts included.
- stderr carries progress lines, in the logger's format, and error messages. When stderr is a pipe
  or a file, writing them never delays the job: a line stderr cannot take at once is dropped. On
  Windows, or on a terminal that is paused, a line can delay the job until it is written.
- Exit status: `send` as H2; `discover` 0, or 1 on error; a missing or unknown command exits 1, and
  with no arguments at all the usage is printed on stdout; `-help` and `-version` exit 0. Usage and
  input errors are found before any network activity. SIGINT and SIGTERM, and on Windows Ctrl-C and
  Ctrl-Break, cancel the job, and the report is still printed.

### Report

A JSON object. Times named `*_ms` are milliseconds from job start, one instant taken before
anything else, or null if the event did not happen.

- `txid`, `wtxid`, `chain`.
- `discovery`:
  - `duration_ms`: when discovery ended (C3).
  - `seeds`, one per DNS seed, each with `name`; `queries`, the RESOLVE queries started; `skipped`,
    QUERIES_PER_SEED minus `queries`; `answers`, every answer received in the window; `accepted`,
    the distinct usable endpoints credited to this seed (an endpoint several seeds returned is
    credited to one of them); and `kept`, those that became candidates.
  - `duplicates`: answers, from any seed, whose endpoint was already accepted; `rejected`: answers
    that are not public, routable IPv4 or IPv6 addresses.
  - `exit_path_candidates`, the sum of `kept`, and `onion_candidates`.
- `slots`, six in slot order, each with `slot`, `class` (`exit_path` or `onion`), `stratum`
  (`prompt`, `mid` or `late`), `scheduled_ms` (the four opportunities' scheduled starts),
  `scheduled_end_ms` (D2), `empty_opportunities` (those without a candidate),
  `missed_opportunities` (C5), `interrupted` (stopped by cancellation), `error` (null unless the
  slot failed) and `attempts`, in the order they were dialled.
- Each attempt: `endpoint` (address and port, an IPv6 address in brackets), `source` (`dns_seed` or
  `bundled`), `provenance` (the seed name, or `bundled`), `outcome`, `reason`,
  `scheduled_start_ms`, `started_ms` (the dial), `connected_ms` (the proxy connected),
  `peer_version` and `peer_user_agent` (from the peer's VERSION), `inv_handed_ms` (the
  announcement point), `inv_written_ms`, `getdata_ms` (the request that was served),
  `tx_written_ms`, `ping_written_ms`, `pong_ms`, `ended_ms`, `extra_requests` (GETDATAs received
  after the announcement point that got no reply), `bytes_sent` and `bytes_recv` (everything
  written to and read from the connection after the proxy connected it).
- `outcome` is `not_announced` (ended before the announcement point), `announced_not_requested`,
  `tx_written_no_pong`, `pong_received` or `post_announcement_failure`.
- `summary`: `connections` (attempts dialled); `announcements_handed`, `announcements_written`,
  `tx_written` and `pongs` (attempts that got that far); `slots_completed` (slots that neither
  failed nor were interrupted); `interrupted` (the job was cancelled); `duration_ms` (when the
  report was made).

### Node

- `-privatebroadcast` (default off) needs a Tor proxy for onion (`-proxy`, `-onion`, or
  `-listenonion` with `-torcontrol`). Startup fails if onion cannot become reachable, or if the
  file descriptors jobs need are not available.
- Regtest only, refused on other chains: `-privatebroadcastseed=<name>` and
  `-privatebroadcastfixedseed=<addr:port>`, each repeatable, as the tool's `-seed` and `-fixedseed`.
- A job's schedule and deadlines are on the node's clock: `setmocktime` moves them, and a change of
  the clock takes effect within a second of real time. Proxy exchanges, reads from the network and
  the checks of networking and shutdown proceed in real time whatever the clock does.
- `sendrawtransaction` queues a job and returns the txid. A transaction whose txid is already in the
  mempool counts as accepted and is queued as given; any other is test-accepted first, and may
  replace mempool transactions as usual.
- A submission that an existing job covers (N5) succeeds without queueing anything, even when the
  queue is full.
- It fails with RPC_LIMIT_EXCEEDED when a job cannot be queued (queue full, networking off, or
  shutting down) and with RPC_MISC_ERROR when no Tor proxy is configured.
- `getprivatebroadcastinfo` returns `jobs`: the retained finished jobs, oldest first, then the
  running and the queued ones. Each job has `txid`, `wtxid`, `state` (`queued`, `running`, `done`
  or `aborted`), `time_added`, `time_started`, `time_ended`,
  `seen_in_mempool` (Unix seconds, each once it applies), `error` (if the job could not run, or was
  stopped by disabling networking or by the cap), `progress` while running (`discovery_done`, set
  when discovery has ended; `opportunities_ended`, counting opportunities that were empty, missed,
  or whose attempt has ended; `connections` and `announcements_written`, counting ended attempts),
  and once it has run, `announced` (at least one INV fully written) and `report`. A running job
  that is aborted still ends with a report; a queued one has none.
- `abortprivatebroadcast <txid or wtxid>` returns `removed_transactions`, each with `txid`,
  `wtxid`, `hex` and `state`, the job's state after the call: `aborted` for a queued job, which is
  dropped at once, and `running` for a running one, which stops shortly. It fails with
  RPC_INVALID_ADDRESS_OR_KEY if no queued or running job matches.
- Without `-privatebroadcast`, both of these fail with RPC_METHOD_NOT_FOUND.

## Assumptions

- **Tor.** The SocksPort isolates streams by SOCKS username and password (`IsolateSOCKSAuth`, Tor's
  default). A SocksPort shared with the node must keep it: nothing at the SOCKS interface can detect
  its absence, and without it Tor may put several of a job's streams, or a job's stream and the
  node's own connections, on one circuit. Tor supports the RESOLVE extension, which returns one
  address per query. Only Tor implementations (C tor, Arti) speak RESOLVE, which is what keeps an
  ordinary SOCKS5 proxy from yielding exit-path candidates. A proxy built to imitate Tor would not be
  detected; it is covered by the proxy being trusted (B3).
- **Recipients** (Bitcoin Core):
  - wait 60 s for a requested transaction before asking another announcer;
  - when they cannot find a transaction's inputs, ask the announcer for every parent they do not
    recognise, confirmed ones included, by txid as MSG_WITNESS_TX, in GETDATAs of up to 1,000
    entries.
- **Release material.** DNS seeds return reachable nodes. The fixed-seed list ages with the release:
  about half of a list's onions still accept BIP324 six months after it is generated, and about one
  in eight after a year.

## Non-goals

- Hiding that a job ran, that it ran from a release with this profile, or anything that correlates
  it with other traffic through the same Tor daemon. The host, Tor's caches and its guard are shared
  with the node.
- Guaranteed delivery, or knowing whether a recipient accepted the transaction. A PONG means only
  that the recipient processed what it was sent.
- Retrying. The remedy for a transaction that did not arrive is another job, submitted by the user.
- The wallet, which is out of scope. Wallet sends are not private broadcasts: the wallet submits to
  the mempool and announces to all peers. And once a transaction that involves the wallet is back in
  the node's mempool, the wallet's periodic resend (every 12 to 36 hours) announces it to every peer
  while it stays unconfirmed, however it was first broadcast.
- Hiding when a job was submitted. A tool job starts at once, and so does a node job submitted to an
  idle queue.
- End-to-end timing correlation by an observer of both the sender's Tor traffic and the network,
  which Tor does not prevent either.
- Hiding operator actions from a recipient that is also one of the node's peers. Shutdown and
  `setnetworkactive false` close a job's open connections within about 100 ms of the node's own.
- Local users of the host, who can see connections to the proxy, process arguments and the tool's
  output.
- Authenticating recipients. Exits and seeds are untrusted.

## Extension: one parent, one child

A parent too cheap to enter mempools on its own can be carried by a child that pays for both, when
the recipient evaluates the two together. Package mode adds that to the base: a job then carries the
child and its unconfirmed parent. For a job without a parent, nothing in the base changes.

### Terms and threat model

- **Package mode**: a job that carries a child and its parent. Where the base says "the
  transaction", read the child, except in A1, A2 and A4, which cover both transactions.
- A recipient in package mode is sent the child, and the parent if it asks for it.

### Invariants

- **F1.** In package mode only the child is announced.
- **F2.** The parent is served at most once per connection, and only for a GETDATA containing
  MSG_WITNESS_TX for the parent's txid, either (a) after the child was served and before the PING,
  or (b) before the child was served, when the GETDATA names neither of the child's ids. A GETDATA
  naming both before the child is served is ignored entirely. After the parent is served, the PING
  goes out and nothing more is served.
- **F3.** After the child is fully written, the PING is held until the parent is served or
  PARENT_HOLD has passed, but never into the last PONG_WAIT of the request window.
- **F4.** A GETDATA received while the job waits for the parent request (from serving the child
  until the PING), or handled under F2 (b), is answered with NOTFOUND for exactly its transaction
  entries that are neither id of either of the job's transactions, and with none if there are no
  such entries. No other NOTFOUND is sent.
- The base changes in package mode as follows:
  - E6: the PING follows the parent phase (F2, F3).
  - E7: the job also sends NOTFOUND, as F4 says.
  - E8: the job also serves the parent on the first request F2 allows, and the PING waits for the
    hold (F3). A Bitcoin Core recipient ends up with the package when its policy accepts it.
  - N5: a submission with a parent is covered only by a job with the same parent; one without a
    parent is covered by a job with any parent.
  - N11: `submitpackage` queues jobs too.

### Parameters

| Parameter | Value | Seen by |
|---|---|---|
| PARENT_HOLD | 30 s | recipients |

PARENT_HOLD + PONG_WAIT is at most the request window, so a child requested promptly gets the whole
hold.

### Interface

- `bitcoin-privbcast send` also takes two transactions, a parent and its child in either order,
  separated by whitespace. They must differ and one must spend the other. Every input of the child
  that spends the parent must name an output the parent has and that can be spent, the two must
  share no input, and together they must weigh at most 404,000 weight units.
- The report adds `parent_txid` and `parent_wtxid`; per attempt `parent_getdata_ms` (the request
  the parent was served for), `parent_tx_written_ms` and `parent_hold_expired_ms` (the PING went out
  without a parent request, F3); and `summary.parents_served`.
- `getprivatebroadcastinfo` adds `parent_txid` for a package job.
- `submitpackage` takes one transaction, or one parent and its child. More than two fail with
  RPC_INVALID_PARAMETER, and two that are not a parent and its child with RPC_VERIFY_ERROR, as
  without `-privatebroadcast`. A transaction whose txid is in the mempool counts as accepted and is
  sent as given. What remains is test-accepted: one transaction alone, as by `sendrawtransaction`;
  two as a package. If the parent then fails only for its fee, the child is checked only for its fee:
  within `maxfeerate`, and the pair paying at least the higher of the mempool minimum feerate and the
  minimum relay feerate. A package rejected as a whole queues nothing. The result has `package_msg`
  (`success`, `parent-reconsiderable` or an error) and `tx-results`, keyed by wtxid, and a job is
  queued only when the package is acceptable. Each entry of `tx-results` has `txid`; `other-wtxid`
  when the mempool holds the txid with another witness; `fees` when the transaction was
  test-accepted; and `error` when it was not accepted, carrying validation's reject reason when
  validation rejected it.
  It fails as `sendrawtransaction` does when a job cannot be queued or no Tor proxy is configured.

### Assumptions

- Recipients (Bitcoin Core) ask for a missing parent about 4 s after receiving the child (2 s for a
  non-preferred peer, 2 s for a request by txid). From version 29 they ask only for the parent when
  they already hold the child as an orphan learned from another peer. They accept a parent below the
  minimum relay feerate in a package from version 31 whatever its version, and in versions 28 to 30
  only if it is TRUC; older versions drop it.

### Non-goals

- Hiding package mode. A recipient that fetches the child can tell from the held PING, and one that
  asks for the parent is served it. The pairing is visible on chain anyway.
- Validating a package fully. The tool checks no fees. When the parent fails only for its fee, the
  node checks the child only for its fee, as the interface says, which needs the child's other
  inputs to be in the mempool or the UTXO set.

### Rationale (not normative)

- Only the child is announced: announcing the parent would invite a request for it before the child,
  and a low-fee parent received alone is rejected.
- A peer that has not been sent the child cannot have learned its inputs from the job, so a request
  naming both was not caused by the announcement (F2).
- The 30 s parent hold is several times a recipient's orphan-parent delay plus a Tor round trip.

## Rationale (not normative)

- **Where privacy comes from.** GOAL-1 rests on A, B and U: the job shares nothing with the node and
  reaches everything through Tor. The schedule (C) adds no address privacy. It buys delivery that
  survives failed attempts and a plan no peer can move. The later slots open at random offsets in
  fixed windows, at least 5 s apart, so there is no regular grid, but the prompt slots and backups
  still form bursts.
- **No knobs.** A tunable would make its users distinguishable, so every parameter is fixed per
  release and the test overrides exist only on regtest. None of the parameters is a privacy
  parameter: changing one changes cost and robustness for every user alike.
- **No retries.** Retrying because the transaction did not come back would act on exactly the signal
  a network adversary controls. To censor a job, an adversary must take the announcement and
  withhold the transaction in every slot, onion slots included, or make every opportunity of a slot
  fail before announcing.
- **Slot shape.** The three prompt slots race two exit paths and an onion, so the first announcement
  comes from whichever connects first, and the prompt onion gives an early route that does not
  depend on the DNS seeds. The late pair runs whatever happened before and uses fresh DNS answers,
  because the onion list ages.
- **Budgets.** 45 s fits an onion rendezvous and the BIP324 handshake over Tor. 75 s outlasts the
  60 s a recipient waits before asking another announcer. 10 s covers a PING round trip. The 5 s
  grace absorbs scheduler jitter only. The 50 s backup floor is the handshake budget plus the grace,
  so a failure before the announcement is known before the backup's time. The discovery window was
  measured: on one Tor client, bursts of RESOLVE queries finished within 8 s nine times in ten, and
  a 15 s query deadline kept the same candidates as 25 s; 18 s leaves a margin.
- **Start spacing.** Starts are spaced from the previous start, not the previous end, because
  recipients can affect when a job ends and must not affect when the next starts. The spacing
  exceeds the discovery window so discoveries never overlap. What a recipient can still affect is
  whether a resubmission during its job is ignored (N5) or queued.
- **Profile.** Protocol 70017 tracks the release. NODE_WITNESS is advertised because the job serves
  witness data, and wtxid relay is required so the transaction is announced and requested by wtxid.
  The user agent is the constant the previous implementation sent (bitcoin/bitcoin#27509), not the
  node's.
- **Own addresses.** Discovery does not exclude the node's own addresses: a filter on node state is
  the coupling A forbids, excluding some addresses would bias the choice of recipients, and delivery
  to the node itself looks like delivery to any other recipient.
- **Exits with `-onlynet=onion`.** Jobs use exit-path peers regardless: the fixed-seed onions alone
  age with the release, Tor hides the sender's address on either path, and an exit can only affect
  its own connection.
- **Proxy.** SOCKS5 carries destinations and credentials in plaintext up to the proxy, so the tool
  accepts only a local one; the node trusts its configured proxy as it does for its own connections.
  A proxy that is not Tor delivers nothing: every stream needs fresh username and password
  credentials, exit-path candidates come only from RESOLVE answers, and only the onion entries of
  the fixed-seed list are used. It learns only that a job ran.
- **Sending the caller's bytes (N2).** Sending the mempool's copy would let a witness variant
  planted in the node's mempool mark the node's broadcasts.
- **Receive cap.** A recipient that cannot find a large transaction's inputs can ask the job for
  about 2,400 parents at 36 bytes each; 128 KiB leaves room for that and the handshake. relay=false
  in the VERSION keeps a recipient from announcing its own transactions to the job, so only its
  requests use the budget.
