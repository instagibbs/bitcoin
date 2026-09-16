# Mempool Replacements

## Current Replace-by-Fee Policy

A transaction conflicts with an in-mempool transaction ("directly conflicting transaction") if they
spend one or more of the same inputs. A transaction may conflict with multiple in-mempool
transactions.

A transaction ("replacement transaction") may replace its directly conflicting transactions and
their in-mempool descendants (together, "original transactions") if, in addition to passing all
other consensus and policy rules, each of the following conditions are met:

1. (Removed)

2. (Removed)

3. The replacement transaction pays an absolute fee of at least the sum paid by the original
   transactions.

   *Rationale*: Only requiring the replacement transaction to have a higher feerate could allow an
   attacker to bypass node minimum relay feerate requirements and cause the network to repeatedly
   relay slightly smaller replacement transactions without adding any more fees. Additionally, if
   any of the original transactions would be included in the next block assembled by an economically
   rational miner, a replacement policy allowing the replacement transaction to decrease the absolute
   fees in the next block would be incentive-incompatible.

4. The additional fees (difference between absolute fee paid by the replacement transaction and the
   sum paid by the original transactions) pays for the replacement transaction's bandwidth at or
   above the rate set by the node's incremental relay feerate. For example, if the incremental relay
   feerate is 0.1 satoshi/vB and the replacement transaction is 500 virtual bytes total, then the
   replacement pays a fee at least 50 satoshis higher than the sum of the original transactions.

   *Rationale*: Try to prevent DoS attacks where an attacker causes the network to repeatedly relay
   transactions each paying a tiny additional amount in fees, e.g. just 1 satoshi.

5. The number of distinct clusters corresponding to conflicting transactions does not exceed 100.

   *Rationale*: Limit CPU usage required to update the mempool for so many transactions being
   removed at once.

6. The feerate diagram of the mempool must be strictly improved by the replacement transaction.

   *Rationale*: This ensures that block fees in all future blocks will go up
   after the replacement (ignoring tail effects at the end of a block).


## Generalized sibling eviction

Single-transaction admission first attempts ordinary acceptance, including replacement of direct
conflicts and their descendants. If the resulting cluster would exceed the count or weight limit,
a non-TRUC transaction gets one additional attempt, in which some transactions that do not
conflict with it may be evicted to make room:

1. Bound the work. The clusters of the incoming transaction's unconfirmed parents and of its
   direct conflicts must together number at most 100.
2. Pin the incoming transaction and its entire unconfirmed ancestor set. If they alone exceed a
   limit, reject; nothing else can be evicted to make them fit.
3. Every other transaction remaining in the parents' clusters, after the direct conflicts and
   their descendants are removed, is a candidate, provided it is still connected to the pinned set.
   Material that the removals disconnect forms its own cluster within limits and is neither
   budgeted nor evicted.
4. Group candidates into chunks of their own linearization, in each cluster's existing order and
   skipping pinned entries, so a chunk's feerate is what its members are worth on their own now
   that the incoming transaction carries the pinned ancestors. Chunks are kept or evicted whole.
5. Fill the remaining count and weight budget greedily: repeatedly keep the highest-feerate chunk
   whose ancestors are all kept or pinned and which fits. Chunks that do not fit, or whose
   ancestors were not kept, are evicted. Ties resolve by cluster and linearization order.
6. Require the incoming transaction to pay the evicted transactions' modified fees plus its own
   incremental relay cost, and strictly improve the mempool's feerate diagram. Direct conflicts
   are charged once through the ordinary rules. All remaining admission checks still apply.

The kept set is ancestor-closed, so the evicted set is descendant-closed in the mempool that
remains after the direct conflicts are removed, and the incoming transaction's cluster is a
subset of the pinned and kept transactions, which fit by construction.
The limit check is still performed after staging. Fee requirements and the diagram check can
still prevent acceptance; this is a structural remedy, not a guarantee that every bump succeeds.

Supported uses include enlarging an RBF transaction when another branch occupies the remaining
cluster space, CPFP from a saturated ancestor cluster, and merging clusters with multiple
unconfirmed inputs. The incoming transaction need not double-spend an existing transaction.
Ordinary acceptance that fits the limits never triggers extra evictions. TRUC's existing sibling
eviction rules remain in place.

The fallback is available to individual transactions, including single-transaction
`testmempoolaccept` and transactions accepted individually during `submitpackage`. It does not
extend atomic package RBF or multi-transaction `testmempoolaccept`, and is disabled during reorg
admission that bypasses policy limits. Transactions evicted this way are reported as replaced,
although they remain valid and may re-enter the mempool later.

### Work bounds and tradeoffs

Ordinary replacement work, including descendant collection for direct conflicts under Rule 5,
happens first. When cluster limits then fail, the order is: the combined affected-cluster count
(parents' and direct conflicts' clusters, at most 100); the incoming transaction's ancestor set,
one union query bounded by the cluster count limit; the pinned-fit check; and only then cluster
traversal. A child of a full chain is therefore rejected without reading any cluster. With
default limits at most 63 parents' clusters can be traversed, since more pinned ancestors cannot
fit.

Selection reads each traversed cluster once in its existing linearization order and queries each
candidate's in-mempool ancestors, which are bounded by the cluster count limit rather than by
input counts. Each ancestor pair costs a binary search within its cluster. Chunking, unit
dependency counting and the greedy fill are near-linear in candidates and ancestor pairs. Main
graph queries may perform deferred linearization work, as any replacement can. No linearization
of the incoming transaction's cluster is computed by the selector, no descendant searches are
performed, and the feerate diagram is compared exactly once per proposal, after the fee check.

This work is performed before any fee is paid and is repeatable with distinct transactions. It is
bounded by the cluster caps but is larger than ordinary conflict collection: with default limits
a deliberately constructed replacement spending outputs of 63 full chains costs a few
milliseconds of selection, roughly three times the cost of collecting 6,400 descendants for a
100-conflict replacement, whereas the common single-cluster case costs tens of microseconds.

The selection is a greedy fit, not an optimal one, and a separate conservative heuristic inspired
by the reorg trimming rule rather than a reuse of it. Chunks of the candidates' own linearization
are a proxy for their value once the pinned ancestors are paid for separately; a chunk may be
disconnected after pinned entries are skipped and is still kept or evicted as one. A transaction
can therefore be evicted when a smaller or cheaper set would have sufficed.

Rejections for insufficient fee, including sibling eviction, are reconsiderable: a peer may retry
the transaction as part of a package, although atomic multi-transaction admission cannot use this
fallback and will fail on cluster limits. Eviction closure statements above are relative to the
mempool after the direct conflicts and their descendants are removed.

## History

* Opt-in full replace-by-fee (without inherited signaling) honoured in mempool and mining as of
  **v0.12.0** ([PR 6871](https://github.com/bitcoin/bitcoin/pull/6871)).

* [BIP125](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki) defined based on
  Bitcoin Core implementation.

* The incremental relay feerate used to calculate the required additional fees is distinct from
  `-minrelaytxfee` and configurable using `-incrementalrelayfee`
  ([PR #9380](https://github.com/bitcoin/bitcoin/pull/9380)).

* RBF enabled by default in the wallet GUI as of **v0.18.1** ([PR
  #11605](https://github.com/bitcoin/bitcoin/pull/11605)).

* Full replace-by-fee enabled as a configurable mempool policy as of **v24.0** ([PR
  #25353](https://github.com/bitcoin/bitcoin/pull/25353)).

* Full replace-by-fee is the default policy as of **v28.0** ([PR #30493](https://github.com/bitcoin/bitcoin/pull/30493)).

* Signaling for replace-by-fee is no longer required as of [PR 30592](https://github.com/bitcoin/bitcoin/pull/30592).

* The incremental relay feerate default is 0.1sat/vB ([PR #33106](https://github.com/bitcoin/bitcoin/pull/33106)).

* Feerate diagram policy enabled in conjunction with switch to cluster mempool as of **v31.0**.
