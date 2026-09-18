# soak: cross-runtime DefraDB soak driver

One binary that boots a mixed Go/Rust DefraDB mesh through `defra-harness`,
drives a seeded workload against it, keeps checking that the runtimes
converge, injects restarts and crashes on a seeded schedule, meters disk and
memory, and writes one replayable artifact directory per run.

Status: M1b (two Rust nodes on regolith + two Go nodes on badger, on this
host, as processes, in a full replicator mesh; `p1-encrypted` profile:
encrypted fields + searchable-encryption index, checker M5). The design and
roadmap live in the agent-ops vault under `Worklogs/cross-defra/soak-harness/`.

## Prerequisites

- A built Rust `defra` (release recommended: `cargo build --release -p cli`
  in defradb.rs), passed as `DEFRA_RUST_BINARY`.
- The Go `defradb` built at `GO_COMPAT_COMMIT` (see
  `crates/defra-version/src/lib.rs` in defradb.rs) on `PATH`, with
  `DEFRA_GO_COMPAT_COMMIT` set to that commit.
- `identity new` is run on both binaries at setup for `--profile p1-encrypted`,
  and on the Rust binary for the owner/reader of `--profile p2-acp`.

```sh
export DEFRA_RUST_BINARY=~/Repos/Source/defradb.rs/target/release/defra
export PATH=~/.cache/defra-harness/v1.1.0:$PATH DEFRA_GO_COMPAT_COMMIT=v1.1.0
cargo run -p soak -- run --seed 42 --ops 1800 --rate 3 --churn
```

### ACP profile

`--profile p2-acp` builds the cluster with local document ACP. Setup
generates two identities (`owner`, `reader`) with the Rust binary and
records them (key hex and DID) under `identities` in the manifest, so a
p2-acp `manifest.json` holds the two private keys in cleartext (throwaway
per-run identities, but do not paste a p2-acp manifest into an issue or
chat); the owner adds `USER_ACP_POLICY` on every node (the policy ids must agree
across runtimes or setup fails) and then the `User` schema bound to it,
and a bearer-token probe against rust-0 and go-0 must pass before the
workload starts. Creates of protected docs and all queries go over HTTP
with a bearer token for the op's actor; `grant` ops run the origin node's
own CLI (`--url host:port client -i <owner> acp document relationship add
... -r reader`) because the HTTP API has no relationship endpoint. Query
ops read the doc as owner, reader and anonymous and record the result as
`views owner= reader= anon=` in `ops.jsonl`. The checker sweeps as the
owner, and M6 compares the three views of every protected doc across each
node pair; a pair where exactly one side is the doc's origin node is
skipped and counted as `m6_by_design` (local ACP gates only there).

Both nodes get a file keyring so their peer identities survive restarts.
The nodes' data and logs are kept under the run directory (the driver points
`DEFRA_WORKSPACE_ROOT` there and sets `DEFRA_E2E_KEEP=1`).

## Commands

| Command | What it does |
|---|---|
| `soak run [flags]` | A new run under `runs/<unix-secs>-<seed>/`. |
| `soak replay --manifest <run>/manifest.json [--until-op N] [--hold]` | Rebuilds a run from its manifest: same seed, profile, executed op count and churn schedule, no disk budget. `--until-op` stops the workload early; `--hold` keeps the mesh up until Enter, printing each node's GraphQL URL. |
| `soak summarize <run dir>` | Rewrites `profile.json` / `profile.md` from the artifact and prints the markdown. |
| `soak compare <run A> <run B>` | Checks two runs against the replay contract; exits non-zero if they differ. |
| `soak manage --topology <n>r0g --out <dir> [--cases R2,A2,S1]` | Pass/fail cases on the P2P management channel, see "Management channel". |

`run` flags (all optional):

| Flag | Default | Meaning |
|---|---|---|
| `--seed N` | unix time | Master seed; both axes derive from it. |
| `--profile NAME` | p0-crud | Workload profile: `p0-crud` (plaintext Users), `p0-size` (p0-crud with a within-run payload-size mix: 256/1,200/16,000/128,000 bytes weighted 40/30/20/10; mixed-size correctness, not a disk decomposition), `p0-size-256` / `p0-size-128k` (p0-crud at a fixed create size, for one-term disk comparison against a same-day `p0-crud` run), `p0-index` (p0-crud with `@index` on `age`; the planned GraphQL is byte-identical to p0-crud at the same seed), `p3-relation` (one-to-many Author/Book; child creates use `author: "<parent docID>"` resolved from a parent slot), `p1-encrypted` (Vault with encrypted secret/pin and an SE index on name; builds the cluster with encryption, dev mode, per-node identities and a shared SE key), `p1-unique` (p1 with a unique name per document instead of the 40-name pool, so an SE query matches exactly one document: it separates the searchable-encryption first-responder misses from the "many documents per name" query shape; run 307 remains the colliding-name result) or `p2-acp` (User under a local ACP policy with owner/reader identities, see "ACP profile"). |
| `--create-nodes 0,1` | all nodes | Node indices that receive create ops (0,1 Rust; 2,3 Go); other ops still go to any node. Recorded in the manifest. |
| `--ops N` | 200 | Ops to plan and execute. |
| `--secs S` | none | Wall deadline; stops the workload first if hit. |
| `--rate R` | 20 | Profile rate, ops/s mesh-wide, and the virtual clock (`virtual_ts = index / rate`). ~3 is sustainable for 1R+1G on a MacBook. |
| `--churn` | off | Enable the seeded restart / crash-kill / graceful-leave schedule. |
| `--churn-spacing S` | 120 | Mean seconds between events and per-node cooldown. |
| `--grace S` | 120 | Mismatches younger than this, or within this long after a node came back, are in-flight sync, not divergence. Covers two failed pushes on the runtimes' 30/60/120s retry ladder. |
| `--settle S` | 120 | After the workload, keep checking this long for an eligible clear check before the final sweep. |
| `--min-settle S` | 0 | Settle at least this long even once the mesh is clear. The default ends the settle on the first clear check, often seconds after the last op, so a run has no sample of an idle mesh: `du` and RSS stop at the load. Set it to get an idle tail; the meter samples throughout. |
| `--ceiling-mb MB` | 122880 | Disk ceiling over all node data dirs; hard stop at 95%. |
| `--floor-rate R` | 0.5 | The governor never throttles below this. |
| `--meter-secs S` | 60 | du / RSS sampling and governor interval. |
| `--control` | off | Positive control: a `Control` collection replicated rust-0 -> go-0 only, written on go-0, must produce divergences on the pairs that predicts and nothing on `Users`. |
| `--retry-intervals 5,10,20,40` | runtime default | Both runtimes' `--replicator-retry-intervals`, on both backends; recorded in the manifest since it changes the system under test. Without it an outage longer than the first 30 s rung is timed by the sender's next dial, not by replication, so recovery numbers are ladder-confounded and the two runtimes are not comparable across that gap. |
| `--node-env KEY=VALUE` | none | Repeatable. Set on every node, both backends (docker `-e`, process inherited from the driver) and both runtimes, and recorded in `manifest.caps.node_env` so a run's log level is auditable. Only validation is the `=`. The Rust partition-tail lines (`dag_fetcher.rs` "Attempt stall budget exhausted", `swarm.rs` "Closing redundant connection", `retry.rs` "Activated durable push markers") are DEBUG, so no existing run contains them: `--node-env RUST_LOG=debug`. |
| `--no-subscribe` | off | Skip the collection subscribe (`p2p_collection_add`), leaving the replicators as the only delivery path. By default every node both subscribes to the collection topic and has a replicator to every other node, so gossip delivers whatever a replicator push loses and a broken push is invisible. Use it to measure the replicator alone. |
| `--sse-go` | off | Open subscriptions on Go nodes too (reproduces the Go memory growth). |
| `--nodes process\|docker` | process | `docker` runs the M2 six-node topology (rust-0, rust-1, go-0 on host A; rust-2, go-1, go-2 on host B) as containers on a `soak-<run_id>` network, see "Docker backend". Recorded per node in the manifest (`backend`) and honoured by `replay`. |
| `--reuse-network` | off | Start even though a `soak-*` network is left over from an earlier run. |
| `--topology <n>r<m>g` | backend default | Mesh shape: `n` Rust nodes, then `m` Go nodes. Either count may be zero, so `4r0g` and `0r4g` are the single-runtime controls for a mixed run. Recorded in the manifest and honoured by `replay`. Without it each backend keeps the shape every published run used: the M2 six in containers, two of each as processes. Node **order is Rust first**, so `--create-nodes 0,1` means the first two Rust nodes at `2r2g` but the first two Go nodes at `0r4g`. |

### Docker backend

`--nodes docker` needs the images `soak-defra:8d8bb299f` (Rust) and
`soak-defradb:$DEFRA_GO_COMPAT_COMMIT` (Go) on the docker host, so the Go
image and the host `defradb` always name the same version; build the Go
image locally for that version, e.g. for v1.1.0, from a defradb clone at
the tag: `docker build --platform linux/arm64 -f tools/defradb.containerfile
--build-arg VERSION=v1.1.0 -t soak-defradb:v1.1.0 <clone at the tag>`. It
also needs `DEFRA_RUST_BINARY` and the Go `defradb` on `PATH` as before
(the driver's CLI calls run on the host against each container's published
API port), and the docker CLI pointed at the host, e.g.
`DOCKER_CONTEXT=orbstack`. The encrypted and ACP profiles refuse the
backend; plaintext profiles (`p0-crud`, `p0-size`, `p0-size-256`, `p0-size-128k`,
`p0-index`, `p3-relation`) run in containers, but 128 KB payloads have never
been exercised through the container path.

```sh
export DOCKER_CONTEXT=orbstack
cargo run -p soak -- run --nodes docker --seed 611 --ops 300 --rate 3
```

Each container mounts `<run dir>/target/docker/<name>` at `/data`, so the
node data stay in the artifact and `docker logs` are flushed to
`<name>/logs/{stdout,stderr}.log` before every log rotation and before
teardown. The run removes its containers and network at the end, on error
too. A run that
was killed leaves them behind, and the next `soak run` refuses to start
while any `soak-*` network exists: remove them (`docker rm -f $(docker ps
-aq --filter name=soak-)`, then `docker network rm soak-<run_id>`) or pass
`--reuse-network`.

## Artifact

```
runs/<unix-secs>-<seed>/
  manifest.json      seed, profile, ops, nodes (store, peer id, backend, image, ip, host), both binaries' version
                     JSON, churn config + planned schedule, caps; at the end ops_executed,
                     stopped_by (ops | secs | budget | until_op) and the checker totals
  ops.jsonl          one record per executed op
  topology.jsonl     churn events as executed: down/up per event, planned vs actual
                     virtual time, wall time, peer id after recovery
  checks.jsonl       every checker pass: status, mismatch/pending/confirmed counts, eligibility
  divergences.jsonl  confirmed divergences (see below), with the pair and per-doc tags
  final_sweep.jsonl  every mismatch of the final full sweep, confirmed or not, with its tag
  lag.jsonl          convergence lag samples per create, by directed pair; source sse or poll
  du.jsonl rss.jsonl budget.jsonl   meter samples and governor decisions
  profile.json/.md   the per-runtime behaviour profile
  target/e2e/<stamp>/{rust-0,rust-1,go-0,go-1}/{data,logs}   node data dirs and stdout/stderr
                     (logs rotated to *.before-event-N before a restart)
  target/docker/<name>/{data,logs}   the same for --nodes docker
```

## How it works

**Generator (axis 1).** `Profile::p0_crud` is a weight table (create 30,
update 40, delete 5, query 25, ~1.2 KiB docs). The op stream is a pure
function of `(seed, profile, node count)`: execution outcomes never feed
back. Update/delete victims are ledger *slots* in creation order; the
executor maps slots to the docIDs it learned from `add_X` replies. A victim
whose create failed (its node was down) is logged as `skipped`, not as an
error. An update or delete whose docID the target node does not hold yet
(replication lag) gets an empty reply from both runtimes; it is logged as
failed with `no doc matched on this node`. Floats are generated with at most 8 significant digits, under the
15-digit roundtrip ceiling.

**Executor.** Every op is one HTTP GraphQL POST to its target node. The
executor is sequential, so throughput is capped at 1 / (average latency);
Rust writes take ~250 ms on regolith, so ~3 ops/s is the practical ceiling
for one Rust node today.

**Checker.** One task for the whole mesh. Every `interval` (10 s): each
collection's docID set is fetched once per node and diffed for every pair
(M1); head CIDs via alias-batched `_commits(docID: ..., depth: 1)` are
fetched once per node over docs touched since the last check plus a cold
sample of 50 and diffed per pair (M3). For `p1-encrypted` the same targets
are also read as plaintext (`filter: {_docID: {_in: [..]}}`) per node and
compared per pair (M5); a null or empty encrypted field on one side only is
recorded as `undecryptable_on`. A mismatch becomes a divergence
record only after it persisted across 3 consecutive checks spanning at
least `grace`; the record names the pair and carries the op range and node
down/up transitions since the last clear check. A pair is eligible when
both members are up and past `grace` since their last recovery; mismatches
on ineligible pairs are logged as `expected` and their pending state is
frozen, neither counted nor cleared. Each divergent doc gets a known-cause
tag when its last write happened while a pair member was down
(`write-during-outage`) or within 30 s of the writer's or a member's
recovery (`write-during-recovery`); the summary's alarm line is the
count of untagged docs. After the workload the
checker settles (checks until a fully clear, fully eligible check or
`--settle` runs out), then sweeps M3 over every shared doc. The summary reports records
written, how many are still present at the final sweep, and the final
sweep's own mismatch count, so a backlog that drains is distinguishable
from a real split.

**Churner (axis 2).** The schedule is drawn at start from the topology
stream: mean spacing, per-node cooldown, kinds drawn uniformly (restart,
crash-kill, graceful leave, and partition on `--nodes docker`), down-time
in 5..30 s. Events fire on wall time from workload start (polled every
250 ms), and the schedule covers the shorter of the op budget and the
`--secs` deadline; manifests without a `churn.config.clock` replay on
virtual time (op progress) as they ran. `topology.jsonl` records planned and actual
clock time. `restart` is the harness's SIGTERM path (same ports, health gate);
`crash_kill` is SIGKILL, a wall-time pause, respawn, then a GraphQL health
poll; `graceful_leave` is the harness's stop (SIGTERM, ports held), a
wall-time pause, then its start on the same ports; `partition` is a docker
network disconnect, a wall-time pause, then connect (the API port goes
with the network, so the driver sees a crash-kill and the `rejoin` record
carries the re-read `p2p_addr`). Down-time is wall time so a stalled workload cannot leave a node
dead. The churner shares the driver task with the workload (the harness
restart future is not `Send`).

**Meter and governor.** From the churner task (it holds the cluster): `du`
of each data dir and the process RSS. Amplification is the cumulative
mesh-wide bytes grown per executed op since the first sample. The governor
sets the op rate that would spend the remaining budget exactly by the
deadline (op-count runs derive one from the remaining ops at the profile
rate), clamped to `[floor, profile rate]`, and raises the hard stop at 95%
of the ceiling; the stop is evaluated per sample, so it can overshoot by one
interval's growth.

**Subscriptions.** One `subscription { Users { _docID } }` is kept open per
Rust node over the GraphQL POST endpoint with `Accept: text/event-stream`,
reconnecting after a restart (`--sse-go` opens them on Go nodes too). Arrivals mark docs recent for M3, give lag
samples at event time (`source: sse`), and 5 s of silence after any event
triggers a check ahead of the clock. Go's subscription fires only for the
node's own mutations, not for remote merges, so event-time lag exists only
into Rust nodes and quiescence triggering is partial; the clock is the
trigger that matters.

**Replay contract.** What `compare` checks: for each op index the planned
fields (`virtual_ts_ms`, `node`, `kind`, `collection`) are identical, the
churn schedules are identical, and docIDs agree wherever both runs learned
one (content-addressed docIDs make payload regeneration exact). Outcomes,
error text, latency and wall time are not part of the contract: crash
down-windows are wall time, so ops at their edges may fail in one run and
succeed in the other.

## Reading a run

- `divergence records: N, still present at final sweep: K` with `final
  sweep: 0 mismatches (eligible)` means every confirmed mismatch healed:
  lag, not a split. Look at `checks.jsonl` for the backlog shape and at
  `lag.jsonl` for the direction.
- A non-zero final sweep with `eligible` is the headline; `final_sweep.jsonl`
  names the docs, pairs, sides and tags, and `profile.md` classifies each by
  the last write versus the outage windows.
- `divergent docs: N tagged, M UNTAGGED` is the alarm line: tagged docs are
  the known write-during-outage loss; untagged ones need a look.
- Counts are record-doc slots unless the line says `unique`: a doc missing on
  one node is one row per pair that node belongs to, so `1277 record-doc
  slots` can be `259 unique docs`. The `final sweep:` line and the `loss`
  tables are unique documents.
- `sampled_pending` is what that pass happened to look at (recent docs plus a
  cold sample of 50), not the size of the backlog.
- Convergence lag is in ms and split by `source`: `poll` is bounded below by
  the 10 s checker interval, `sse` is event time. The `*->rust` / `*->go`
  rows are by receiving runtime. Creates that never arrived have no sample at
  all and are listed as unseen under the table, not as a fast percentile.
- `bytes_grown_per_mesh_write` divides one node's growth by the whole mesh's
  successful writes: it is replication amplification, not that node's writes.
- On the docker backend the memory heading says `docker stats MemUsage`; the
  values are whatever `docker stats` printed for the container, not `ps` RSS
  of one process.
- The `loss` tables count creates made by some other node while a node was
  down and still missing on it at the final sweep. `[down,up]` is the strict
  window; `[down,up+30s]` adds the recovery window, since a node answers
  GraphQL before its replicator link is back.
- `NOT eligible` on the final sweep means a node was down or in grace at the
  end; lengthen `--settle`.

Known runtime behaviours met while building M0 (Rust `ba6dac661`, Go
`53f0e76a3`, macOS arm64):

- Rust HTTP writes take ~250 ms (create/update/delete) against Go's ~3 ms;
  debug and release builds alike. Queries are ~1-3 ms on both.
- Disk: ~8.4 KB per write op on rust-0/regolith vs ~5.8 KB on go-0/badger,
  engine-inclusive. Max RSS ~107 MB vs ~238 MB.
- Go -> Rust pushes fail under load (Rust's DAG block fetches from Go time
  out and back off; Rust rejects re-pushes of an in-flight CID) and Go
  retries on its 30/60/120/240 s ladder, so single docs took 20 s to 7 min
  to converge at 3 ops/s. That is why `--grace` defaults to 120 s.
- Without a file keyring a Go node comes back from every restart as a new
  peer ID and the Rust replicator never reconnects to it; the driver uses
  `TestClusterBuilder::with_file_keyring()`.
- A create, update or delete made on either node while its peer is
  crash-killed, or within seconds of a node's recovery, is never replicated
  afterwards (the write-during-outage tag). Unchanged by the retry ladder.
- With four nodes in a full mesh, every direction converges in 4-8 s median;
  the 55 s Go-to-Rust median of a single pair does not appear.
- Go's GraphQL subscriptions do not fire for remote merges, and a Go node
  with one open grows by roughly 200 MB of resident memory per minute at
  3 ops/s until it restarts (7.8 GB after 30 minutes); Rust nodes do not.
  That is why the driver subscribes on Rust nodes only.

### Topology

`--topology <n>r<m>g` sets the mesh size and runtime mix. Nodes are named
`rust-0..rust-<n-1>` then `go-0..go-<m-1>`, and each runtime's nodes alternate
between the two partition sides so neither side is single-runtime.

```sh
soak run --topology 2r2g      # two of each, the published process shape
soak run --topology 4r0g      # all-Rust control
soak run --topology 0r4g      # all-Go control
soak run --topology 6r2g      # asymmetric
```

A single-runtime mesh skips the steps that need a node of each kind and says
so: the `--control` wiring, and the `p2-acp` token probe against the absent
runtime. `p2-acp` itself needs a Rust node, because it mints identities with
the Rust CLI.

One cost grows sharply with the mesh, and it is not the checker. The checker
reads each node once per pass and compares the unordered pairs in memory, so
its HTTP cost is linear in nodes. `profile.md`, though, prints one row per
*directed* pair: 12 rows at four nodes, 30 at six, 380 at twenty, which stops
being readable well before that. Node memory is the real ceiling. Size the run
to the host.

## Management channel

`soak manage` is a minutes-long evaluation of `POST /api/v0/p2p/manage`: the
caller hits one Rust node's HTTP API (the relay) with a JWT whose `aud` is
the target's peer id, and the relay carries the op over P2P to the target,
which authorizes the actor against NAC before applying it.

```sh
DEFRA_RUST_BINARY=<defradb.rs>/target/debug/defra \
  soak manage --topology 2r0g --cases R2,A2,S1 --out runs/manage-1
```

The cluster is the `run` mesh with NAC enabled (`--node-acp-enable` and a
startup identity, which is the NAC owner and the HTTP courier at every
relay). Every node gets the `User` schema, peer connections and a replicator
to every other node, all as the owner. Three actors are generated and granted
on every node through `acp node relationship add`: `admin` (the `admin`
relation), `operator` (`add-p2p-collection` and `list-p2p-replicator` only),
`outsider` (nothing).

Cases live by group in `src/manage/{routing,authz,state,bounds,partition}.rs`,
the table and runner in `cases.rs`; each restores what it changed. `--cases`
selects by name in table order, default all but B3, which locates the
libp2p request size bound by bisection and runs under `--locate-size-bound`
(or by name) on its own; a case whose topology requirement the mesh cannot
host is skipped, not failed. Outcomes: `Pass`, `Fail { expected, got }`,
`Skip { reason }`, `Infra { error }` (a harness fault, never a product
finding). `--out` receives `manifest.json` (nodes, peer ids, actors in
cleartext like `run`), `summary.json` (per case: outcome, notes a case
recorded, every relayed op with status and latency, and the target's list for
that op's family after each mutate) and `cases.md`. `--docker` is not
supported yet, so P1 (partition) skips.

## Not yet

A second machine, per-pair partitions, link degradation (tc/netem),
relations / secondary indexes / lens, node-internal telemetry (otel), a
concurrent executor, M1 sweep scoping, tag rules for anything but the
outage loss.
