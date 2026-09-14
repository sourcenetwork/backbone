# soak: cross-runtime DefraDB soak driver

One binary that boots a mixed Go/Rust DefraDB mesh through `defra-harness`,
drives a seeded workload against it, keeps checking that the runtimes
converge, injects restarts and crashes on a seeded schedule, meters disk and
memory, and writes one replayable artifact directory per run.

Status: M0 skeleton (one Rust node on regolith + one Go node on badger, on
this host, as processes). The design and roadmap live in the agent-ops vault
under `Worklogs/cross-defra/soak-harness/`.

## Prerequisites

- A built Rust `defra` (release recommended: `cargo build --release -p cli`
  in defradb.rs), passed as `DEFRA_RUST_BINARY`.
- The Go `defradb` built at `GO_COMPAT_COMMIT` (see
  `crates/defra-version/src/lib.rs` in defradb.rs) on `PATH`, with
  `DEFRA_GO_COMPAT_COMMIT` set to that commit.

```sh
export DEFRA_RUST_BINARY=~/Repos/Source/defradb.rs/target/release/defra
export PATH=~/.cache/defra-harness/53f0e76a3:$PATH DEFRA_GO_COMPAT_COMMIT=53f0e76a3
cargo run -p soak -- run --seed 42 --ops 1800 --rate 3 --churn
```

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

`run` flags (all optional):

| Flag | Default | Meaning |
|---|---|---|
| `--seed N` | unix time | Master seed; both axes derive from it. |
| `--ops N` | 200 | Ops to plan and execute. |
| `--secs S` | none | Wall deadline; stops the workload first if hit. |
| `--rate R` | 20 | Profile rate, ops/s mesh-wide, and the virtual clock (`virtual_ts = index / rate`). ~3 is sustainable for 1R+1G on a MacBook. |
| `--churn` | off | Enable the seeded restart / crash-kill schedule. |
| `--churn-spacing S` | 120 | Mean seconds between events and per-node cooldown. |
| `--grace S` | 120 | Mismatches younger than this, or within this long after a node came back, are in-flight sync, not divergence. Covers two failed pushes on the runtimes' 30/60/120s retry ladder. |
| `--settle S` | 120 | After the workload, keep checking this long for an eligible clear check before the final sweep. |
| `--ceiling-mb MB` | 122880 | Disk ceiling over all node data dirs; hard stop at 95%. |
| `--floor-rate R` | 0.5 | The governor never throttles below this. |
| `--meter-secs S` | 60 | du / RSS sampling and governor interval. |
| `--control` | off | Positive control: a `Control` collection replicated Rust -> Go only, written on Go, must produce one M1 and one M3 divergence. |

## Artifact

```
runs/<unix-secs>-<seed>/
  manifest.json      seed, profile, ops, nodes (store, peer id), both binaries' version
                     JSON, churn config + planned schedule, caps; at the end ops_executed,
                     stopped_by (ops | secs | budget | until_op) and the checker totals
  ops.jsonl          one record per executed op
  topology.jsonl     churn events as executed: down/up per event, planned vs actual
                     virtual time, wall time, peer id after recovery
  checks.jsonl       every checker pass: status, mismatch/pending/confirmed counts, eligibility
  divergences.jsonl  confirmed divergences (see below)
  final_sweep.jsonl  every mismatch of the final full sweep, confirmed or not
  lag.jsonl          convergence lag samples per create, by direction
  du.jsonl rss.jsonl budget.jsonl   meter samples and governor decisions
  profile.json/.md   the per-runtime behaviour profile
  target/e2e/<stamp>/{rust-0,go-0}/{data,logs}   node data dirs and stdout/stderr
                     (logs rotated to *.before-event-N before a restart)
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

**Checker.** One task per node pair. Every `interval` (10 s): M1 docID-set
diff over each collection (one POST per node), then M3 head-CID diff via
alias-batched `_commits(docID: ..., depth: 1)` over docs touched since the
last check plus a cold sample of 50. A mismatch becomes a divergence record
only after it persisted across 3 consecutive checks spanning at least
`grace`; the record's `event_window` carries the op range and the node
down/up transitions since the last clear check. While a node is down, or for `grace` after it came back, mismatches
are logged as `expected` and skip confirmation. After the workload the
checker settles (checks until an eligible clear check or `--settle` runs
out), then sweeps M3 over every shared doc. The summary reports records
written, how many are still present at the final sweep, and the final
sweep's own mismatch count, so a backlog that drains is distinguishable
from a real split.

**Churner (axis 2).** The schedule is drawn at start from the topology
stream: mean spacing, per-node cooldown, three kinds drawn uniformly
(restart, crash-kill, graceful leave), down-time in 5..30 s. Events
fire on virtual time (op progress, polled every 250 ms), so a replay fires
them within a few ops of the same index; `topology.jsonl` records planned
and actual virtual time. `restart` is the harness's SIGTERM path (same ports, health gate);
`crash_kill` is SIGKILL, a wall-time pause, respawn, then a GraphQL health
poll; `graceful_leave` is the harness's stop (SIGTERM, ports held), a
wall-time pause, then its start on the same ports. Down-time is wall time so a stalled workload cannot leave a node
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
  names the docs and sides.
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

## Not in M0

Containers, a second machine, network partitions, subscriptions and SSE
quiescence, encryption / ACP / relations / indexes / lens, node-internal
telemetry, known-issue tag rules (the `tags` field is always empty), a
concurrent executor, M1 sweep scoping, more than one pair.
