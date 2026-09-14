//! `soak`: cross-runtime DefraDB soak driver (M0 skeleton).
//!
//! Boots a mixed Go/Rust mesh through `defra-harness`, drives a seeded
//! workload, checks convergence between the runtimes, and writes a replayable
//! run artifact under `runs/<unix-secs>-<seed>/`.
//!
//! ```text
//! soak run [--seed N] [--ops N] [--secs S] [--rate OPS_PER_SEC] [--control]
//!          [--churn [--churn-spacing SECS]] [--grace SECS] [--settle SECS]
//!          [--ceiling-mb MB] [--floor-rate R] [--meter-secs S]
//!          [--retry-intervals 5,10,20,40] [--until-op N] [--hold]
//! soak replay --manifest <run>/manifest.json [--until-op N] [--hold]
//!             [--grace SECS] [--settle SECS]
//! soak summarize <run dir>
//! soak compare <run dir A> <run dir B>
//! ```
//! Env: `DEFRA_RUST_BINARY` (built `defra`), Go `defradb` on PATH with
//! `DEFRA_GO_COMPAT_COMMIT` set.
//!
//! `--control` adds a `Control` collection replicated Rust -> Go only and
//! writes to the Go side, so the checker must report M1 and M3 divergences
//! on it (the positive control). `--churn` enables the seeded restart /
//! crash-kill schedule. `replay` rebuilds a run from its manifest: same
//! seed, profile, executed op count and churn schedule, no disk budget;
//! `--until-op` stops the workload early and `--hold` keeps the mesh up for
//! inspection until Enter. `--retry-intervals` sets both runtimes'
//! `--replicator-retry-intervals` (default ladder 30,60,120,240,480,960,1920
//! s) and is recorded in the manifest, since it changes the system under
//! test. `compare` checks two runs against the replay
//! contract: planned op fields and the churn schedule, plus docIDs where
//! both runs have one; outcomes and timing are not part of it.

mod checker;
mod churn;
mod confirm;
mod executor;
mod generator;
mod meter;
mod summary;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use defra_harness::{extract_p2p_addr, TestCluster};
use eyre::{eyre, Result, WrapErr};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use checker::{Checker, CheckerConfig, Touch};
use churn::ChurnConfig;
use executor::{gql, now_ms, Executor};
use generator::{Generator, OpKind, Profile};
use meter::{Meter, MeterConfig};

const SCHEMA: &str = "type Users { name: String age: Int score: Float blob: String }";
const CONTROL: &str = "Control";
const CONTROL_SCHEMA: &str = "type Control { v: Int }";
const RUST: usize = 0;
const GO: usize = 1;
/// Durable store per node index; the Rust cli has no other durable engine
/// and Go has only badger.
const STORES: [&str; 2] = ["regolith", "badger"];

/// Everything a run needs; `replay` rebuilds it from a manifest.
struct RunArgs {
    seed: u64,
    ops: usize,
    secs: Option<u64>,
    profile: Profile,
    control: bool,
    churn: Option<ChurnConfig>,
    grace: Duration,
    settle: Duration,
    ceiling_bytes: u64,
    floor_rate: f64,
    meter_interval: Duration,
    until_op: Option<u64>,
    hold: bool,
    replay_of: Option<String>,
    /// Comma-separated seconds for both nodes' replicator retry ladder.
    retry_intervals: Option<String>,
}

impl RunArgs {
    fn from_flags() -> Result<Self> {
        let mut profile = Profile::p0_crud();
        if let Some(rate) = flag("rate") {
            profile.rate = rate.parse().wrap_err("--rate must be a number")?;
        }
        let mut churn = has_flag("churn").then(ChurnConfig::default);
        if let (Some(cfg), Some(secs)) = (churn.as_mut(), flag("churn-spacing")) {
            let ms = secs
                .parse::<u64>()
                .wrap_err("--churn-spacing must be seconds")?
                * 1000;
            cfg.spacing_ms = ms;
            cfg.cooldown_ms = ms;
        }
        let checker = CheckerConfig::default();
        Ok(Self {
            seed: parse_flag("seed", unix_secs())?,
            ops: parse_flag("ops", 200)?,
            secs: opt_flag("secs")?,
            profile,
            control: has_flag("control"),
            churn,
            grace: Duration::from_secs(parse_flag("grace", checker.grace.as_secs())?),
            settle: Duration::from_secs(parse_flag("settle", checker.settle.as_secs())?),
            ceiling_bytes: (parse_flag::<f64>("ceiling-mb", 120.0 * 1024.0)? * 1_048_576.0) as u64,
            floor_rate: parse_flag("floor-rate", 0.5)?,
            meter_interval: Duration::from_secs(parse_flag("meter-secs", 60)?),
            until_op: opt_flag("until-op")?,
            hold: has_flag("hold"),
            replay_of: None,
            retry_intervals: flag("retry-intervals"),
        })
    }

    /// The original run's parameters. `ops` stays the planned count so the
    /// churn schedule's horizon is identical; the workload stops at the
    /// original's executed count via `until_op`, and the disk budget is off.
    fn from_manifest(path: &Path) -> Result<Self> {
        let m: Value = serde_json::from_str(
            &std::fs::read_to_string(path)
                .wrap_err_with(|| format!("reading {}", path.display()))?,
        )?;
        let caps = &m["caps"];
        let churn = match m["churn"]["config"].as_object() {
            Some(_) => Some(serde_json::from_value(m["churn"]["config"].clone())?),
            None => None,
        };
        Ok(Self {
            seed: m["seed"]
                .as_u64()
                .ok_or_else(|| eyre!("manifest has no seed"))?,
            ops: m["ops"]
                .as_u64()
                .ok_or_else(|| eyre!("manifest has no ops"))? as usize,
            secs: None,
            profile: serde_json::from_value(m["profile"].clone()).wrap_err("manifest profile")?,
            control: m["control"].as_bool().unwrap_or(false),
            churn,
            grace: Duration::from_secs(parse_flag(
                "grace",
                caps["grace_secs"].as_u64().unwrap_or(120),
            )?),
            settle: Duration::from_secs(parse_flag(
                "settle",
                caps["settle_secs"].as_u64().unwrap_or(120),
            )?),
            ceiling_bytes: u64::MAX / 2,
            floor_rate: caps["floor_rate"].as_f64().unwrap_or(0.5),
            meter_interval: Duration::from_secs(caps["meter_secs"].as_u64().unwrap_or(60)),
            until_op: opt_flag("until-op")?.or_else(|| m["ops_executed"].as_u64()),
            hold: has_flag("hold"),
            replay_of: m["run_id"].as_str().map(String::from),
            retry_intervals: caps["retry_intervals"].as_str().map(String::from),
        })
    }
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv
        .first()
        .map(String::as_str)
        .filter(|a| !a.starts_with("--"))
        .unwrap_or("run");
    match cmd {
        "summarize" => {
            let dir = argv
                .get(1)
                .ok_or_else(|| eyre!("usage: soak summarize <run dir>"))?;
            summary::write_profile(Path::new(dir))?;
            print!(
                "{}",
                std::fs::read_to_string(Path::new(dir).join("profile.md"))?
            );
            Ok(())
        }
        "compare" => {
            let (a, b) = match (argv.get(1), argv.get(2)) {
                (Some(a), Some(b)) => (a, b),
                _ => eyre::bail!("usage: soak compare <run dir A> <run dir B>"),
            };
            let report = summary::compare(Path::new(a), Path::new(b))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            eyre::ensure!(
                report["identical"] == json!(true) || report["prefix_identical"] == json!(true),
                "runs differ on the replay contract"
            );
            Ok(())
        }
        "run" | "replay" => {
            eyre::ensure!(
                std::env::var_os("DEFRA_RUST_BINARY").is_some(),
                "set DEFRA_RUST_BINARY to a built `defra` (e.g. <defradb.rs>/target/debug/defra)"
            );
            let args = if cmd == "replay" {
                let m = flag("manifest").ok_or_else(|| eyre!("replay needs --manifest <path>"))?;
                RunArgs::from_manifest(Path::new(&m))?
            } else {
                RunArgs::from_flags()?
            };
            let run_dir = new_run_dir(args.seed)?;
            // defra-harness puts node dirs under <workspace>/target/e2e and
            // deletes them on drop. Point the workspace at the run dir and
            // keep them so the artifact holds the node data and logs. Set
            // before any thread exists.
            std::env::set_var("DEFRA_WORKSPACE_ROOT", &run_dir);
            std::env::set_var("DEFRA_E2E_KEEP", "1");
            println!(
                "run dir: {}  seed: {}  ops: {}{}",
                run_dir.display(),
                args.seed,
                args.ops,
                args.replay_of
                    .as_deref()
                    .map(|r| format!("  (replay of {r})"))
                    .unwrap_or_default()
            );
            tokio::runtime::Runtime::new()?.block_on(run(&run_dir, args))
        }
        other => eyre::bail!("unknown command {other}; use run, replay, summarize or compare"),
    }
}

async fn run(run_dir: &Path, a: RunArgs) -> Result<()> {
    let mut builder = TestCluster::builder()
        .rust_nodes(1)
        .go_nodes(1)
        .with_p2p()
        // File keyrings so peer identities survive restarts: without one the
        // Rust node mints a new peer ID per start, and with only the Env
        // keyring so does the Go node; a replicator pointed at the old id
        // never reconnects.
        .with_file_keyring()
        .with_node_store(RUST, STORES[RUST])
        .with_node_store(GO, STORES[GO]);
    if let Some(intervals) = &a.retry_intervals {
        let flag = ["--replicator-retry-intervals", intervals.as_str()];
        builder = builder.with_extra_rust_args(flag).with_extra_go_args(flag);
        println!("replicator retry intervals on both nodes: {intervals}s");
    }
    let cluster = builder
        .build()
        .await
        .wrap_err("building the mixed cluster")?;
    for i in [RUST, GO] {
        println!(
            "{} at {} ({})",
            cluster.nodes[i].name,
            cluster.api_url(i),
            STORES[i]
        );
    }
    wire_bidirectional(&cluster, &a.profile.collection)?;
    preflight(&cluster, &a.profile.collection).await?;
    let mut collections = vec![a.profile.collection.clone()];
    if a.control {
        wire_control(&cluster).await?;
        collections.push(CONTROL.to_string());
    }

    let nodes: Vec<(String, String)> = (0..cluster.len())
        .map(|i| {
            (
                cluster.nodes[i].name.clone(),
                cluster.api_url(i).to_string(),
            )
        })
        .collect();
    let http = reqwest::Client::new();
    let mut peer_ids = Vec::new();
    for (name, url) in &nodes {
        let pid = churn::peer_id(&http, url).await;
        println!("{name} peer id: {}", pid.as_deref().unwrap_or("?"));
        peer_ids.push(pid);
    }
    let horizon_ms = churn::virtual_ms(a.ops as u64, a.profile.rate);
    let churn_events = a
        .churn
        .as_ref()
        .map(|cfg| churn::schedule(a.seed, nodes.len(), horizon_ms, cfg))
        .unwrap_or_default();
    for e in &churn_events {
        println!(
            "churn plan #{} at {}s: {:?} {} (down {}ms)",
            e.index,
            e.virtual_ts_ms / 1000,
            e.kind,
            nodes[e.node].0,
            e.down_ms
        );
    }
    let run_id = run_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rust_binary = std::env::var("DEFRA_RUST_BINARY").unwrap_or_default();
    let manifest_path = run_dir.join("manifest.json");
    let manifest = json!({
        "run_id": run_id,
        "replay_of": a.replay_of,
        "seed": a.seed,
        "ops": a.ops,
        "secs": a.secs,
        "profile": a.profile,
        "control": a.control,
        "nodes": nodes.iter().zip(STORES).zip(&peer_ids).map(|(((name, url), store), pid)| {
            json!({"name": name, "api_url": url, "store": store, "peer_id": pid})
        }).collect::<Vec<_>>(),
        "rust_binary": rust_binary,
        "rust_version": version_json(&rust_binary),
        "go_compat_commit": std::env::var("DEFRA_GO_COMPAT_COMMIT").unwrap_or_default(),
        "go_version": version_json("defradb"),
        "churn": a.churn.as_ref().map(|cfg| json!({"config": cfg, "schedule": churn_events})),
        "caps": {
            "ceiling_bytes": a.ceiling_bytes, "floor_rate": a.floor_rate,
            "meter_secs": a.meter_interval.as_secs(), "grace_secs": a.grace.as_secs(),
            "settle_secs": a.settle.as_secs(), "until_op": a.until_op,
            "retry_intervals": a.retry_intervals,
        },
        "started_wall_ts_ms": now_ms(),
    });
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    let op_index = Arc::new(AtomicU64::new(0));
    let rate_milli = Arc::new(AtomicU64::new((a.profile.rate * 1000.0) as u64));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let churn_failed = Arc::new(AtomicBool::new(false));
    let (touched_tx, touched_rx) = mpsc::unbounded_channel();
    let (transitions_tx, transitions_rx) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let (churn_stop_tx, churn_stop_rx) = oneshot::channel();
    let checker = Checker::new(
        [nodes[RUST].clone(), nodes[GO].clone()],
        collections,
        CheckerConfig {
            grace: a.grace,
            settle: a.settle,
            ..CheckerConfig::default()
        },
        a.seed,
        run_id.clone(),
        Arc::clone(&op_index),
        run_dir,
    )?;
    let checker_task = tokio::spawn(checker.run(touched_rx, transitions_rx, stop_rx));
    let meter = Meter::new(
        MeterConfig {
            interval: a.meter_interval,
            ceiling_bytes: a.ceiling_bytes,
            floor_rate: a.floor_rate,
            profile_rate: a.profile.rate,
            deadline: a.secs.map(|s| Instant::now() + Duration::from_secs(s)),
            ops: a.ops,
        },
        run_dir,
        Arc::clone(&rate_milli),
        Arc::clone(&stop_flag),
        Arc::clone(&op_index),
    )?;

    let node_list = nodes.clone();
    let mut generator = Generator::new(a.seed, a.profile.clone(), nodes.len());
    let mut executor = Executor::new(nodes, &a.profile.collection, &run_dir.join("ops.jsonl"))?;
    let workload = async {
        let mut current_rate = a.profile.rate;
        let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / current_rate));
        let deadline = a.secs.map(|s| Instant::now() + Duration::from_secs(s));
        let (mut ok, mut failed, mut skipped, mut executed) = (0u64, 0u64, 0u64, 0u64);
        let mut stopped_by = "ops";
        let started = Instant::now();
        for op in generator.by_ref().take(a.ops) {
            if a.until_op.is_some_and(|n| op.index >= n) {
                stopped_by = "until_op";
                break;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                stopped_by = "secs";
                break;
            }
            if stop_flag.load(Ordering::Relaxed) {
                stopped_by = if churn_failed.load(Ordering::Relaxed) {
                    "churn_error"
                } else {
                    "budget"
                };
                break;
            }
            let rate = rate_milli.load(Ordering::Relaxed) as f64 / 1000.0;
            if rate > 0.0 && (rate - current_rate).abs() > 1e-9 {
                current_rate = rate;
                tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate));
                tick.tick().await;
            }
            tick.tick().await;
            let record = executor.execute(&op).await?;
            op_index.store(op.index + 1, Ordering::Relaxed);
            executed = op.index + 1;
            if record.ok {
                ok += 1;
                if let Some(id) = &record.doc_id {
                    let _ = touched_tx.send(Touch {
                        doc_id: id.clone(),
                        node: record.node.clone(),
                        wall_ts_ms: record.wall_ts_ms,
                        create: op.kind == OpKind::Create,
                    });
                }
            } else if record.skipped {
                skipped += 1;
            } else {
                failed += 1;
                println!(
                    "op {} {:?} on {} failed: {}",
                    op.index,
                    op.kind,
                    record.node,
                    record.error.unwrap_or_default()
                );
            }
        }
        println!(
            "done: {executed} ops ({ok} ok, {failed} failed, {skipped} skipped orphans), {:.2} ops/s over {:.1}s, stopped by {stopped_by}",
            executed as f64 / started.elapsed().as_secs_f64(),
            started.elapsed().as_secs_f64()
        );
        let _ = churn_stop_tx.send(());
        Ok::<_, eyre::Report>((executed, stopped_by))
    };
    // The churner owns the cluster from here and shares this task with the
    // workload: the harness restart future is not Send, so it cannot be
    // spawned. With no schedule it only meters and waits for stop.
    let churner = churn::run(
        cluster,
        churn_events,
        a.profile.rate,
        a.profile.collection.clone(),
        Arc::clone(&op_index),
        transitions_tx,
        run_dir.join("topology.jsonl"),
        meter,
        churn_stop_rx,
    );
    // A churner failure drops the cluster; stop the workload within a tick
    // instead of letting it run for hours against a dead mesh.
    let churner = async {
        let result = churner.await;
        if result.is_err() {
            churn_failed.store(true, Ordering::Relaxed);
            stop_flag.store(true, Ordering::Relaxed);
        }
        result
    };
    let (workload_result, cluster) = tokio::join!(workload, churner);
    let cluster = cluster.wrap_err("churner")?;
    let (executed, stopped_by) = workload_result?;
    let _ = stop_tx.send(());
    let summary = checker_task.await?.wrap_err("checker")?;
    println!(
        "checks: {} ({} unreachable), divergence records: {}, still present at final sweep: {}",
        summary.checks, summary.unreachable, summary.divergences, summary.unresolved
    );
    println!(
        "final sweep: {} mismatches ({})",
        summary.final_mismatches,
        if summary.final_eligible {
            "eligible"
        } else {
            "NOT eligible: a node was down or in grace"
        }
    );
    if a.hold {
        println!("holding: nodes stay up for inspection, press Enter to stop");
        for (name, url) in &node_list {
            println!("  {name}: {url}/api/v0/graphql");
        }
        let _ = std::io::stdin().read_line(&mut String::new());
    }

    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    m["ops_executed"] = json!(executed);
    m["stopped_by"] = json!(stopped_by);
    m["ended_wall_ts_ms"] = json!(now_ms());
    m["checker"] = json!({
        "checks": summary.checks, "unreachable": summary.unreachable,
        "divergence_records": summary.divergences, "unresolved": summary.unresolved,
        "final_mismatches": summary.final_mismatches, "final_eligible": summary.final_eligible,
    });
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&m)?)?;
    drop(cluster);
    summary::write_profile(run_dir)?;
    println!("profile: {}", run_dir.join("profile.md").display());
    Ok(())
}

/// Both nodes replicate `collection` to each other over libp2p.
/// Same call order as defradb.rs `p2p_interop_bench`, which is proven on
/// mixed clusters.
fn wire_bidirectional(cluster: &TestCluster, collection: &str) -> Result<()> {
    let addr = [
        extract_p2p_addr(cluster, RUST),
        extract_p2p_addr(cluster, GO),
    ];
    for i in [RUST, GO] {
        cluster.client(i).schema_add(SCHEMA)?;
    }
    cluster.client(RUST).p2p_connect(&[addr[GO].as_str()])?;
    for i in [RUST, GO] {
        cluster.client(i).p2p_collection_add(&[collection])?;
    }
    cluster
        .client(RUST)
        .p2p_replicator_set(&[collection], &addr[GO])?;
    cluster
        .client(GO)
        .p2p_replicator_set(&[collection], &addr[RUST])?;
    Ok(())
}

/// T0 check: a doc created on Go must show up on Rust over HTTP GraphQL
/// before any workload runs, so a miswired mesh fails fast.
async fn preflight(cluster: &TestCluster, collection: &str) -> Result<()> {
    cluster
        .client(GO)
        .collection_create(collection, r#"{"name": "preflight", "age": 1}"#)
        .wrap_err("creating the preflight doc on go-0")?;
    let http = reqwest::Client::new();
    let query =
        format!("{{ {collection}(filter: {{name: {{_eq: \"preflight\"}}}}) {{ _docID }} }}");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let data = gql(&http, cluster.api_url(RUST), &query)
            .await
            .map_err(eyre::Report::msg)?;
        if data[collection].as_array().map_or(0, Vec::len) == 1 {
            println!("preflight ok: go-0 -> rust-0 replication works");
            return Ok(());
        }
        eyre::ensure!(
            Instant::now() < deadline,
            "preflight doc did not replicate go-0 -> rust-0 within 60s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Positive control: `Control` replicates Rust -> Go only. A doc created on
/// Go never reaches Rust (M1), and a Rust-created doc updated on Go has
/// different heads on the two sides (M3).
async fn wire_control(cluster: &TestCluster) -> Result<()> {
    for i in [RUST, GO] {
        cluster.client(i).schema_add(CONTROL_SCHEMA)?;
    }
    let go_addr = extract_p2p_addr(cluster, GO);
    cluster
        .client(RUST)
        .p2p_replicator_set(&[CONTROL], &go_addr)?;
    let http = reqwest::Client::new();
    let go_url = cluster.api_url(GO);
    let rust_url = cluster.api_url(RUST);
    let create = |v: u32| format!("mutation {{ add_{CONTROL}(input: [{{v: {v}}}]) {{ _docID }} }}");
    gql(&http, go_url, &create(1))
        .await
        .map_err(eyre::Report::msg)?;
    let data = gql(&http, rust_url, &create(2))
        .await
        .map_err(eyre::Report::msg)?;
    let id = data[format!("add_{CONTROL}")][0]["_docID"]
        .as_str()
        .ok_or_else(|| eyre!("control create returned no _docID"))?
        .to_string();
    let deadline = Instant::now() + Duration::from_secs(60);
    let seen = format!("{{ {CONTROL}(docID: \"{id}\") {{ _docID }} }}");
    loop {
        let data = gql(&http, go_url, &seen).await.map_err(eyre::Report::msg)?;
        if data[CONTROL].as_array().map_or(0, Vec::len) == 1 {
            break;
        }
        eyre::ensure!(Instant::now() < deadline, "control doc did not reach go-0");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let update =
        format!("mutation {{ update_{CONTROL}(docID: \"{id}\", input: {{v: 3}}) {{ _docID }} }}");
    gql(&http, go_url, &update)
        .await
        .map_err(eyre::Report::msg)?;
    println!("control wired: M1 doc on go-0 only, M3 doc {id} updated on go-0 only");
    Ok(())
}

/// `<binary> version --format json`, or null if that fails.
fn version_json(binary: &str) -> Value {
    Command::new(binary)
        .args(["version", "--format", "json"])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .unwrap_or(Value::Null)
}

/// `--name value` from argv.
fn flag(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == format!("--{name}") {
            return args.next();
        }
    }
    None
}

fn has_flag(name: &str) -> bool {
    std::env::args().any(|a| a == format!("--{name}"))
}

fn parse_flag<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    Ok(opt_flag(name)?.unwrap_or(default))
}

fn opt_flag<T>(name: &str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    flag(name)
        .map(|s| s.parse::<T>())
        .transpose()
        .map_err(|e| eyre!("--{name}: {e}"))
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `runs/<unix-secs>-<seed>/` under the current dir, absolute. Fails if it
/// exists so two runs never share an artifact.
fn new_run_dir(seed: u64) -> Result<PathBuf> {
    std::fs::create_dir_all("runs")?;
    let dir = PathBuf::from("runs").join(format!("{}-{seed}", unix_secs()));
    std::fs::create_dir(&dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    Ok(dir.canonicalize()?)
}
