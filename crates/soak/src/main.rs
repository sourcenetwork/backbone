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
//!          [--min-settle SECS] [--no-subscribe] [--node-env KEY=VALUE]...
//!          [--retry-intervals 5,10,20,40] [--sse-go] [--until-op N] [--hold]
//!          [--nodes process|docker] [--reuse-network]
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
//! test; both backends take it. `--min-settle SECS` keeps the settle (and
//! the meter) running that long after the workload stops even if the mesh is
//! already clear, which is the only way a run gets an idle sample.
//! `--no-subscribe` skips the collection subscribe, leaving the replicator as
//! the only delivery path, so a push failure is visible instead of masked by
//! gossip. `--node-env KEY=VALUE`, repeatable, reaches every node on both
//! backends and both runtimes, and is recorded in the manifest; it is how a
//! run raises its log level (`--node-env RUST_LOG=debug`). `compare` checks two runs against the replay
//! contract: planned op fields and the churn schedule, plus docIDs where
//! both runs have one; outcomes and timing are not part of it.
//!
//! `--nodes docker` runs the M2 six-node topology as containers on a
//! `soak-<run_id>` network instead of harness processes (p0-crud only);
//! the backend is recorded in the manifest and honoured by `replay`.

mod auth;
mod checker;
mod churn;
mod confirm;
mod executor;
mod generator;
mod meter;
mod nodes;
mod sse;
mod summary;
mod tags;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use defra_harness::TestCluster;
use eyre::{bail, eyre, Result, WrapErr};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use auth::{auth_token, Identities, Identity};
use checker::{Checker, CheckerConfig, Touch};
use churn::{ChurnClock, ChurnConfig, ChurnEvent};
use executor::{gql, gql_as, http_client, now_ms, Executor};
use generator::{Actor, Generator, OpKind, Profile};
use meter::{Meter, MeterConfig};
use nodes::{DockerNodes, Nodes};

const SCHEMA: &str = "type Users { name: String age: Int score: Float blob: String }";
const VAULT_SCHEMA: &str =
    "type Vault { name: String secret: String pin: String score: Float blob: String }";
/// Shared searchable-encryption key for every node; the key is not under test.
const SE_KEY: [u8; 32] = [0x5e; 32];

fn schema_for(profile: &Profile) -> &'static str {
    if profile.is_encrypted() {
        VAULT_SCHEMA
    } else {
        SCHEMA
    }
}

/// The p2-acp collection, bound to the policy added at setup.
fn acp_schema(policy_id: &str) -> String {
    format!(
        "type User @policy(id: \"{policy_id}\", resource: \"users\") {{ name: String age: Int score: Float blob: String }}"
    )
}

/// Node binary per index: the Rust `defra` before `GO0`, Go `defradb` after.
fn binaries() -> Result<Vec<PathBuf>> {
    let rust = PathBuf::from(
        std::env::var("DEFRA_RUST_BINARY").wrap_err("DEFRA_RUST_BINARY must be set")?,
    );
    let go = PathBuf::from("defradb");
    Ok((0..STORES.len())
        .map(|i| if i < GO0 { rust.clone() } else { go.clone() })
        .collect())
}

fn generate_identity(bin: &Path, what: &str) -> Result<Identity> {
    let id = defra_harness::identity::generate_identity(bin)
        .wrap_err_with(|| format!("generating the {what} identity"))?;
    Ok(Identity {
        key_hex: id.private_key_hex,
        did: id.did,
    })
}
const CONTROL: &str = "Control";
const CONTROL_SCHEMA: &str = "type Control { v: Int }";
/// Node indices: the harness spawns Rust nodes first, then Go nodes.
const RUST0: usize = 0;
const GO0: usize = 2;
/// Durable store per node index; the Rust cli has no other durable engine
/// and Go has only badger.
const STORES: [&str; 4] = ["regolith", "regolith", "badger", "badger"];
/// Container images for `--nodes docker`, tagged by the commit they hold.
const RUST_IMAGE: &str = "soak-defra:8d8bb299f";

/// Everything a run needs; `replay` rebuilds it from a manifest.
struct RunArgs {
    seed: u64,
    ops: usize,
    secs: Option<u64>,
    profile: Profile,
    control: bool,
    churn: Option<ChurnConfig>,
    /// The original's stored schedule on replay; `None` draws one.
    churn_schedule: Option<Vec<ChurnEvent>>,
    grace: Duration,
    settle: Duration,
    /// Settle at least this long after the workload stops, clear or not.
    min_settle: Duration,
    ceiling_bytes: u64,
    floor_rate: f64,
    meter_interval: Duration,
    until_op: Option<u64>,
    hold: bool,
    replay_of: Option<String>,
    /// Comma-separated seconds for both nodes' replicator retry ladder.
    retry_intervals: Option<String>,
    /// Also subscribe on Go nodes (reproduces the memory growth).
    sse_go: bool,
    /// Skip the collection subscribe: replicators are the only delivery path.
    no_subscribe: bool,
    /// `KEY=VALUE` pairs set on every node, both backends and both runtimes.
    node_env: Vec<String>,
    /// Containers on a `soak-<run_id>` network instead of harness processes.
    docker: bool,
    /// Start even if a `soak-*` network is left over from an earlier run.
    reuse_network: bool,
}

impl RunArgs {
    fn from_flags() -> Result<Self> {
        let profile_name = flag("profile").unwrap_or_else(|| "p0-crud".to_string());
        let mut profile = Profile::by_name(&profile_name).ok_or_else(|| {
            eyre!(
                "unknown --profile {profile_name}; use p0-crud, p1-encrypted, p1-unique or p2-acp"
            )
        })?;
        if let Some(rate) = flag("rate") {
            profile.rate = rate.parse().wrap_err("--rate must be a number")?;
        }
        let docker = match flag("nodes").as_deref() {
            None | Some("process") => false,
            Some("docker") => true,
            Some(other) => bail!("unknown --nodes {other}; use process or docker"),
        };
        let node_count = if docker {
            nodes::m2_specs().len()
        } else {
            STORES.len()
        };
        if let Some(list) = flag("create-nodes") {
            let nodes: Vec<usize> = list
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<usize>()
                        .wrap_err("--create-nodes must be node indices")
                })
                .collect::<Result<_>>()?;
            eyre::ensure!(
                nodes.iter().all(|n| *n < node_count),
                "--create-nodes: index out of range"
            );
            profile.create_nodes = Some(nodes);
        }
        let mut churn = has_flag("churn").then(|| ChurnConfig {
            clock: ChurnClock::Wall,
            ..ChurnConfig::default()
        });
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
            churn_schedule: None,
            grace: Duration::from_secs(parse_flag("grace", checker.grace.as_secs())?),
            settle: Duration::from_secs(parse_flag("settle", checker.settle.as_secs())?),
            min_settle: Duration::from_secs(parse_flag(
                "min-settle",
                checker.min_settle.as_secs(),
            )?),
            ceiling_bytes: (parse_flag::<f64>("ceiling-mb", 120.0 * 1024.0)? * 1_048_576.0) as u64,
            floor_rate: parse_flag("floor-rate", 0.5)?,
            meter_interval: Duration::from_secs(parse_flag("meter-secs", 60)?),
            until_op: opt_flag("until-op")?,
            hold: has_flag("hold"),
            replay_of: None,
            retry_intervals: flag("retry-intervals"),
            sse_go: has_flag("sse-go"),
            no_subscribe: has_flag("no-subscribe"),
            node_env: {
                let items = flags("node-env");
                for kv in &items {
                    split_node_env(kv)?;
                }
                items
            },
            docker,
            reuse_network: has_flag("reuse-network"),
        })
    }

    /// The original run's parameters. The stored churn schedule is replayed
    /// as recorded (older manifests without one are redrawn from the seed
    /// over the planned `ops`); the workload stops at the original's
    /// executed count via `until_op`, and the disk budget is off.
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
        let churn_schedule = match m["churn"]["schedule"].as_array() {
            Some(_) => Some(serde_json::from_value(m["churn"]["schedule"].clone())?),
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
            churn_schedule,
            grace: Duration::from_secs(parse_flag(
                "grace",
                caps["grace_secs"].as_u64().unwrap_or(120),
            )?),
            settle: Duration::from_secs(parse_flag(
                "settle",
                caps["settle_secs"].as_u64().unwrap_or(120),
            )?),
            min_settle: Duration::from_secs(parse_flag(
                "min-settle",
                caps["min_settle_secs"].as_u64().unwrap_or(0),
            )?),
            ceiling_bytes: u64::MAX / 2,
            floor_rate: caps["floor_rate"].as_f64().unwrap_or(0.5),
            meter_interval: Duration::from_secs(caps["meter_secs"].as_u64().unwrap_or(60)),
            until_op: opt_flag("until-op")?.or_else(|| m["ops_executed"].as_u64()),
            hold: has_flag("hold"),
            replay_of: m["run_id"].as_str().map(String::from),
            retry_intervals: caps["retry_intervals"].as_str().map(String::from),
            sse_go: has_flag("sse-go") || caps["sse_go"].as_bool().unwrap_or(false),
            no_subscribe: has_flag("no-subscribe")
                || caps["no_subscribe"].as_bool().unwrap_or(false),
            node_env: match flags("node-env") {
                items if !items.is_empty() => items,
                _ => caps["node_env"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
            },
            docker: m["nodes"][0]["backend"] == json!("docker"),
            reuse_network: has_flag("reuse-network"),
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
    let mut nodes = start_nodes(run_dir, &a).await?;
    let result = drive(run_dir, &a, &mut nodes).await;
    let shutdown = nodes.shutdown().await;
    result?;
    shutdown?;
    summary::write_profile(run_dir)?;
    println!("profile: {}", run_dir.join("profile.md").display());
    Ok(())
}

/// Harness processes, or the M2 six-node topology as containers.
async fn start_nodes(run_dir: &Path, a: &RunArgs) -> Result<Nodes> {
    if a.docker {
        eyre::ensure!(
            !a.profile.is_encrypted() && !a.profile.is_acp(),
            "docker backend supports p0-crud only in M2 stage one"
        );
        // The host CLIs must resolve before any container exists: a panic
        // in `client()` would skip the teardown.
        binaries()?;
        let leftover = nodes::existing_networks().await?;
        eyre::ensure!(
            leftover.is_empty() || a.reuse_network,
            "soak networks exist: {}; remove them (docker network rm) or pass --reuse-network",
            leftover.join(", ")
        );
        let run_id = run_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // The Go image tag is the compat commit, so image and host binary
        // always name the same version.
        let commit = std::env::var("DEFRA_GO_COMPAT_COMMIT")
            .wrap_err("DEFRA_GO_COMPAT_COMMIT must be set for the docker backend")?;
        eyre::ensure!(
            !commit.is_empty(),
            "DEFRA_GO_COMPAT_COMMIT must be set for the docker backend"
        );
        let go_image = format!("soak-defradb:{commit}");
        let images = (RUST_IMAGE, go_image.as_str());
        if let Some(intervals) = &a.retry_intervals {
            println!("replicator retry intervals in every container: {intervals}s");
        }
        let docker = DockerNodes::start(
            &run_id,
            run_dir,
            nodes::m2_specs(),
            images,
            a.retry_intervals.as_deref(),
            &a.node_env,
        )
        .await
        .wrap_err("starting the docker cluster")?;
        println!("docker backend: {RUST_IMAGE} + {go_image} on soak-{run_id}");
        return Ok(Nodes::Docker(docker));
    }
    // The harness spawns nodes as children of this process and does not clear
    // their environment, so setting it here reaches every node of either
    // runtime, including the ones a churn event respawns.
    apply_node_env(&a.node_env)?;
    let mut builder = TestCluster::builder()
        .rust_nodes(2)
        .go_nodes(2)
        .with_p2p()
        // File keyrings so peer identities survive restarts: without one the
        // Rust node mints a new peer ID per start, and with only the Env
        // keyring so does the Go node; a replicator pointed at the old id
        // never reconnects.
        .with_file_keyring();
    for (i, store) in STORES.iter().enumerate() {
        builder = builder.with_node_store(i, *store);
    }
    if a.profile.is_encrypted() {
        // Recipe configuration (spec 62, D1): dev mode so Go's KMS has a node
        // identity under --no-keyring, an explicit identity per node, and one
        // SE key seeded into every file keyring.
        builder = builder
            .with_encryption()
            .with_development()
            .with_shared_searchable_encryption_key(SE_KEY);
        for (i, bin) in binaries()?.iter().enumerate() {
            let identity = generate_identity(bin, &format!("node {i}"))?;
            builder = builder.with_node_identity(i, identity.key_hex);
        }
        println!("encrypted profile: encryption + dev mode + per-node identities + shared SE key");
    }
    if a.profile.is_acp() {
        builder = builder.with_acp_local();
    }
    if let Some(intervals) = &a.retry_intervals {
        let flag = ["--replicator-retry-intervals", intervals.as_str()];
        builder = builder.with_extra_rust_args(flag).with_extra_go_args(flag);
        println!("replicator retry intervals on both nodes: {intervals}s");
    }
    let cluster = builder
        .build()
        .await
        .wrap_err("building the mixed cluster")?;
    Ok(Nodes::Process {
        cluster,
        stopped: HashMap::new(),
    })
}

/// Everything between the nodes coming up and the final manifest; the
/// caller shuts the nodes down whether or not this succeeds.
async fn drive(run_dir: &Path, a: &RunArgs, nodes: &mut Nodes) -> Result<()> {
    for i in 0..nodes.len() {
        println!(
            "{} at {} ({})",
            nodes.name(i),
            nodes.api_url(i),
            nodes.store(i)
        );
    }
    let identities = if a.profile.is_acp() {
        let rust = &binaries()?[RUST0];
        let ids = Identities {
            owner: generate_identity(rust, "owner")?,
            reader: generate_identity(rust, "reader")?,
        };
        println!(
            "acp profile: local ACP, owner {} reader {}",
            ids.owner.did, ids.reader.did
        );
        Some(ids)
    } else {
        None
    };
    wire_full_mesh(nodes, &a.profile, identities.as_ref(), a.no_subscribe)?;
    preflight(nodes, &a.profile.collection).await?;
    if let Some(ids) = &identities {
        token_probe(nodes, &a.profile.collection, &ids.owner).await?;
    }
    let mut collections = vec![a.profile.collection.clone()];
    if a.control {
        wire_control(nodes).await?;
        collections.push(CONTROL.to_string());
    }

    let endpoints: Vec<(String, String)> = (0..nodes.len())
        .map(|i| (nodes.name(i).to_string(), nodes.api_url(i)))
        .collect();
    let http = http_client(Duration::from_secs(30));
    let mut peer_ids = Vec::new();
    for (name, url) in &endpoints {
        let pid = churn::peer_id(&http, url).await;
        println!("{name} peer id: {}", pid.as_deref().unwrap_or("?"));
        peer_ids.push(pid);
    }
    // On wall time the run ends at `--secs` if that comes first; events
    // drawn past it would never fire.
    let mut horizon_ms = churn::virtual_ms(a.ops as u64, a.profile.rate);
    if let (Some(cfg), Some(secs)) = (a.churn.as_ref(), a.secs) {
        if cfg.clock == ChurnClock::Wall {
            horizon_ms = horizon_ms.min(secs * 1000);
        }
    }
    let churn_events = match (&a.churn_schedule, &a.churn) {
        (Some(stored), _) => stored.clone(),
        (None, Some(cfg)) => churn::schedule_with(
            a.seed,
            endpoints.len(),
            horizon_ms,
            cfg,
            nodes.supports_partition(),
        ),
        (None, None) => Vec::new(),
    };
    for e in &churn_events {
        println!(
            "churn plan #{} at {}s: {:?} {} (down {}ms)",
            e.index,
            e.virtual_ts_ms / 1000,
            e.kind,
            endpoints[e.node].0,
            e.down_ms
        );
    }
    let run_id = run_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rust_binary = std::env::var("DEFRA_RUST_BINARY").unwrap_or_default();
    let backend = if a.docker { "docker" } else { "process" };
    let manifest_path = run_dir.join("manifest.json");
    let manifest = json!({
        "run_id": run_id,
        "replay_of": a.replay_of,
        "seed": a.seed,
        "ops": a.ops,
        "secs": a.secs,
        "profile": a.profile,
        "control": a.control,
        "identities": identities,
        "nodes": endpoints.iter().zip(&peer_ids).enumerate().map(|(i, ((name, url), pid))| {
            let c = nodes.container(i);
            json!({
                "name": name, "api_url": url, "store": nodes.store(i), "peer_id": pid,
                "backend": backend, "image": c.map(|c| &c.image),
                "ip": c.and_then(|c| c.ip.as_deref()), "host": c.map(|c| c.spec.host),
            })
        }).collect::<Vec<_>>(),
        "rust_binary": rust_binary,
        "rust_version": version_json(&rust_binary),
        "go_compat_commit": std::env::var("DEFRA_GO_COMPAT_COMMIT").unwrap_or_default(),
        "go_version": version_json("defradb"),
        "churn": a.churn.as_ref().map(|cfg| json!({"config": cfg, "schedule": churn_events})),
        "caps": {
            "ceiling_bytes": a.ceiling_bytes, "floor_rate": a.floor_rate,
            "meter_secs": a.meter_interval.as_secs(), "grace_secs": a.grace.as_secs(),
            "settle_secs": a.settle.as_secs(), "min_settle_secs": a.min_settle.as_secs(),
            "until_op": a.until_op,
            "retry_intervals": a.retry_intervals, "sse_go": a.sse_go,
            "no_subscribe": a.no_subscribe, "node_env": a.node_env,
        },
        "started_wall_ts_ms": now_ms(),
    });
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    let op_index = Arc::new(AtomicU64::new(0));
    let rate_milli = Arc::new(AtomicU64::new((a.profile.rate * 1000.0) as u64));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let churn_failed = Arc::new(AtomicBool::new(false));
    let workload_done = Arc::new(AtomicBool::new(false));
    let (touched_tx, touched_rx) = mpsc::unbounded_channel();
    let (transitions_tx, transitions_rx) = mpsc::unbounded_channel();
    let (arrivals_tx, arrivals_rx) = mpsc::unbounded_channel();
    let subscription = format!("subscription {{ {} {{ _docID }} }}", a.profile.collection);
    let subscriptions: Vec<_> = endpoints
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| a.sse_go || name.starts_with("rust"))
        .map(|(i, (_, url))| {
            tokio::spawn(sse::subscribe(
                i,
                url.clone(),
                subscription.clone(),
                arrivals_tx.clone(),
            ))
        })
        .collect();
    drop(arrivals_tx);
    let (stop_tx, stop_rx) = oneshot::channel();
    let (churn_stop_tx, churn_stop_rx) = oneshot::channel();
    let checker = Checker::new(
        endpoints.clone(),
        collections,
        CheckerConfig {
            grace: a.grace,
            settle: a.settle,
            min_settle: a.min_settle,
            encrypted_fields: a.profile.encrypt_fields.clone(),
            acp: identities.clone(),
            ..CheckerConfig::default()
        },
        a.seed,
        run_id.clone(),
        Arc::clone(&op_index),
        run_dir,
    )?;
    let checker_task = tokio::spawn(checker.run(touched_rx, transitions_rx, arrivals_rx, stop_rx));
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

    let mut generator = Generator::new(a.seed, a.profile.clone(), endpoints.len());
    let mut executor = Executor::new(
        endpoints.clone(),
        &a.profile,
        identities.clone(),
        nodes.binaries()?,
        &run_dir.join("ops.jsonl"),
    )?;
    let workload = async {
        let result = async {
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
                    // Grants change relationships, not documents; nothing replicates.
                    if let Some(id) = record.doc_id.as_ref().filter(|_| op.kind != OpKind::Grant) {
                        let _ = touched_tx.send(Touch {
                            doc_id: id.clone(),
                            node: record.node.clone(),
                            wall_ts_ms: record.wall_ts_ms,
                            create: op.kind == OpKind::Create,
                            protected: match (op.kind, op.actor) {
                                (OpKind::Create, Some(Actor::Owner)) => Some(true),
                                (OpKind::Create, Some(Actor::Anon)) => Some(false),
                                _ => None,
                            },
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
            Ok::<_, eyre::Report>((executed, stopped_by))
        }
        .await;
        // The settle starts here, while the churner (and its meter) keep
        // running; an error path must signal it too or the checker never
        // returns and the churner is never released.
        workload_done.store(true, Ordering::Relaxed);
        let _ = stop_tx.send(());
        result
    };
    // The churner borrows the nodes from here and shares this task with the
    // workload: the harness restart future is not Send, so it cannot be
    // spawned. With no schedule it only meters and waits for stop.
    let churner = churn::run(
        nodes,
        churn_events,
        a.churn.as_ref().map(|c| c.clock).unwrap_or_default(),
        a.profile.rate,
        a.profile.collection.clone(),
        Arc::clone(&op_index),
        transitions_tx,
        run_dir.join("topology.jsonl"),
        meter,
        Arc::clone(&workload_done),
        churn_stop_rx,
    );
    // After a churner failure the mesh is not what the run planned; stop the
    // workload within a tick instead of letting it run for hours against it.
    let churner = async {
        let result = churner.await;
        if result.is_err() {
            churn_failed.store(true, Ordering::Relaxed);
            stop_flag.store(true, Ordering::Relaxed);
        }
        result
    };
    // The churner holds the nodes, so it is the only thing that can meter:
    // release it once the checker's settle and final sweep are done, not when
    // the workload stops, or a `--min-settle` run has no idle sample.
    let settle_meter = async {
        let summary = checker_task.await;
        let _ = churn_stop_tx.send(());
        summary
    };
    let (workload_result, churner_result, checker_result) =
        tokio::join!(workload, churner, settle_meter);
    churner_result.wrap_err("churner")?;
    let (executed, stopped_by) = workload_result?;
    let summary = checker_result?.wrap_err("checker")?;
    for task in &subscriptions {
        task.abort();
    }
    println!(
        "subscription events per node: {:?}; checks triggered by quiescence: {}",
        summary.sse_events, summary.quiet_checks
    );
    println!(
        "checks: {} ({} unreachable), divergence records: {}, still present at final sweep: {}",
        summary.checks, summary.unreachable, summary.divergences, summary.unresolved
    );
    if summary.m5_docs > 0 {
        println!("m5 docs compared: {}", summary.m5_docs);
    }
    if summary.m6_docs + summary.m6_by_design > 0 {
        println!(
            "m6 docs compared: {} (by design skipped: {})",
            summary.m6_docs, summary.m6_by_design
        );
    }
    println!(
        "final sweep: {} mismatches ({})",
        summary.final_mismatches,
        if summary.final_eligible {
            "eligible"
        } else {
            "NOT eligible: a node was down or in grace"
        }
    );
    println!(
        "divergent docs: {} with a known-cause tag, {} UNTAGGED",
        summary.tagged_docs, summary.untagged_docs
    );
    if a.hold {
        println!("holding: nodes stay up for inspection, press Enter to stop");
        for (name, url) in &endpoints {
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
        "tagged_docs": summary.tagged_docs, "untagged_docs": summary.untagged_docs,
        "sse_events": summary.sse_events, "quiet_checks": summary.quiet_checks,
        "m5_docs": summary.m5_docs,
        "m6_docs": summary.m6_docs, "m6_by_design": summary.m6_by_design,
    });
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&m)?)?;
    Ok(())
}

/// Every node replicates `collection` to every other over libp2p: connect
/// to all peers, subscribe the collection, one replicator per directed
/// pair. Same call order as defradb.rs `p2p_interop_bench`, which is
/// proven on mixed clusters. On ACP the owner adds the policy on every
/// node (ids must agree, the schema references one) and adds the schema.
/// The topics each node subscribes to: none under `--no-subscribe`, which
/// leaves the replicators as the only delivery path.
fn subscribe_topics(collection: &str, no_subscribe: bool) -> Vec<&str> {
    if no_subscribe {
        Vec::new()
    } else {
        vec![collection]
    }
}

fn wire_full_mesh(
    nodes: &Nodes,
    profile: &Profile,
    identities: Option<&Identities>,
    no_subscribe: bool,
) -> Result<()> {
    let collection = profile.collection.as_str();
    let n = nodes.len();
    let addrs: Vec<String> = (0..n).map(|i| nodes.p2p_addr(i)).collect();
    if let Some(ids) = identities {
        let mut policy_ids = Vec::new();
        for i in 0..n {
            let name = nodes.name(i);
            let out = nodes
                .client(i)
                .acp_policy_add(defra_harness::USER_ACP_POLICY, &ids.owner.key_hex)
                .wrap_err_with(|| format!("adding the policy on {name}"))?;
            let id = out["PolicyID"]
                .as_str()
                .or(out["policyID"].as_str())
                .ok_or_else(|| eyre!("policy id missing on {name}: {out}"))?;
            policy_ids.push(id.to_string());
        }
        eyre::ensure!(
            policy_ids.iter().all(|x| x == &policy_ids[0]),
            "policy ids differ across nodes: {policy_ids:?}"
        );
        println!("policy {} on every node", policy_ids[0]);
        for i in 0..n {
            nodes
                .client(i)
                .schema_add_with_identity(&acp_schema(&policy_ids[0]), &ids.owner.key_hex)
                .wrap_err_with(|| format!("adding the schema on {}", nodes.name(i)))?;
        }
    } else {
        for i in 0..n {
            nodes.client(i).schema_add(schema_for(profile))?;
        }
    }
    for i in 0..n {
        let others: Vec<&str> = (0..n)
            .filter(|j| *j != i)
            .map(|j| addrs[j].as_str())
            .collect();
        nodes.client(i).p2p_connect(&others)?;
    }
    let topics = subscribe_topics(collection, no_subscribe);
    if topics.is_empty() {
        println!("no collection subscribe: replicators are the only delivery path");
    } else {
        for i in 0..n {
            nodes.client(i).p2p_collection_add(&topics)?;
        }
    }
    for i in 0..n {
        for j in (0..n).filter(|j| *j != i) {
            nodes
                .client(i)
                .p2p_replicator_set(&[collection], &addrs[j])?;
        }
    }
    if let Some(field) = &profile.se_field {
        for i in 0..n {
            nodes
                .client(i)
                .encrypted_index_add(collection, field)
                .wrap_err_with(|| format!("encrypted index on {}", nodes.name(i)))?;
        }
    }
    Ok(())
}

/// T0 check: a doc created on each node must show up on every other node
/// over HTTP GraphQL before any workload runs, so a miswired mesh fails fast.
async fn preflight(nodes: &Nodes, collection: &str) -> Result<()> {
    let n = nodes.len();
    for i in 0..n {
        let doc = format!(r#"{{"name": "preflight-{}"}}"#, nodes.name(i));
        nodes
            .client(i)
            .collection_create(collection, &doc)
            .wrap_err_with(|| format!("creating the preflight doc on {}", nodes.name(i)))?;
    }
    let http = http_client(Duration::from_secs(30));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let mut missing = Vec::new();
        for creator in 0..n {
            let name = nodes.name(creator);
            let query = format!(
                "{{ {collection}(filter: {{name: {{_eq: \"preflight-{name}\"}}}}) {{ _docID }} }}"
            );
            for viewer in (0..n).filter(|v| *v != creator) {
                let data = gql(&http, &nodes.api_url(viewer), &query)
                    .await
                    .map_err(eyre::Report::msg)?;
                if data[collection].as_array().map_or(0, Vec::len) != 1 {
                    missing.push(format!("{name} -> {}", nodes.name(viewer)));
                }
            }
        }
        if missing.is_empty() {
            println!("preflight ok: every node's doc reached every other node");
            return Ok(());
        }
        eyre::ensure!(
            Instant::now() < deadline,
            "preflight docs did not replicate within 90s: {}",
            missing.join(", ")
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A bearer token minted for the owner must be accepted by one node of each
/// runtime (audience = host:port), or every identity-scoped op would fail.
async fn token_probe(nodes: &Nodes, collection: &str, owner: &Identity) -> Result<()> {
    let http = http_client(Duration::from_secs(30));
    let query = format!("{{ {collection}(limit: 1) {{ _docID }} }}");
    for i in [RUST0, GO0] {
        let name = nodes.name(i);
        let url = nodes.api_url(i);
        let token = auth_token(&owner.key_hex, &url)?;
        gql_as(&http, &url, &query, Some(&token))
            .await
            .map_err(|e| eyre!("bearer token rejected by {name}: {e}"))?;
    }
    println!("token probe ok: owner bearer accepted by rust-0 and go-0");
    Ok(())
}

/// Positive control: `Control` exists on every node but replicates rust-0 ->
/// go-0 only. A doc created on go-0 never reaches the others (M1), and a
/// rust-0-created doc updated on go-0 has different heads on the two (M3).
async fn wire_control(nodes: &Nodes) -> Result<()> {
    for i in 0..nodes.len() {
        nodes.client(i).schema_add(CONTROL_SCHEMA)?;
    }
    let go_addr = nodes.p2p_addr(GO0);
    nodes
        .client(RUST0)
        .p2p_replicator_set(&[CONTROL], &go_addr)?;
    let http = http_client(Duration::from_secs(30));
    let go_url = &nodes.api_url(GO0);
    let rust_url = &nodes.api_url(RUST0);
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

/// Every `--name VALUE` occurrence, in command-line order.
fn flags(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == format!("--{name}") {
            out.extend(args.next());
        }
    }
    out
}

/// The only validation a `--node-env` item gets: it has an `=`.
fn split_node_env(item: &str) -> Result<(&str, &str)> {
    item.split_once('=')
        .ok_or_else(|| eyre!("--node-env {item}: expected KEY=VALUE"))
}

/// Set the pairs on this process; spawned nodes inherit them.
fn apply_node_env(items: &[String]) -> Result<()> {
    for item in items {
        let (k, v) = split_node_env(item)?;
        std::env::set_var(k, v);
    }
    if !items.is_empty() {
        println!("node env on every node: {}", items.join(" "));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `--no-subscribe` removes gossip so the replicator is the only path;
    /// without the flag every node subscribes to the collection as before.
    #[test]
    fn no_subscribe_skips_the_collection_topic() {
        assert_eq!(subscribe_topics("Users", false), vec!["Users"]);
        assert!(subscribe_topics("Users", true).is_empty());
    }

    /// The process backend has no per-node env hook: nodes are children of
    /// this process and inherit its environment, so applying the pairs here
    /// is what reaches both runtimes.
    #[test]
    fn node_env_is_applied_to_this_process_and_validated() {
        assert_eq!(
            split_node_env("RUST_LOG=debug").unwrap(),
            ("RUST_LOG", "debug")
        );
        // A value may contain further `=`; only the first splits.
        assert_eq!(
            split_node_env("RUST_LOG=defra=debug,libp2p=info").unwrap(),
            ("RUST_LOG", "defra=debug,libp2p=info")
        );
        assert!(split_node_env("RUST_LOG").is_err());

        apply_node_env(&["SOAK_TEST_NODE_ENV=debug".to_string()]).unwrap();
        assert_eq!(std::env::var("SOAK_TEST_NODE_ENV").unwrap(), "debug");
        assert!(apply_node_env(&["NO_EQUALS_HERE".to_string()]).is_err());
        // Nothing to apply, nothing set.
        apply_node_env(&[]).unwrap();
        assert!(std::env::var("SOAK_TEST_NODE_ENV_UNSET").is_err());
    }

    /// The manifest cap is `caps.node_env`, and a replay of a run that used
    /// the flag gets the same environment without retyping it.
    #[test]
    fn node_env_round_trips_through_manifest_caps() {
        let dir = std::env::temp_dir().join(format!("soak-caps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.json");
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "run_id": "1789000000-42",
                "seed": 42,
                "ops": 100,
                "profile": Profile::p0_crud(),
                "nodes": [{"backend": "process"}],
                "caps": {"node_env": ["RUST_LOG=debug", "GOLOG_LEVEL=debug"]},
            }))
            .unwrap(),
        )
        .unwrap();
        let a = RunArgs::from_manifest(&path).unwrap();
        assert_eq!(a.node_env, ["RUST_LOG=debug", "GOLOG_LEVEL=debug"]);
        // A manifest written before this commit has no such cap.
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "run_id": "1789000000-42", "seed": 42, "ops": 100,
                "profile": Profile::p0_crud(), "nodes": [{"backend": "process"}], "caps": {},
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(RunArgs::from_manifest(&path).unwrap().node_env.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn schema_follows_profile() {
        assert_eq!(schema_for(&Profile::p0_crud()), SCHEMA);
        assert_eq!(schema_for(&Profile::p1_encrypted()), VAULT_SCHEMA);
        // The ACP path uses `acp_schema` instead; pin what `schema_for` returns.
        assert_eq!(schema_for(&Profile::p2_acp()), SCHEMA);
        assert!(VAULT_SCHEMA.contains("type Vault") && VAULT_SCHEMA.contains("secret: String"));
    }

    #[test]
    fn acp_schema_carries_policy_id() {
        assert_eq!(
            acp_schema("abc"),
            "type User @policy(id: \"abc\", resource: \"users\") { name: String age: Int score: Float blob: String }"
        );
    }
}
