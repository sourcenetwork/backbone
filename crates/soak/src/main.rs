//! `soak`: cross-runtime DefraDB soak driver (M0 skeleton).
//!
//! Boots a mixed Go/Rust mesh through `defra-harness`, drives a seeded
//! workload, checks convergence between the runtimes, and writes a replayable
//! run artifact under `runs/<unix-secs>-<seed>/`.
//!
//! ```text
//! soak [--seed N] [--ops N] [--rate OPS_PER_SEC]
//! ```
//! Env: `DEFRA_RUST_BINARY` (built `defra`), Go `defradb` on PATH with
//! `DEFRA_GO_COMPAT_COMMIT` set.

mod executor;
mod generator;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use defra_harness::{extract_p2p_addr, TestCluster};
use eyre::{Result, WrapErr};
use serde_json::json;

use executor::{gql, Executor};
use generator::{Generator, Profile};

const SCHEMA: &str = "type Users { name: String age: Int score: Float blob: String }";
const RUST: usize = 0;
const GO: usize = 1;
/// Durable store per node index; the Rust cli has no other durable engine
/// and Go has only badger.
const STORES: [&str; 2] = ["regolith", "badger"];

fn main() -> Result<()> {
    eyre::ensure!(
        std::env::var_os("DEFRA_RUST_BINARY").is_some(),
        "set DEFRA_RUST_BINARY to a built `defra` (e.g. <defradb.rs>/target/debug/defra)"
    );
    let seed: u64 = match flag("seed") {
        Some(s) => s.parse().wrap_err("--seed must be a u64")?,
        None => unix_secs(),
    };
    let ops: usize = flag("ops").map_or(Ok(200), |s| s.parse())?;
    let mut profile = Profile::p0_crud();
    if let Some(rate) = flag("rate") {
        profile.rate = rate.parse().wrap_err("--rate must be a number")?;
    }

    let run_dir = new_run_dir(seed)?;
    // defra-harness puts node dirs under <workspace>/target/e2e and deletes
    // them on drop. Point the workspace at the run dir and keep them so the
    // artifact holds the node data and logs. Set before any thread exists.
    std::env::set_var("DEFRA_WORKSPACE_ROOT", &run_dir);
    std::env::set_var("DEFRA_E2E_KEEP", "1");
    println!("run dir: {}  seed: {seed}  ops: {ops}", run_dir.display());
    tokio::runtime::Runtime::new()?.block_on(run(&run_dir, seed, profile, ops))
}

async fn run(run_dir: &Path, seed: u64, profile: Profile, ops: usize) -> Result<()> {
    let cluster = TestCluster::builder()
        .rust_nodes(1)
        .go_nodes(1)
        .with_p2p()
        .with_node_store(RUST, STORES[RUST])
        .with_node_store(GO, STORES[GO])
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
    wire_bidirectional(&cluster, &profile.collection)?;
    preflight(&cluster, &profile.collection).await?;

    let nodes: Vec<(String, String)> = (0..cluster.len())
        .map(|i| {
            (
                cluster.nodes[i].name.clone(),
                cluster.api_url(i).to_string(),
            )
        })
        .collect();
    let manifest = json!({
        "seed": seed,
        "ops": ops,
        "profile": profile,
        "nodes": nodes.iter().zip(STORES).map(|((name, url), store)| {
            json!({"name": name, "api_url": url, "store": store})
        }).collect::<Vec<_>>(),
        "rust_binary": std::env::var("DEFRA_RUST_BINARY").unwrap_or_default(),
        "go_compat_commit": std::env::var("DEFRA_GO_COMPAT_COMMIT").unwrap_or_default(),
    });
    std::fs::write(
        run_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    let mut generator = Generator::new(seed, profile.clone(), nodes.len());
    let mut executor = Executor::new(nodes, &profile.collection, &run_dir.join("ops.jsonl"))?;
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / profile.rate));
    let (mut ok, mut failed) = (0usize, 0usize);
    let started = Instant::now();
    for op in generator.by_ref().take(ops) {
        tick.tick().await;
        let record = executor.execute(&op).await?;
        if record.ok {
            ok += 1;
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
        "done: {ok} ok, {failed} failed, {:.1} ops/s over {:.1}s",
        ops as f64 / started.elapsed().as_secs_f64(),
        started.elapsed().as_secs_f64()
    );
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
