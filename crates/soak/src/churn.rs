//! Seeded topology churn (axis 2).
//!
//! The schedule of restart / crash-kill events is drawn at run start as
//! offsets on the run's churn clock, so it is a pure function of the seed
//! and printable before the run begins. The clock is wall time from workload
//! start, or virtual time (op progress, `op_index / rate`, the same clock the
//! generator's `virtual_ts_ms` uses) for manifests that predate the choice.
//! Down-time is always wall time so a stalled workload cannot leave a node
//! dead forever.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::executor::{gql, now_ms};
use crate::meter::Meter;
use crate::nodes::Nodes;

/// Stream derivation constant for the topology axis.
const TOPO_AXIS: u64 = 0x7090_10c4_0000_0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChurnKind {
    /// SIGTERM, then start again on the same ports.
    Restart,
    /// SIGKILL, stay dead for `down_ms` of wall time, respawn.
    CrashKill,
    /// SIGTERM, stay stopped for `down_ms` with the ports held, start again.
    GracefulLeave,
    /// Network disconnect for `down_ms` of wall time, then connect.
    Partition,
}

/// Which clock the schedule offsets are read against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChurnClock {
    /// Op progress over the profile rate; the clock old manifests ran on.
    #[default]
    Virtual,
    /// Elapsed wall time since the workload started.
    Wall,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChurnEvent {
    pub index: usize,
    /// Offset from workload start on the run's churn clock.
    pub virtual_ts_ms: u64,
    pub node: usize,
    pub kind: ChurnKind,
    /// Zero for Restart.
    pub down_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChurnConfig {
    /// Mean time between events, mesh-wide.
    pub spacing_ms: u64,
    /// Minimum time from one event's end to the next on that node.
    pub cooldown_ms: u64,
    /// Down-time bounds, inclusive.
    pub down_ms: (u64, u64),
    /// Absent from old manifests, which ran on virtual time.
    #[serde(default)]
    pub clock: ChurnClock,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            spacing_ms: 120_000,
            cooldown_ms: 120_000,
            down_ms: (5_000, 30_000),
            clock: ChurnClock::Virtual,
        }
    }
}

/// Events in ascending clock time, all before `horizon_ms`. A draw that
/// lands on a cooling-down node is dropped, not redrawn, so the stream stays
/// a pure function of the seed. `partitions` adds the Partition kind to the
/// draw for backends that can cut a node off the network.
pub fn schedule_with(
    seed: u64,
    nodes: usize,
    horizon_ms: u64,
    cfg: &ChurnConfig,
    partitions: bool,
) -> Vec<ChurnEvent> {
    let mut rng = StdRng::seed_from_u64(seed ^ TOPO_AXIS);
    let mut last_end: Vec<Option<u64>> = vec![None; nodes];
    let mut events = Vec::new();
    let mut t = 0;
    loop {
        t += rng.gen_range(cfg.spacing_ms / 2..=cfg.spacing_ms * 3 / 2);
        if t >= horizon_ms {
            return events;
        }
        let node = rng.gen_range(0..nodes);
        let kinds = if partitions { 4 } else { 3 };
        let kind = match rng.gen_range(0..kinds) {
            0 => ChurnKind::Restart,
            1 => ChurnKind::CrashKill,
            2 => ChurnKind::GracefulLeave,
            _ => ChurnKind::Partition,
        };
        let down_ms = match kind {
            ChurnKind::Restart => 0,
            _ => rng.gen_range(cfg.down_ms.0..=cfg.down_ms.1),
        };
        if last_end[node].is_some_and(|end| t < end + cfg.cooldown_ms) {
            continue;
        }
        last_end[node] = Some(t + down_ms);
        events.push(ChurnEvent {
            index: events.len(),
            virtual_ts_ms: t,
            node,
            kind,
            down_ms,
        });
    }
}

/// A node went down or came back; the checker uses it for eligibility and
/// for the known-cause tags.
#[derive(Clone, Copy, Debug)]
pub struct Transition {
    pub node: usize,
    pub up: bool,
    pub wall_ts_ms: u64,
}

/// Virtual time of the workload: ops issued so far over the profile rate.
pub fn virtual_ms(op_index: u64, rate: f64) -> u64 {
    (op_index as f64 * 1000.0 / rate) as u64
}

/// Fires `events` on `clock` until `workload_done`, then keeps metering
/// until `stop`, so the settle window is sampled too; returns with every node
/// up. Each down/up phase appends a line to the log. The meter samples from
/// here too, since this task holds the nodes.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    nodes: &mut Nodes,
    events: Vec<ChurnEvent>,
    clock: ChurnClock,
    rate: f64,
    collection: String,
    op_index: Arc<AtomicU64>,
    transitions: mpsc::UnboundedSender<Transition>,
    log_path: PathBuf,
    mut meter: Meter,
    workload_done: Arc<AtomicBool>,
    mut stop: oneshot::Receiver<()>,
) -> Result<()> {
    let mut log = BufWriter::new(
        File::create(&log_path).wrap_err_with(|| format!("creating {}", log_path.display()))?,
    );
    let http = reqwest::Client::new();
    let started = Instant::now();
    let now = || match clock {
        ChurnClock::Virtual => virtual_ms(op_index.load(Ordering::Relaxed), rate),
        ChurnClock::Wall => started.elapsed().as_millis() as u64,
    };
    let mut pending = events.into_iter().peekable();
    loop {
        meter.maybe_sample(nodes).await?;
        // Once the workload has stopped the run is settling: keep metering,
        // but do not fire an event into the window the settle is measuring.
        if !workload_done.load(Ordering::Relaxed)
            && pending.peek().is_some_and(|e| e.virtual_ts_ms <= now())
        {
            let event = pending.next().expect("peeked");
            fire(
                nodes,
                &event,
                &http,
                &collection,
                &now,
                &transitions,
                &mut log,
            )
            .await?;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            _ = &mut stop => {
                meter.sample(nodes).await?;
                return Ok(());
            }
        }
    }
}

async fn fire(
    nodes: &mut Nodes,
    event: &ChurnEvent,
    http: &reqwest::Client,
    collection: &str,
    now: &dyn Fn() -> u64,
    transitions: &mpsc::UnboundedSender<Transition>,
    log: &mut BufWriter<File>,
) -> Result<()> {
    let name = nodes.name(event.node).to_string();
    let url = nodes.api_url(event.node);
    let started = Instant::now();
    let _ = transitions.send(Transition {
        node: event.node,
        up: false,
        wall_ts_ms: now_ms(),
    });
    log_phase(log, event, &name, "down", now(), 0, None, None)?;
    println!(
        "churn #{} {:?} {name} at {}ms (planned {}ms)",
        event.index,
        event.kind,
        now(),
        event.virtual_ts_ms
    );
    match event.kind {
        ChurnKind::Restart => {
            rotate_logs(nodes, event).await?;
            nodes
                .restart(event.node)
                .await
                .wrap_err_with(|| format!("{name}: restart"))?
        }
        ChurnKind::CrashKill => {
            nodes
                .kill(event.node)
                .await
                .wrap_err_with(|| format!("{name}: kill"))?;
            tokio::time::sleep(Duration::from_millis(event.down_ms)).await;
            nodes
                .respawn(event.node)
                .await
                .wrap_err_with(|| format!("{name}: respawn"))?;
        }
        ChurnKind::GracefulLeave => {
            rotate_logs(nodes, event).await?;
            nodes
                .stop(event.node)
                .await
                .wrap_err_with(|| format!("{name}: stop"))?;
            tokio::time::sleep(Duration::from_millis(event.down_ms)).await;
            nodes
                .start_stopped(event.node)
                .await
                .wrap_err_with(|| format!("{name}: start after leave"))?;
        }
        ChurnKind::Partition => {
            nodes
                .partition(event.node)
                .await
                .wrap_err_with(|| format!("{name}: partition"))?;
            tokio::time::sleep(Duration::from_millis(event.down_ms)).await;
            nodes
                .rejoin(event.node)
                .await
                .wrap_err_with(|| format!("{name}: rejoin"))?;
            log_phase(
                log,
                event,
                &name,
                "rejoin",
                now(),
                started.elapsed().as_millis() as u64,
                None,
                Some(&nodes.p2p_addr(event.node)),
            )?;
        }
    }
    wait_healthy(http, &url, collection, Duration::from_secs(60))
        .await
        .wrap_err_with(|| format!("{name}: not healthy after {:?}", event.kind))?;
    let _ = transitions.send(Transition {
        node: event.node,
        up: true,
        wall_ts_ms: now_ms(),
    });
    let pid = peer_id(http, &url).await;
    log_phase(
        log,
        event,
        &name,
        "up",
        now(),
        started.elapsed().as_millis() as u64,
        pid.as_deref(),
        None,
    )?;
    println!(
        "churn #{} {name} back up after {:?} as peer {}",
        event.index,
        started.elapsed(),
        pid.as_deref().unwrap_or("?")
    );
    Ok(())
}

/// The node's libp2p peer ID from `GET /api/v0/p2p/info`. Both runtimes
/// answer with a list of multiaddrs; take the id after the first `/p2p/`.
pub async fn peer_id(http: &reqwest::Client, url: &str) -> Option<String> {
    let body: Value = http
        .get(format!("{url}/api/v0/p2p/info"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    find_peer_id(&body)
}

fn find_peer_id(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => s
            .split("/p2p/")
            .nth(1)
            .map(|id| id.split('/').next().unwrap_or(id).to_string()),
        Value::Array(a) => a.iter().find_map(find_peer_id),
        Value::Object(o) => o.values().find_map(find_peer_id),
        _ => None,
    }
}

/// The harness truncates stdout.log on every spawn; keep the old process's
/// log so the artifact holds the whole history. A container's output is
/// flushed to the same files first.
async fn rotate_logs(nodes: &mut Nodes, event: &ChurnEvent) -> Result<()> {
    nodes.dump_logs(event.node).await?;
    let name = nodes.name(event.node).to_string();
    let log_dir = nodes.log_dir(event.node);
    for file in ["stdout.log", "stderr.log"] {
        let from = log_dir.join(file);
        let to = log_dir.join(format!("{file}.before-event-{}", event.index));
        if from.exists() {
            std::fs::rename(&from, &to)
                .wrap_err_with(|| format!("{name}: rotating {}", from.display()))?;
        }
    }
    Ok(())
}

/// `p2p_addr` is the container's re-read address, recorded on the `rejoin`
/// phase only.
#[allow(clippy::too_many_arguments)]
fn log_phase(
    log: &mut BufWriter<File>,
    event: &ChurnEvent,
    node: &str,
    phase: &str,
    virtual_ts_ms: u64,
    duration_ms: u64,
    peer_id: Option<&str>,
    p2p_addr: Option<&str>,
) -> Result<()> {
    let mut line = json!({
        "event": event.index, "kind": event.kind, "node": node, "phase": phase,
        "planned_virtual_ts_ms": event.virtual_ts_ms, "virtual_ts_ms": virtual_ts_ms,
        "wall_ts_ms": now_ms(), "down_ms": event.down_ms, "duration_ms": duration_ms,
        "peer_id": peer_id,
    });
    if let Some(addr) = p2p_addr {
        line["p2p_addr"] = json!(addr);
    }
    serde_json::to_writer(&mut *log, &line)?;
    log.write_all(b"\n")?;
    log.flush()?;
    Ok(())
}

async fn wait_healthy(
    http: &reqwest::Client,
    url: &str,
    collection: &str,
    timeout: Duration,
) -> Result<()> {
    let query = format!("{{ {collection}(limit: 1) {{ _docID }} }}");
    let deadline = Instant::now() + timeout;
    loop {
        if gql(http, url, &query).await.is_ok() {
            return Ok(());
        }
        eyre::ensure!(
            Instant::now() < deadline,
            "no healthy GraphQL answer within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600_000;

    fn plan(seed: u64) -> Vec<ChurnEvent> {
        schedule_with(seed, 2, HOUR, &ChurnConfig::default(), false)
    }

    #[test]
    fn same_seed_same_schedule() {
        assert_eq!(plan(5), plan(5));
        assert!(
            plan(5).len() >= 10,
            "an hour at ~2min spacing yields many events"
        );
    }

    #[test]
    fn different_seed_different_schedule() {
        assert_ne!(plan(5), plan(6));
    }

    #[test]
    fn ordered_within_horizon_and_cooldown() {
        let cfg = ChurnConfig::default();
        let events = plan(9);
        let mut last_end = [0u64; 2];
        let mut prev = 0;
        for e in &events {
            assert!(e.virtual_ts_ms < HOUR);
            assert!(e.virtual_ts_ms >= prev, "events must be time-ordered");
            assert!(
                e.virtual_ts_ms >= last_end[e.node] + cfg.cooldown_ms || last_end[e.node] == 0,
                "node {} event at {} violates cooldown after {}",
                e.node,
                e.virtual_ts_ms,
                last_end[e.node]
            );
            last_end[e.node] = e.virtual_ts_ms + e.down_ms;
            prev = e.virtual_ts_ms;
        }
    }

    #[test]
    fn down_time_within_bounds_and_all_kinds_drawn() {
        let cfg = ChurnConfig::default();
        let events = plan(3);
        for kind in [
            ChurnKind::Restart,
            ChurnKind::CrashKill,
            ChurnKind::GracefulLeave,
        ] {
            assert!(
                events.iter().any(|e| e.kind == kind),
                "{kind:?} never drawn"
            );
        }
        for e in &events {
            match e.kind {
                ChurnKind::Restart => assert_eq!(e.down_ms, 0),
                _ => assert!((cfg.down_ms.0..=cfg.down_ms.1).contains(&e.down_ms)),
            }
        }
    }

    /// Replay redraws the schedule from the seed, so the draws without the
    /// Partition kind are frozen: these are the first events of seed 106.
    #[test]
    fn process_schedule_is_unchanged_without_partition() {
        let ev = schedule_with(106, 4, 1_800_000, &ChurnConfig::default(), false);
        let head: Vec<_> = ev
            .iter()
            .take(4)
            .map(|e| (e.virtual_ts_ms, e.node, e.kind, e.down_ms))
            .collect();
        assert_eq!(
            head,
            [
                (174_829, 3, ChurnKind::CrashKill, 26_658),
                (348_896, 2, ChurnKind::CrashKill, 15_703),
                (470_098, 3, ChurnKind::GracefulLeave, 14_878),
                (635_362, 2, ChurnKind::Restart, 0),
            ]
        );
    }

    #[test]
    fn docker_schedule_draws_partitions() {
        let cfg = ChurnConfig::default();
        let ev = schedule_with(106, 6, 1_800_000, &cfg, true);
        assert!(ev.iter().any(|e| e.kind == ChurnKind::Partition));
        assert!(ev
            .iter()
            .filter(|e| e.kind == ChurnKind::Partition)
            .all(|e| (cfg.down_ms.0..=cfg.down_ms.1).contains(&e.down_ms)));
    }
}
