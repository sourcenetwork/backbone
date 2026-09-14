//! Convergence checker for one node pair.
//!
//! Every check: M1 docID-set diff over each collection (one POST per node),
//! then M3 head-CID diff (`_commits(docID, depth: 1)`, alias-batched) over
//! the docs touched since the last check plus a cold sample; the shutdown
//! check sweeps M3 over every shared doc. Mismatches pass through
//! [`Confirmer`] before they become records in `divergences.jsonl`; every
//! check appends a line to `checks.jsonl`.
//!
//! ponytail: the M1 sweep is O(docs) per check, fine at M0 scale (<100k
//! docs); add recent-window scoping for M1 when a sweep exceeds ~1s.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eyre::{eyre, Result, WrapErr};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::churn::Transition;
use crate::confirm::{Confirmer, Key};
use crate::executor::{gql, now_ms};

/// A confirmed mismatch: key, detail, checks it persisted across.
type Confirmed = (Key, Value, u32);

/// A doc the workload just wrote; feeds M3 scoping and, for creates, the
/// convergence-lag samples.
#[derive(Debug)]
pub struct Touch {
    pub doc_id: String,
    pub node: String,
    pub wall_ts_ms: u64,
    pub create: bool,
}

/// Forget a create still unseen on the other side after this long; by then
/// it is a divergence, not a lag sample.
const LAG_TTL_MS: u64 = 900_000;

pub struct CheckerConfig {
    pub interval: Duration,
    /// A mismatch younger than this is "sync in flight", never a divergence.
    /// Both runtimes retry a failed push after 30s then 60s, so a doc whose
    /// push failed twice lands at ~90s; the default covers that.
    pub grace: Duration,
    pub confirmations: u32,
    /// Untouched shared docs to head-check per interval check.
    pub cold_sample: usize,
    /// `_commits` aliases per POST.
    pub batch: usize,
    /// After the workload stops, keep checking this long for a clear check
    /// before the final sweep, so in-flight sync is not read as divergence.
    pub settle: Duration,
}

impl Default for CheckerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            grace: Duration::from_secs(120),
            confirmations: 3,
            cold_sample: 50,
            batch: 100,
            settle: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub checks: u64,
    pub unreachable: u64,
    /// Divergence records written.
    pub divergences: u64,
    /// Confirmed mismatches still present at the final sweep.
    pub unresolved: usize,
    /// Mismatches in the final full sweep, whatever their eligibility.
    pub final_mismatches: usize,
    /// Whether the final sweep was eligible (no node down or in grace).
    pub final_eligible: bool,
}

pub struct Checker {
    http: reqwest::Client,
    /// (name, api_url) of side 0 and side 1.
    pair: [(String, String); 2],
    collections: Vec<String>,
    cfg: CheckerConfig,
    rng: StdRng,
    confirmer: Confirmer,
    run_id: String,
    seed: u64,
    /// Ops issued so far, kept current by the driver.
    op_index: Arc<AtomicU64>,
    /// Op index at the last check with zero mismatches; the record's
    /// event window starts here.
    last_clear_op: u64,
    /// Nodes currently down per the churner.
    down: HashSet<usize>,
    /// Mismatches before this instant are expected (a node came back less
    /// than `grace` ago).
    eligible_at: Instant,
    checks: BufWriter<File>,
    divergences: BufWriter<File>,
    /// Every mismatch of the final sweep, confirmed or not.
    final_sweep: BufWriter<File>,
    /// Creates not yet seen on the other side: doc -> (origin side, wall ms).
    awaiting: HashMap<String, (usize, u64)>,
    /// Node down/up transitions since the last clear check, for the
    /// record's event window.
    window_events: Vec<Value>,
    lag: BufWriter<File>,
    summary: Summary,
}

impl Checker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pair: [(String, String); 2],
        collections: Vec<String>,
        cfg: CheckerConfig,
        seed: u64,
        run_id: String,
        op_index: Arc<AtomicU64>,
        run_dir: &Path,
    ) -> Result<Self> {
        let open = |name: &str| -> Result<BufWriter<File>> {
            let path = run_dir.join(name);
            Ok(BufWriter::new(File::create(&path).wrap_err_with(|| {
                format!("creating {}", path.display())
            })?))
        };
        Ok(Self {
            http: reqwest::Client::new(),
            pair,
            collections,
            confirmer: Confirmer::new(cfg.confirmations, cfg.grace),
            cfg,
            rng: StdRng::seed_from_u64(seed),
            run_id,
            seed,
            op_index,
            last_clear_op: 0,
            down: HashSet::new(),
            eligible_at: Instant::now(),
            checks: open("checks.jsonl")?,
            divergences: open("divergences.jsonl")?,
            final_sweep: open("final_sweep.jsonl")?,
            awaiting: HashMap::new(),
            window_events: Vec::new(),
            lag: open("lag.jsonl")?,
            summary: Summary::default(),
        })
    }

    /// Check every `interval` until `stop` fires, then settle and run the
    /// full sweep. `touched` feeds docIDs the workload wrote since the last
    /// check; `transitions` feeds node down/up events from the churner.
    pub async fn run(
        mut self,
        mut touched: mpsc::UnboundedReceiver<Touch>,
        mut transitions: mpsc::UnboundedReceiver<Transition>,
        mut stop: oneshot::Receiver<()>,
    ) -> Result<Summary> {
        let mut tick = tokio::time::interval(self.cfg.interval);
        tick.tick().await; // the immediate first tick
        let mut recent = HashSet::new();
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    while let Ok(t) = touched.try_recv() {
                        self.note(t, &mut recent);
                    }
                    self.check(std::mem::take(&mut recent), &mut transitions, false)
                        .await?;
                }
                _ = &mut stop => {
                    // Settle: keep checking until a clear, eligible check or
                    // the budget runs out, then sweep everything.
                    let deadline = Instant::now() + self.cfg.settle;
                    loop {
                        while let Ok(t) = touched.try_recv() {
                            self.note(t, &mut recent);
                        }
                        let (clear, eligible) = self
                            .check(std::mem::take(&mut recent), &mut transitions, false)
                            .await?;
                        if (clear && eligible) || Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::sleep(self.cfg.interval).await;
                    }
                    self.check(HashSet::new(), &mut transitions, true).await?;
                    self.summary.unresolved = self.confirmer.unresolved();
                    return Ok(self.summary);
                }
            }
        }
    }

    fn note(&mut self, t: Touch, recent: &mut HashSet<String>) {
        if t.create {
            if let Some(side) = self.pair.iter().position(|(n, _)| *n == t.node) {
                self.awaiting.insert(t.doc_id.clone(), (side, t.wall_ts_ms));
            }
        }
        recent.insert(t.doc_id);
    }

    /// One check; returns (clear, eligible). `Err` only for log I/O; an
    /// unreachable node is logged and leaves the confirmer untouched, so
    /// pending mismatches survive it. While a node is down, or for `grace`
    /// after it came back, mismatches are expected and skip the confirmer.
    async fn check(
        &mut self,
        recent: HashSet<String>,
        transitions: &mut mpsc::UnboundedReceiver<Transition>,
        full: bool,
    ) -> Result<(bool, bool)> {
        let now = Instant::now();
        while let Ok(t) = transitions.try_recv() {
            if t.up {
                self.down.remove(&t.node);
                self.eligible_at = now + self.cfg.grace;
            } else {
                self.down.insert(t.node);
            }
            let node = self.pair.get(t.node).map(|(n, _)| n.as_str());
            self.window_events.push(json!({
                "node": node, "up": t.up, "wall_ts_ms": now_ms(),
            }));
        }
        let eligible = self.down.is_empty() && now >= self.eligible_at;
        let op_index = self.op_index.load(Ordering::Relaxed);
        let mut line = json!({
            "wall_ts_ms": now_ms(), "op_index": op_index, "full": full, "eligible": eligible,
        });
        self.summary.checks += 1;
        let mut clear = false;
        match self.compare(&recent, full).await {
            Err(e) => {
                self.summary.unreachable += 1;
                line["status"] = json!("unreachable");
                line["error"] = json!(e.to_string());
            }
            Ok((mismatches, m3_docs)) => {
                let n = mismatches.len();
                if full {
                    self.summary.final_mismatches = n;
                    self.summary.final_eligible = eligible;
                    for ((col, mech, id), detail) in &mismatches {
                        let line = json!({
                            "collection": col, "mechanism": mech, "doc_id": id, "detail": detail,
                        });
                        serde_json::to_writer(&mut self.final_sweep, &line)?;
                        self.final_sweep.write_all(b"\n")?;
                    }
                    self.final_sweep.flush()?;
                }
                let (status, confirmed) = if n == 0 {
                    // Tell the confirmer everything cleared: consecutive
                    // means consecutive, and emitted entries stop counting
                    // as unresolved.
                    self.confirmer.observe::<Value>(now, Vec::new());
                    self.last_clear_op = op_index;
                    self.window_events.clear();
                    clear = true;
                    ("clear", 0)
                } else if !eligible {
                    ("expected", 0)
                } else {
                    let confirmed = self.confirmer.observe(now, mismatches);
                    self.record(&confirmed, op_index)?;
                    ("mismatch", confirmed.len())
                };
                line["status"] = json!(status);
                line["m3_docs"] = json!(m3_docs);
                line["mismatches"] = json!(n);
                line["pending"] = json!(self.confirmer.pending());
                line["confirmed"] = json!(confirmed);
            }
        }
        serde_json::to_writer(&mut self.checks, &line)?;
        self.checks.write_all(b"\n")?;
        self.checks.flush()?;
        Ok((clear, eligible))
    }

    /// M1 + M3 over all collections. Returns the mismatches and how many
    /// docs got a head check.
    async fn compare(
        &mut self,
        recent: &HashSet<String>,
        full: bool,
    ) -> Result<(Vec<(Key, Value)>, usize)> {
        let mut mismatches = Vec::new();
        let mut m3_docs = 0;
        for col in self.collections.clone() {
            let ids = [self.doc_ids(0, &col).await?, self.doc_ids(1, &col).await?];
            self.sample_lag(&ids)?;
            for side in 0..2 {
                for id in ids[side].difference(&ids[1 - side]) {
                    let missing_on = &self.pair[1 - side].0;
                    mismatches.push((
                        (col.clone(), "M1", id.clone()),
                        json!({ "missing_on": missing_on }),
                    ));
                }
            }
            let shared: Vec<&String> = ids[0].intersection(&ids[1]).collect();
            let targets: Vec<String> = if full {
                shared.iter().map(|s| s.to_string()).collect()
            } else {
                let (hot, cold): (Vec<&String>, Vec<&String>) =
                    shared.iter().partition(|id| recent.contains(**id));
                hot.into_iter()
                    .chain(
                        cold.choose_multiple(&mut self.rng, self.cfg.cold_sample)
                            .copied(),
                    )
                    .cloned()
                    .collect()
            };
            m3_docs += targets.len();
            for chunk in targets.chunks(self.cfg.batch) {
                let heads = [self.heads(0, chunk).await?, self.heads(1, chunk).await?];
                for id in chunk {
                    if heads[0][id] != heads[1][id] {
                        mismatches.push((
                            (col.clone(), "M3", id.clone()),
                            json!({ "heads_a": heads[0][id], "heads_b": heads[1][id] }),
                        ));
                    }
                }
            }
        }
        Ok((mismatches, m3_docs))
    }

    /// One record per (collection, mechanism) confirmed in this check.
    fn record(&mut self, confirmed: &[Confirmed], op_index: u64) -> Result<()> {
        let mut groups: HashMap<(String, &'static str), Vec<&Confirmed>> = HashMap::new();
        for c in confirmed {
            groups.entry((c.0 .0.clone(), c.0 .1)).or_default().push(c);
        }
        let mut keys: Vec<_> = groups.keys().cloned().collect();
        keys.sort();
        for (col, mech) in keys {
            let items = &groups[&(col.clone(), mech)];
            let record = json!({
                "run_id": self.run_id,
                "seed": self.seed,
                "detected_wall_ts_ms": now_ms(),
                "detected_op_index": op_index,
                "pair": [self.pair[0].0, self.pair[1].0],
                "collection": col,
                "mechanism": mech,
                "doc_ids": items.iter().map(|i| &i.0 .2).collect::<Vec<_>>(),
                "details": items.iter().map(|i| &i.1).collect::<Vec<_>>(),
                "event_window": {
                    "op_index": [self.last_clear_op, op_index],
                    "topology_events": self.window_events,
                },
                "tags": tags(),
                "confirmations": items.iter().map(|i| i.2).max().unwrap_or(0),
            });
            serde_json::to_writer(&mut self.divergences, &record)?;
            self.divergences.write_all(b"\n")?;
            self.divergences.flush()?;
            self.summary.divergences += 1;
            println!(
                "DIVERGENCE {mech} {col}: {} doc(s), window ops {}..{}",
                items.len(),
                self.last_clear_op,
                op_index
            );
        }
        Ok(())
    }

    /// Creates now visible on the other side become lag samples; the
    /// resolution is the check interval.
    fn sample_lag(&mut self, ids: &[HashSet<String>; 2]) -> Result<()> {
        let now = now_ms();
        let op_index = self.op_index.load(Ordering::Relaxed);
        let pair = &self.pair;
        let mut lines = Vec::new();
        self.awaiting.retain(|doc, (side, created)| {
            if !ids[*side].contains(doc) {
                return now.saturating_sub(*created) < LAG_TTL_MS;
            }
            if !ids[1 - *side].contains(doc) {
                return true;
            }
            lines.push(json!({
                "wall_ts_ms": now, "op_index": op_index, "doc_id": doc,
                "from": pair[*side].0, "to": pair[1 - *side].0,
                "lag_ms": now.saturating_sub(*created),
            }));
            false
        });
        for line in lines {
            serde_json::to_writer(&mut self.lag, &line)?;
            self.lag.write_all(b"\n")?;
        }
        self.lag.flush()?;
        Ok(())
    }

    async fn doc_ids(&self, side: usize, col: &str) -> Result<HashSet<String>> {
        let (name, url) = &self.pair[side];
        let data = gql(&self.http, url, &format!("{{ {col} {{ _docID }} }}"))
            .await
            .map_err(|e| eyre!("{name}: docID sweep of {col}: {e}"))?;
        Ok(data[col]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["_docID"].as_str().map(String::from))
            .collect())
    }

    /// Sorted head CIDs per docID, one POST for the whole chunk.
    async fn heads(&self, side: usize, ids: &[String]) -> Result<HashMap<String, Vec<String>>> {
        let (name, url) = &self.pair[side];
        let selections: Vec<String> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| format!("d{i}: _commits(docID: \"{id}\", depth: 1) {{ cid }}"))
            .collect();
        let data = gql(&self.http, url, &format!("{{ {} }}", selections.join(" ")))
            .await
            .map_err(|e| eyre!("{name}: head query for {} docs: {e}", ids.len()))?;
        Ok(ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let mut cids: Vec<String> = data[format!("d{i}")]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["cid"].as_str().map(String::from))
                    .collect();
                cids.sort();
                (id.clone(), cids)
            })
            .collect())
    }
}

/// Known-issue tags for a divergence. The rules table arrives with the
/// encryption surface (M3 of the roadmap); nothing in the P0 profile can
/// match a known issue yet.
fn tags() -> Vec<String> {
    Vec::new()
}
