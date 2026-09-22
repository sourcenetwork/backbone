//! Convergence checker for an N-node mesh.
//!
//! Every check: the docID set of each collection is fetched once per node
//! (M1), diffed for every pair; head CIDs (`_commits(docID, depth: 1)`) are
//! fetched once per node over the docs touched since the last check plus a
//! cold sample (M3) and diffed per pair; the shutdown check sweeps every
//! shared doc. A pair is eligible when both members are up and past
//! `grace` since their last recovery; mismatches on ineligible pairs are
//! expected and their pending state is frozen. Eligible mismatches pass
//! through [`Confirmer`] before they become records in `divergences.jsonl`;
//! every check appends a line to `checks.jsonl`.
//!
//! ponytail: the M1 sweep is O(docs) per node per check, fine at M1 scale
//! (<20k docs); add recent-window scoping when a check exceeds ~1s.

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

use crate::auth::{Identities, TokenCache};
use crate::churn::Transition;
use crate::confirm::{Confirmer, Key};
use crate::executor::{gql_as, http_client, now_ms};
use crate::generator::Actor;
use crate::sse::Arrival;
use crate::tags::{tag, Outage, Tag};

/// After the last subscription event, this much silence triggers a check
/// ahead of the clock.
const QUIET: Duration = Duration::from_secs(5);

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
    /// Creates on ACP profiles: whether the doc got a policy (owner-created).
    /// None on p0/p1 and on non-creates.
    pub protected: Option<bool>,
}

/// Forget a create still unseen somewhere after this long; by then it is a
/// divergence, not a lag sample.
const LAG_TTL_MS: u64 = 900_000;

/// docID -> one value per configured encrypted field (None = null/absent).
pub type FieldMap = HashMap<String, Vec<Option<String>>>;

/// M5: a doc both nodes hold must read the same plaintext on both. A null
/// or empty value on one side only is "replicated but undecryptable".
pub fn m5_compare(
    a: &FieldMap,
    b: &FieldMap,
    node_a: &str,
    node_b: &str,
    targets: &[String],
    fields: &[String],
) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for id in targets {
        let (Some(x), Some(y)) = (a.get(id), b.get(id)) else {
            continue;
        };
        for (i, field) in fields.iter().enumerate() {
            let (vx, vy) = (x.get(i).cloned().flatten(), y.get(i).cloned().flatten());
            let empty = |v: &Option<String>| v.as_deref().is_none_or(str::is_empty);
            let detail = match (empty(&vx), empty(&vy)) {
                (true, true) => continue,
                (true, false) => json!({ "undecryptable_on": node_a, "field": field }),
                (false, true) => json!({ "undecryptable_on": node_b, "field": field }),
                (false, false) if vx != vy => {
                    json!({ "field": field, "a": short(&vx), "b": short(&vy) })
                }
                _ => continue,
            };
            out.push((id.clone(), detail));
            break;
        }
    }
    out
}

/// First 8 chars: enough to see two values differ without logging secrets.
/// Settle ends once the floor has been served and either the mesh is clear
/// or the budget is spent. A zero floor is the historical early exit.
fn settle_done(elapsed: Duration, min_settle: Duration, settle: Duration, clear: bool) -> bool {
    elapsed >= min_settle && (clear || elapsed >= settle)
}

fn short(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("").chars().take(8).collect()
}

/// docID -> visible to [owner, reader, anon].
pub type ViewMap = HashMap<String, [bool; 3]>;
const VIEWERS: [&str; 3] = ["owner", "reader", "anon"];
const VIEWER_ACTORS: [Actor; 3] = [Actor::Owner, Actor::Reader, Actor::Anon];

/// M6: the three views of a protected doc must agree across a pair unless
/// exactly one side is the doc's origin node (local ACP gates only there).
pub fn m6_compare(
    a: &ViewMap,
    b: &ViewMap,
    names: &[String],
    idx_a: usize,
    idx_b: usize,
    origin: &HashMap<String, usize>,
    targets: &[String],
) -> (Vec<(String, Value)>, usize) {
    let mut out = Vec::new();
    let mut by_design = 0;
    for id in targets {
        let (Some(x), Some(y), Some(o)) = (a.get(id), b.get(id), origin.get(id)) else {
            continue;
        };
        if (*o == idx_a) != (*o == idx_b) {
            by_design += 1;
            continue;
        }
        if let Some(i) = (0..3).find(|i| x[*i] != y[*i]) {
            out.push((
                id.clone(),
                json!({ "viewer": VIEWERS[i], "a": x[i], "b": y[i], "origin": names[*o] }),
            ));
        }
    }
    (out, by_design)
}

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
    /// Settle for at least this long even if the mesh is already clear, so a
    /// run that wants an idle sample gets one after the load stops.
    pub min_settle: Duration,
    /// Encrypted fields to compare as plaintext (M5); empty = off.
    pub encrypted_fields: Vec<String>,
    /// Owner/reader identities for the access-parity views (M6); None = off.
    pub acp: Option<Identities>,
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
            min_settle: Duration::ZERO,
            encrypted_fields: Vec::new(),
            acp: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub checks: u64,
    /// Checks in which at least one node did not answer.
    pub unreachable: u64,
    /// Divergence records written.
    pub divergences: u64,
    /// Confirmed mismatches still present at the final sweep.
    pub unresolved: usize,
    /// Mismatches in the final full sweep over every pair.
    pub final_mismatches: usize,
    /// Whether every pair was eligible and every node reachable at the sweep.
    pub final_eligible: bool,
    /// Divergent docs in records with a known-cause tag, and without one.
    pub tagged_docs: u64,
    pub untagged_docs: u64,
    /// Subscription events received per node.
    pub sse_events: Vec<u64>,
    /// Checks triggered by quiescence rather than the clock.
    pub quiet_checks: u64,
    /// Docs whose plaintext was compared on both sides of a pair (M5), summed
    /// over checks; zero means M5 never compared anything.
    pub m5_docs: u64,
    /// Protected docs whose three views were compared across a pair (M6),
    /// and those skipped because one side was the doc's origin node.
    pub m6_docs: u64,
    pub m6_by_design: u64,
}

/// What one comparison pass found.
struct Compared {
    /// Mismatches on eligible pairs.
    mismatches: Vec<(Key, Value)>,
    /// All mismatches, eligible or not, with their pair (for the final sweep).
    all: Vec<(Key, Value)>,
    m3_docs: usize,
    /// Docs present in both maps of a pair and so actually compared by M5.
    m5_docs: usize,
    m6_docs: usize,
    m6_by_design: usize,
    unreachable: Vec<usize>,
}

pub struct Checker {
    http: reqwest::Client,
    /// (name, api_url) per node index.
    nodes: Vec<(String, String)>,
    /// Unordered pairs (a < b) and their key string `"<a>|<b>"`.
    pairs: Vec<(usize, usize, String)>,
    collections: Vec<String>,
    cfg: CheckerConfig,
    /// Bearer tokens for the M6 views; None off ACP profiles.
    tokens: Option<TokenCache>,
    rng: StdRng,
    confirmer: Confirmer,
    run_id: String,
    seed: u64,
    /// Ops issued so far, kept current by the driver.
    op_index: Arc<AtomicU64>,
    /// Op index at the last fully clear check; the record's event window
    /// starts here.
    last_clear_op: u64,
    /// Nodes currently down per the churner.
    down: HashSet<usize>,
    /// Per node: mismatches before this instant are expected (it came back
    /// less than `grace` ago).
    eligible_at: Vec<Instant>,
    /// Node down/up transitions since the last clear check.
    window_events: Vec<Value>,
    /// Every outage so far, for the known-cause tags.
    outages: Vec<Outage>,
    /// Last successful write per doc: (node, wall ms).
    last_write: HashMap<String, (usize, u64)>,
    /// Per created doc: (origin node index, protected), from creates.
    doc_meta: HashMap<String, (usize, bool)>,
    checks: BufWriter<File>,
    divergences: BufWriter<File>,
    /// Every mismatch of the final sweep, confirmed or not.
    final_sweep: BufWriter<File>,
    /// Creates not yet seen everywhere: doc -> (origin, wall ms, nodes seen on).
    awaiting: HashMap<String, (usize, u64, HashSet<usize>)>,
    lag: BufWriter<File>,
    summary: Summary,
}

impl Checker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nodes: Vec<(String, String)>,
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
        let mut pairs = Vec::new();
        for a in 0..nodes.len() {
            for b in a + 1..nodes.len() {
                pairs.push((a, b, format!("{}|{}", nodes[a].0, nodes[b].0)));
            }
        }
        Ok(Self {
            http: http_client(Duration::from_secs(30)),
            eligible_at: vec![Instant::now(); nodes.len()],
            nodes,
            pairs,
            collections,
            confirmer: Confirmer::new(cfg.confirmations, cfg.grace),
            tokens: cfg.acp.clone().map(TokenCache::new),
            cfg,
            rng: StdRng::seed_from_u64(seed),
            run_id,
            seed,
            op_index,
            last_clear_op: 0,
            down: HashSet::new(),
            window_events: Vec::new(),
            outages: Vec::new(),
            last_write: HashMap::new(),
            doc_meta: HashMap::new(),
            checks: open("checks.jsonl")?,
            divergences: open("divergences.jsonl")?,
            final_sweep: open("final_sweep.jsonl")?,
            awaiting: HashMap::new(),
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
        mut arrivals: mpsc::UnboundedReceiver<Arrival>,
        mut stop: oneshot::Receiver<()>,
    ) -> Result<Summary> {
        self.summary.sse_events = vec![0; self.nodes.len()];
        let mut tick = tokio::time::interval(self.cfg.interval);
        tick.tick().await; // the immediate first tick
        let mut recent = HashSet::new();
        let mut quiet_until: Option<tokio::time::Instant> = None;
        loop {
            let quiet = async {
                match quiet_until {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = tick.tick() => {
                    while let Ok(t) = touched.try_recv() {
                        self.note(t, &mut recent);
                    }
                    self.check(std::mem::take(&mut recent), &mut transitions, false)
                        .await?;
                }
                Some(a) = arrivals.recv() => {
                    self.arrival(a, &mut recent)?;
                    quiet_until = Some(tokio::time::Instant::now() + QUIET);
                }
                _ = quiet => {
                    quiet_until = None;
                    self.summary.quiet_checks += 1;
                    while let Ok(t) = touched.try_recv() {
                        self.note(t, &mut recent);
                    }
                    self.check(std::mem::take(&mut recent), &mut transitions, false)
                        .await?;
                    tick.reset();
                }
                _ = &mut stop => {
                    // Settle: keep checking until a fully clear, eligible
                    // check or the budget runs out, then sweep everything.
                    let started = Instant::now();
                    loop {
                        while let Ok(t) = touched.try_recv() {
                            self.note(t, &mut recent);
                        }
                        while let Ok(a) = arrivals.try_recv() {
                            self.arrival(a, &mut recent)?;
                        }
                        let clear = self
                            .check(std::mem::take(&mut recent), &mut transitions, false)
                            .await?;
                        if settle_done(started.elapsed(), self.cfg.min_settle, self.cfg.settle, clear)
                        {
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
        if let Some(node) = self.nodes.iter().position(|(n, _)| *n == t.node) {
            if t.create {
                self.awaiting
                    .insert(t.doc_id.clone(), (node, t.wall_ts_ms, HashSet::new()));
                if let Some(protected) = t.protected {
                    self.doc_meta.insert(t.doc_id.clone(), (node, protected));
                }
            }
            self.last_write
                .insert(t.doc_id.clone(), (node, t.wall_ts_ms));
        }
        recent.insert(t.doc_id);
    }

    /// A subscription event: the doc is recent for M3, and if it is a create
    /// still awaited on that node, a lag sample with event-time resolution.
    fn arrival(&mut self, a: Arrival, recent: &mut HashSet<String>) -> Result<()> {
        if let Some(c) = self.summary.sse_events.get_mut(a.node) {
            *c += 1;
        }
        let total = self.nodes.len();
        let mut line = None;
        if let Some((origin, created, seen)) = self.awaiting.get_mut(&a.doc_id) {
            if *origin != a.node && seen.insert(a.node) {
                line = Some(json!({
                    "wall_ts_ms": a.wall_ts_ms, "op_index": self.op_index.load(Ordering::Relaxed),
                    "doc_id": a.doc_id, "from": self.nodes[*origin].0, "to": self.nodes[a.node].0,
                    "lag_ms": a.wall_ts_ms.saturating_sub(*created), "source": "sse",
                }));
                if seen.len() >= total - 1 {
                    self.awaiting.remove(&a.doc_id);
                }
            }
        }
        if let Some(line) = line {
            serde_json::to_writer(&mut self.lag, &line)?;
            self.lag.write_all(b"\n")?;
            self.lag.flush()?;
        }
        recent.insert(a.doc_id);
        Ok(())
    }

    /// Known-cause tag for `doc` diverging on the pair `key`.
    fn tag_for(&self, key: &str, doc: &str) -> Option<Tag> {
        let (a, b, _) = self.pairs.iter().find(|(_, _, k)| k == key)?;
        let (writer, wall) = self.last_write.get(doc)?;
        tag(*writer, *wall, (*a, *b), &self.outages)
    }

    /// One check; returns whether it was fully clear (no mismatch on any
    /// eligible pair, every pair eligible, every node reachable). `Err` only
    /// for log I/O. A node that does not answer is treated as ineligible for
    /// this check, so its pairs' pending state is frozen, not cleared.
    async fn check(
        &mut self,
        recent: HashSet<String>,
        transitions: &mut mpsc::UnboundedReceiver<Transition>,
        full: bool,
    ) -> Result<bool> {
        let now = Instant::now();
        while let Ok(t) = transitions.try_recv() {
            if t.up {
                self.down.remove(&t.node);
                if let Some(e) = self.eligible_at.get_mut(t.node) {
                    *e = now + self.cfg.grace;
                }
                if let Some(o) = self
                    .outages
                    .iter_mut()
                    .rev()
                    .find(|o| o.node == t.node && o.up_ms.is_none())
                {
                    o.up_ms = Some(t.wall_ts_ms);
                }
            } else {
                self.down.insert(t.node);
                self.outages.push(Outage {
                    node: t.node,
                    down_ms: t.wall_ts_ms,
                    up_ms: None,
                });
            }
            let node = self.nodes.get(t.node).map(|(n, _)| n.as_str());
            self.window_events.push(json!({
                "node": node, "up": t.up, "wall_ts_ms": t.wall_ts_ms,
            }));
        }
        let mut node_ok: Vec<bool> = (0..self.nodes.len())
            .map(|n| !self.down.contains(&n) && now >= self.eligible_at[n])
            .collect();
        let op_index = self.op_index.load(Ordering::Relaxed);
        self.summary.checks += 1;

        let compared = self.compare(&recent, full, &mut node_ok).await?;
        self.summary.m5_docs += compared.m5_docs as u64;
        self.summary.m6_docs += compared.m6_docs as u64;
        self.summary.m6_by_design += compared.m6_by_design as u64;
        let eligible_pairs = self
            .pairs
            .iter()
            .filter(|(a, b, _)| node_ok[*a] && node_ok[*b])
            .count();
        let all_eligible = eligible_pairs == self.pairs.len();
        let n = compared.mismatches.len();
        let expected = compared.all.len() - n;
        if full {
            self.summary.final_mismatches = compared.all.len();
            self.summary.final_eligible = all_eligible && compared.unreachable.is_empty();
            for ((pair, col, mech, id), detail) in &compared.all {
                let line = json!({
                    "pair": pair, "collection": col, "mechanism": mech, "doc_id": id,
                    "detail": detail, "tag": self.tag_for(pair, id),
                });
                serde_json::to_writer(&mut self.final_sweep, &line)?;
                self.final_sweep.write_all(b"\n")?;
            }
            self.final_sweep.flush()?;
        }
        let ineligible: HashSet<String> = self
            .pairs
            .iter()
            .filter(|(a, b, _)| !(node_ok[*a] && node_ok[*b]))
            .map(|(_, _, key)| key.clone())
            .collect();
        let confirmed = self
            .confirmer
            .observe(now, compared.mismatches, |k| ineligible.contains(&k.0));
        self.record(&confirmed, op_index)?;
        let clear = n == 0 && all_eligible && compared.unreachable.is_empty();
        if clear {
            self.last_clear_op = op_index;
            self.window_events.clear();
        }
        if !compared.unreachable.is_empty() {
            self.summary.unreachable += 1;
        }
        let status = if clear {
            "clear"
        } else if !compared.unreachable.is_empty() {
            "unreachable"
        } else if n == 0 {
            "expected"
        } else {
            "mismatch"
        };
        let line = json!({
            "wall_ts_ms": now_ms(), "op_index": op_index, "full": full,
            "eligible": all_eligible, "eligible_pairs": eligible_pairs,
            "unreachable_nodes": compared.unreachable.iter().map(|n| &self.nodes[*n].0).collect::<Vec<_>>(),
            "status": status, "m3_docs": compared.m3_docs, "m5_docs": compared.m5_docs, "mismatches": n, "expected": expected,
            "m6_docs": compared.m6_docs, "m6_by_design": compared.m6_by_design,
            "pending": self.confirmer.pending(), "confirmed": confirmed.len(),
            "duration_ms": now.elapsed().as_millis() as u64,
        });
        serde_json::to_writer(&mut self.checks, &line)?;
        self.checks.write_all(b"\n")?;
        self.checks.flush()?;
        Ok(clear)
    }

    /// M1 + M3 (+ M5 for encrypted, M6 for ACP profiles) over all collections
    /// and pairs. On ACP profiles the sweeps and fetches read as the owner so
    /// protected documents are in scope; only the reader and anonymous views
    /// of M6 use their own identities.
    /// A node whose queries fail is added to `unreachable` and cleared in
    /// `node_ok`.
    async fn compare(
        &mut self,
        recent: &HashSet<String>,
        full: bool,
        node_ok: &mut [bool],
    ) -> Result<Compared> {
        let mut out = Compared {
            mismatches: Vec::new(),
            all: Vec::new(),
            m3_docs: 0,
            m5_docs: 0,
            m6_docs: 0,
            m6_by_design: 0,
            unreachable: Vec::new(),
        };
        for col in self.collections.clone() {
            let mut ids: Vec<Option<HashSet<String>>> = Vec::new();
            for (n, ok) in node_ok.iter_mut().enumerate() {
                match self.doc_ids(n, &col).await {
                    Ok(set) => ids.push(Some(set)),
                    Err(_) => {
                        ids.push(None);
                        if !out.unreachable.contains(&n) {
                            out.unreachable.push(n);
                        }
                        *ok = false;
                    }
                }
            }
            self.sample_lag(&ids)?;

            // M1 per pair.
            for (a, b, key) in &self.pairs {
                let (Some(sa), Some(sb)) = (&ids[*a], &ids[*b]) else {
                    continue;
                };
                let eligible = node_ok[*a] && node_ok[*b];
                for (from, to, missing) in [(sa, sb, *b), (sb, sa, *a)] {
                    for id in from.difference(to) {
                        let entry = (
                            (key.clone(), col.clone(), "M1", id.clone()),
                            json!({ "missing_on": self.nodes[missing].0 }),
                        );
                        if eligible {
                            out.mismatches.push(entry.clone());
                        }
                        out.all.push(entry);
                    }
                }
            }

            // M3: heads fetched once per node over the union of targets.
            let mut held: HashMap<&String, usize> = HashMap::new();
            for set in ids.iter().flatten() {
                for id in set {
                    *held.entry(id).or_default() += 1;
                }
            }
            let universe: Vec<&String> = held
                .iter()
                .filter(|(_, n)| **n >= 2)
                .map(|(id, _)| *id)
                .collect();
            let targets: Vec<String> = if full {
                universe.iter().map(|s| s.to_string()).collect()
            } else {
                let (hot, cold): (Vec<&String>, Vec<&String>) =
                    universe.iter().partition(|id| recent.contains(**id));
                hot.into_iter()
                    .chain(
                        cold.choose_multiple(&mut self.rng, self.cfg.cold_sample)
                            .copied(),
                    )
                    .cloned()
                    .collect()
            };
            out.m3_docs += targets.len();
            let mut heads: Vec<Option<HashMap<String, Vec<String>>>> = Vec::new();
            for (n, set) in ids.iter().enumerate() {
                let Some(set) = set else {
                    heads.push(None);
                    continue;
                };
                let mine: Vec<String> = targets
                    .iter()
                    .filter(|t| set.contains(*t))
                    .cloned()
                    .collect();
                let mut map = HashMap::new();
                let mut failed = false;
                for chunk in mine.chunks(self.cfg.batch) {
                    match self.heads(n, chunk).await {
                        Ok(part) => map.extend(part),
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    heads.push(None);
                    if !out.unreachable.contains(&n) {
                        out.unreachable.push(n);
                    }
                    node_ok[n] = false;
                } else {
                    heads.push(Some(map));
                }
            }
            for (a, b, key) in &self.pairs {
                let (Some(ha), Some(hb)) = (&heads[*a], &heads[*b]) else {
                    continue;
                };
                let eligible = node_ok[*a] && node_ok[*b];
                for id in &targets {
                    let (Some(x), Some(y)) = (ha.get(id), hb.get(id)) else {
                        continue;
                    };
                    if x != y {
                        let entry = (
                            (key.clone(), col.clone(), "M3", id.clone()),
                            json!({ "heads_a": x, "heads_b": y }),
                        );
                        if eligible {
                            out.mismatches.push(entry.clone());
                        }
                        out.all.push(entry);
                    }
                }
            }
            // M5: plaintext parity on the same targets, only for encrypted profiles.
            if !self.cfg.encrypted_fields.is_empty() {
                let mut plain: Vec<Option<FieldMap>> = Vec::new();
                for (n, set) in ids.iter().enumerate() {
                    let Some(set) = set else {
                        plain.push(None);
                        continue;
                    };
                    let mine: Vec<String> = targets
                        .iter()
                        .filter(|t| set.contains(*t))
                        .cloned()
                        .collect();
                    let mut map = FieldMap::new();
                    let mut failed = false;
                    for chunk in mine.chunks(self.cfg.batch) {
                        match self.encrypted_fields(n, &col, chunk).await {
                            Ok(part) => map.extend(part),
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        plain.push(None);
                        if !out.unreachable.contains(&n) {
                            out.unreachable.push(n);
                        }
                        node_ok[n] = false;
                    } else {
                        plain.push(Some(map));
                    }
                }
                for (a, b, key) in &self.pairs {
                    let (Some(pa), Some(pb)) = (&plain[*a], &plain[*b]) else {
                        continue;
                    };
                    let eligible = node_ok[*a] && node_ok[*b];
                    out.m5_docs += pa.keys().filter(|id| pb.contains_key(*id)).count();
                    for (id, detail) in m5_compare(
                        pa,
                        pb,
                        &self.nodes[*a].0,
                        &self.nodes[*b].0,
                        &targets,
                        &self.cfg.encrypted_fields,
                    ) {
                        let entry = ((key.clone(), col.clone(), "M5", id), detail);
                        if eligible {
                            out.mismatches.push(entry.clone());
                        }
                        out.all.push(entry);
                    }
                }
            }
            // M6: access parity on the protected subset, only for ACP profiles.
            if self.cfg.acp.is_some() {
                let protected: Vec<String> = targets
                    .iter()
                    .filter(|id| self.doc_meta.get(*id).is_some_and(|m| m.1))
                    .cloned()
                    .collect();
                let origin: HashMap<String, usize> = protected
                    .iter()
                    .map(|id| (id.clone(), self.doc_meta[id].0))
                    .collect();
                let mut views: Vec<Option<ViewMap>> = Vec::new();
                for (n, set) in ids.iter().enumerate() {
                    let Some(set) = set else {
                        views.push(None);
                        continue;
                    };
                    let mine: Vec<String> = protected
                        .iter()
                        .filter(|t| set.contains(*t))
                        .cloned()
                        .collect();
                    let mut map = ViewMap::new();
                    let mut failed = false;
                    for chunk in mine.chunks(self.cfg.batch) {
                        match self.views(n, &col, chunk).await {
                            Ok(part) => map.extend(part),
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        views.push(None);
                        if !out.unreachable.contains(&n) {
                            out.unreachable.push(n);
                        }
                        node_ok[n] = false;
                    } else {
                        views.push(Some(map));
                    }
                }
                let names: Vec<String> = self.nodes.iter().map(|(n, _)| n.clone()).collect();
                for (a, b, key) in &self.pairs {
                    let (Some(va), Some(vb)) = (&views[*a], &views[*b]) else {
                        continue;
                    };
                    let eligible = node_ok[*a] && node_ok[*b];
                    let (found, by_design) =
                        m6_compare(va, vb, &names, *a, *b, &origin, &protected);
                    out.m6_docs += va.keys().filter(|id| vb.contains_key(*id)).count() - by_design;
                    out.m6_by_design += by_design;
                    for (id, detail) in found {
                        let entry = ((key.clone(), col.clone(), "M6", id), detail);
                        if eligible {
                            out.mismatches.push(entry.clone());
                        }
                        out.all.push(entry);
                    }
                }
            }
        }
        Ok(out)
    }

    /// One record per (pair, collection, mechanism) confirmed in this check.
    fn record(&mut self, confirmed: &[Confirmed], op_index: u64) -> Result<()> {
        let mut groups: HashMap<(String, String, &'static str), Vec<&Confirmed>> = HashMap::new();
        for c in confirmed {
            groups
                .entry((c.0 .0.clone(), c.0 .1.clone(), c.0 .2))
                .or_default()
                .push(c);
        }
        let mut keys: Vec<_> = groups.keys().cloned().collect();
        keys.sort();
        for (pair, col, mech) in keys {
            let items = &groups[&(pair.clone(), col.clone(), mech)];
            let members: Vec<&str> = pair.split('|').collect();
            let doc_tags: Vec<Option<Tag>> =
                items.iter().map(|i| self.tag_for(&pair, &i.0 .3)).collect();
            let mut tags: Vec<Tag> = doc_tags.iter().flatten().copied().collect();
            tags.sort_by_key(|t| *t as u8);
            tags.dedup();
            let untagged = doc_tags.iter().filter(|t| t.is_none()).count() as u64;
            self.summary.tagged_docs += doc_tags.len() as u64 - untagged;
            self.summary.untagged_docs += untagged;
            let record = json!({
                "run_id": self.run_id,
                "seed": self.seed,
                "detected_wall_ts_ms": now_ms(),
                "detected_op_index": op_index,
                "pair": members,
                "collection": col,
                "mechanism": mech,
                "doc_ids": items.iter().map(|i| &i.0 .3).collect::<Vec<_>>(),
                "details": items.iter().map(|i| &i.1).collect::<Vec<_>>(),
                "event_window": {
                    "op_index": [self.last_clear_op, op_index],
                    "topology_events": self.window_events,
                },
                "tags": tags,
                "doc_tags": doc_tags,
                "confirmations": items.iter().map(|i| i.2).max().unwrap_or(0),
            });
            serde_json::to_writer(&mut self.divergences, &record)?;
            self.divergences.write_all(b"\n")?;
            self.divergences.flush()?;
            self.summary.divergences += 1;
            println!(
                "DIVERGENCE {mech} {col} on {pair}: {} doc(s) ({untagged} untagged), window ops {}..{}",
                items.len(),
                self.last_clear_op,
                op_index
            );
        }
        Ok(())
    }

    /// Creates now visible on another node become lag samples for that
    /// directed pair; the resolution is the check interval.
    fn sample_lag(&mut self, ids: &[Option<HashSet<String>>]) -> Result<()> {
        let now = now_ms();
        let op_index = self.op_index.load(Ordering::Relaxed);
        let nodes = &self.nodes;
        let total = nodes.len();
        let mut lines = Vec::new();
        self.awaiting.retain(|doc, (origin, created, seen)| {
            for (n, set) in ids.iter().enumerate() {
                if n == *origin || seen.contains(&n) {
                    continue;
                }
                if set.as_ref().is_some_and(|s| s.contains(doc)) {
                    seen.insert(n);
                    lines.push(json!({
                        "wall_ts_ms": now, "op_index": op_index, "doc_id": doc,
                        "from": nodes[*origin].0, "to": nodes[n].0,
                        "lag_ms": now.saturating_sub(*created), "source": "poll",
                    }));
                }
            }
            seen.len() < total - 1 && now.saturating_sub(*created) < LAG_TTL_MS
        });
        for line in lines {
            serde_json::to_writer(&mut self.lag, &line)?;
            self.lag.write_all(b"\n")?;
        }
        self.lag.flush()?;
        Ok(())
    }

    /// The owner bearer when ACP is configured (protected docs are invisible
    /// to an anonymous read on their origin node), else none.
    fn sweep_bearer(&mut self, url: &str) -> Result<Option<String>> {
        match &mut self.tokens {
            Some(t) => t.bearer(Actor::Owner, url),
            None => Ok(None),
        }
    }

    async fn doc_ids(&mut self, node: usize, col: &str) -> Result<HashSet<String>> {
        let (name, url) = self.nodes[node].clone();
        let bearer = self.sweep_bearer(&url)?;
        let query = format!("{{ {col} {{ _docID }} }}");
        let data = gql_as(&self.http, &url, &query, bearer.as_deref())
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
    async fn heads(&mut self, node: usize, ids: &[String]) -> Result<HashMap<String, Vec<String>>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let (name, url) = self.nodes[node].clone();
        let bearer = self.sweep_bearer(&url)?;
        let selections: Vec<String> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| format!("d{i}: _commits(docID: \"{id}\", depth: 1) {{ cid }}"))
            .collect();
        let query = format!("{{ {} }}", selections.join(" "));
        let data = gql_as(&self.http, &url, &query, bearer.as_deref())
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

    /// The configured encrypted fields for `ids`, one POST per chunk.
    async fn encrypted_fields(
        &mut self,
        node: usize,
        col: &str,
        ids: &[String],
    ) -> Result<FieldMap> {
        if ids.is_empty() {
            return Ok(FieldMap::new());
        }
        let (name, url) = self.nodes[node].clone();
        let bearer = self.sweep_bearer(&url)?;
        let fields = self.cfg.encrypted_fields.join(" ");
        let list: Vec<String> = ids.iter().map(|id| format!("\"{id}\"")).collect();
        let query = format!(
            "{{ {col}(filter: {{_docID: {{_in: [{}]}}}}) {{ _docID {fields} }} }}",
            list.join(", ")
        );
        let data = gql_as(&self.http, &url, &query, bearer.as_deref())
            .await
            .map_err(|e| eyre!("{name}: encrypted-field read of {} docs: {e}", ids.len()))?;
        Ok(data[col]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| {
                let id = d["_docID"].as_str()?.to_string();
                let vals = self
                    .cfg
                    .encrypted_fields
                    .iter()
                    .map(|f| d[f].as_str().map(String::from))
                    .collect();
                Some((id, vals))
            })
            .collect())
    }

    /// Presence of `ids` as seen by owner, reader and anon: one POST per
    /// viewer per chunk. A doc a viewer cannot see is simply absent.
    async fn views(&mut self, node: usize, col: &str, ids: &[String]) -> Result<ViewMap> {
        if ids.is_empty() {
            return Ok(ViewMap::new());
        }
        let (name, url) = self.nodes[node].clone();
        let list: Vec<String> = ids.iter().map(|id| format!("\"{id}\"")).collect();
        let query = format!(
            "{{ {col}(filter: {{_docID: {{_in: [{}]}}}}) {{ _docID }} }}",
            list.join(", ")
        );
        let mut map: ViewMap = ids.iter().map(|id| (id.clone(), [false; 3])).collect();
        for (i, actor) in VIEWER_ACTORS.iter().enumerate() {
            let bearer = match &mut self.tokens {
                Some(t) => t.bearer(*actor, &url)?,
                None => None,
            };
            let data = gql_as(&self.http, &url, &query, bearer.as_deref())
                .await
                .map_err(|e| eyre!("{name}: {} view of {} docs: {e}", VIEWERS[i], ids.len()))?;
            for d in data[col].as_array().into_iter().flatten() {
                if let Some(seen) = d["_docID"].as_str().and_then(|id| map.get_mut(id)) {
                    seen[i] = true;
                }
            }
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_holds_for_min_settle_then_exits_on_clear_or_budget() {
        let (min, settle) = (Duration::from_secs(60), Duration::from_secs(120));
        // Clear early no longer ends the settle while the floor is unserved.
        assert!(!settle_done(Duration::from_secs(13), min, settle, true));
        // Served floor plus clear ends it.
        assert!(settle_done(Duration::from_secs(60), min, settle, true));
        // Never clear: the budget still ends it.
        assert!(!settle_done(Duration::from_secs(119), min, settle, false));
        assert!(settle_done(Duration::from_secs(120), min, settle, false));
        // A floor past the budget wins: the budget alone cannot cut it short.
        assert!(!settle_done(
            Duration::from_secs(150),
            Duration::from_secs(300),
            settle,
            true
        ));
        // Default: zero floor is the historical early exit on the first clear.
        assert!(settle_done(Duration::ZERO, Duration::ZERO, settle, true));
    }

    fn fm(rows: &[(&str, &[Option<&str>])]) -> FieldMap {
        rows.iter()
            .map(|(id, vals)| {
                (
                    id.to_string(),
                    vals.iter().map(|v| v.map(String::from)).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn m5_equal_differ_undecryptable() {
        let a = fm(&[
            ("d1", &[Some("s"), Some("1")]),
            ("d2", &[Some("s"), Some("2")]),
            ("d3", &[Some("s"), Some("3")]),
        ]);
        let b = fm(&[
            ("d1", &[Some("s"), Some("1")]),
            ("d2", &[Some("x"), Some("2")]),
            ("d3", &[None, Some("3")]),
        ]);
        let targets = [
            "d1".to_string(),
            "d2".to_string(),
            "d3".to_string(),
            "d4".to_string(),
        ];
        let fields = ["secret".to_string(), "pin".to_string()];
        let out = m5_compare(&a, &b, "rust-0", "go-0", &targets, &fields);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0].0, "d2");
        assert_eq!(out[0].1["field"], "secret");
        assert!(out[0].1["a"].is_string() && out[0].1["b"].is_string());
        assert_eq!(out[1].0, "d3");
        assert_eq!(
            out[1].1,
            json!({ "undecryptable_on": "go-0", "field": "secret" })
        );
    }

    #[test]
    fn m6_peer_pairs_compare_and_origin_pairs_are_by_design() {
        let mut a = ViewMap::new();
        let mut b = ViewMap::new();
        a.insert("d1".into(), [true, true, false]);
        b.insert("d1".into(), [true, true, false]); // equal
        a.insert("d2".into(), [true, false, false]);
        b.insert("d2".into(), [true, true, false]); // reader differs
        a.insert("d3".into(), [true, false, false]);
        b.insert("d3".into(), [true, true, true]); // origin vs peer
        let mut origin = HashMap::new();
        origin.insert("d1".to_string(), 3usize);
        origin.insert("d2".to_string(), 3);
        origin.insert("d3".to_string(), 0);
        let targets = [
            "d1".to_string(),
            "d2".to_string(),
            "d3".to_string(),
            "d4".to_string(),
        ];
        let names: Vec<String> = ["rust-0", "rust-1", "go-0", "go-1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (out, by_design) = m6_compare(&a, &b, &names, 0, 2, &origin, &targets);
        assert_eq!(by_design, 1, "d3: rust-0 is its origin, go-0 a peer");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "d2");
        assert_eq!(
            out[0].1,
            json!({ "viewer": "reader", "a": false, "b": true, "origin": "go-1" })
        );
    }
}
