//! End-of-run profile: reads the artifact's JSONL files back and writes
//! `profile.json` plus a one-screen `profile.md` (`soak summarize DIR`), and
//! the replay-contract comparison of two runs (`soak compare A B`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use eyre::{Result, WrapErr};
use serde_json::{json, Value};

use crate::meter::percentile;

fn read_jsonl(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

fn pct(values: &[u64]) -> Value {
    json!({
        "n": values.len(),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "max": values.iter().max(),
    })
}

/// Build the profile from `run_dir` and write `profile.json` / `profile.md`.
pub fn write_profile(run_dir: &Path) -> Result<Value> {
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("manifest.json")).wrap_err("reading manifest.json")?,
    )?;
    let ops = read_jsonl(&run_dir.join("ops.jsonl"));
    let du = read_jsonl(&run_dir.join("du.jsonl"));
    let rss = read_jsonl(&run_dir.join("rss.jsonl"));
    let lag = read_jsonl(&run_dir.join("lag.jsonl"));
    let checks = read_jsonl(&run_dir.join("checks.jsonl"));
    let divergences = read_jsonl(&run_dir.join("divergences.jsonl"));
    let topology = read_jsonl(&run_dir.join("topology.jsonl"));

    // Latency per (node, kind); outcome counts.
    let mut latency: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    let (mut ok, mut failed, mut skipped, mut writes_ok) = (0u64, 0u64, 0u64, 0u64);
    for op in &ops {
        let is_ok = op["ok"].as_bool().unwrap_or(false);
        if is_ok {
            ok += 1;
            if is_write(s(op, "kind")) {
                writes_ok += 1;
            }
            latency
                .entry((s(op, "node").to_string(), s(op, "kind").to_string()))
                .or_default()
                .push(op["latency_ms"].as_u64().unwrap_or(0));
        } else if op["skipped"].as_bool().unwrap_or(false) {
            skipped += 1;
        } else {
            failed += 1;
        }
    }
    let span_s = match (ops.first(), ops.last()) {
        (Some(a), Some(b)) if ops.len() > 1 => {
            (b["wall_ts_ms"].as_f64().unwrap_or(0.0) - a["wall_ts_ms"].as_f64().unwrap_or(0.0))
                / 1000.0
        }
        _ => 0.0,
    };

    // Disk: first and last sample per node; bytes per mesh-wide write op.
    let mut disk: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for d in &du {
        let bytes = d["bytes"].as_u64().unwrap_or(0);
        disk.entry(s(d, "node").to_string())
            .and_modify(|e| e.1 = bytes)
            .or_insert((bytes, bytes));
    }
    let mut rss_max: BTreeMap<String, u64> = BTreeMap::new();
    for r in &rss {
        let b = r["rss_bytes"].as_u64().unwrap_or(0);
        let e = rss_max.entry(s(r, "node").to_string()).or_default();
        *e = (*e).max(b);
    }
    // Lag in three groupings: directed pair, source alone, and receiving
    // runtime x source. `source` is what the sample came from (poll or sse);
    // mixing them hides that an sse sample is an event-time arrival.
    let mut lag_sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut lag_groups: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    let mut lag_seen: BTreeMap<(String, String), HashSet<&str>> = BTreeMap::new();
    for l in &lag {
        let source = l["source"].as_str().unwrap_or("poll");
        let ms = l["lag_ms"].as_u64().unwrap_or(0);
        *lag_sources.entry(source.to_string()).or_default() += 1;
        for key in [
            (
                format!("{}->{}", s(l, "from"), s(l, "to")),
                "all".to_string(),
            ),
            ("all".to_string(), source.to_string()),
            (format!("*->{}", runtime(s(l, "to"))), source.to_string()),
        ] {
            lag_groups.entry(key).or_default().push(ms);
        }
        if let Some(id) = l["doc_id"].as_str() {
            lag_seen
                .entry((s(l, "from").to_string(), s(l, "to").to_string()))
                .or_default()
                .insert(id);
        }
    }
    // Censoring: creates that never produced a lag sample on the far side are
    // not fast, they are unseen, and they are absent from every percentile.
    let mut creates_by_node: BTreeMap<&str, HashSet<&str>> = BTreeMap::new();
    for op in &ops {
        if op["ok"].as_bool() == Some(true) && s(op, "kind") == "create" {
            if let Some(id) = op["doc_id"].as_str() {
                creates_by_node.entry(s(op, "node")).or_default().insert(id);
            }
        }
    }
    let node_names: Vec<&str> = manifest["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n["name"].as_str())
        .collect();
    let mut lag_unseen: Vec<Value> = Vec::new();
    for (from, creates) in &creates_by_node {
        for to in &node_names {
            if to == from {
                continue;
            }
            let seen = lag_seen.get(&(from.to_string(), to.to_string()));
            let seen_here = seen.map_or(0, |s| creates.iter().filter(|d| s.contains(*d)).count());
            lag_unseen.push(json!({"from": from, "to": to, "creates": creates.len(),
                                   "lag_samples": seen.map_or(0, HashSet::len),
                                   "unseen": creates.len() - seen_here}));
        }
    }
    let mut check_status: BTreeMap<String, u64> = BTreeMap::new();
    for c in &checks {
        *check_status.entry(s(c, "status").to_string()).or_default() += 1;
    }
    let final_check = checks
        .iter()
        .rev()
        .find(|c| c["full"].as_bool() == Some(true));
    let diverged_docs: usize = divergences
        .iter()
        .map(|d| d["doc_ids"].as_array().map_or(0, Vec::len))
        .sum();
    let mut record_tags: BTreeMap<String, u64> = BTreeMap::new();
    for d in &divergences {
        for t in d["doc_tags"].as_array().into_iter().flatten() {
            *record_tags
                .entry(t.as_str().unwrap_or("untagged").to_string())
                .or_default() += 1;
        }
    }
    let final_sweep_lines = read_jsonl(&run_dir.join("final_sweep.jsonl"));
    let mut sweep_tags: BTreeMap<String, u64> = BTreeMap::new();
    for f in &final_sweep_lines {
        *sweep_tags
            .entry(f["tag"].as_str().unwrap_or("untagged").to_string())
            .or_default() += 1;
    }
    let sweep_docs: std::collections::HashSet<&str> = final_sweep_lines
        .iter()
        .filter_map(|f| f["doc_id"].as_str())
        .collect();
    // Unique documents, not rows: a sweep row is one (pair, doc) mismatch, so a
    // doc missing on one node shows up once per pair that node is in.
    let mut m1_by_missing: BTreeMap<&str, HashSet<&str>> = BTreeMap::new();
    let mut m1_docs: HashSet<&str> = HashSet::new();
    for f in &final_sweep_lines {
        if s(f, "mechanism") != "M1" {
            continue;
        }
        let (Some(doc), Some(node)) = (f["doc_id"].as_str(), f["detail"]["missing_on"].as_str())
        else {
            continue;
        };
        m1_docs.insert(doc);
        m1_by_missing.entry(node).or_default().insert(doc);
    }
    let union_where = |pred: fn(&str) -> bool| -> HashSet<&str> {
        m1_by_missing
            .iter()
            .filter(|(n, _)| pred(n))
            .flat_map(|(_, d)| d.iter().copied())
            .collect()
    };
    let m1_on_rust = union_where(|n| n.starts_with("rust"));
    let m1_on_go = union_where(|n| n.starts_with("go"));
    let diverged_docs_unique: HashSet<&str> = divergences
        .iter()
        .flat_map(|d| d["doc_ids"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .collect();
    let mut record_docs_healed = 0u64;
    let mut record_docs_persistent = 0u64;
    for d in &divergences {
        for id in d["doc_ids"].as_array().into_iter().flatten() {
            if sweep_docs.contains(id.as_str().unwrap_or("")) {
                record_docs_persistent += 1;
            } else {
                record_docs_healed += 1;
            }
        }
    }
    let mut records_by_pair: BTreeMap<String, u64> = BTreeMap::new();
    for d in &divergences {
        let pair = d["pair"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .unwrap_or_default();
        *records_by_pair.entry(pair).or_default() += 1;
    }
    let mut churn_kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut longest_outage_ms = 0u64;
    for t in &topology {
        if s(t, "phase") == "up" {
            *churn_kinds.entry(s(t, "kind").to_string()).or_default() += 1;
            longest_outage_ms = longest_outage_ms.max(t["duration_ms"].as_u64().unwrap_or(0));
        }
    }
    // Docker samples carry a null pid: those bytes are `docker stats` MemUsage
    // for the whole container, not the process RSS `ps` reports.
    let rss_instrument = if !rss.is_empty() && rss.iter().all(|r| r["pid"].is_null()) {
        "docker_stats"
    } else {
        "ps"
    };
    let causes = classify_final_sweep(
        &read_jsonl(&run_dir.join("final_sweep.jsonl")),
        &ops,
        &topology,
    );
    let stores: HashMap<String, String> = manifest["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| (s(n, "name").to_string(), s(n, "store").to_string()))
        .collect();

    let profile = json!({
        "run_id": manifest["run_id"],
        "seed": manifest["seed"],
        "ops": {"executed": ops.len(), "ok": ok, "failed": failed, "skipped": skipped,
                "writes_ok": writes_ok, "span_s": span_s,
                "achieved_ops_per_s": if span_s > 0.0 { (ops.len() as f64 - 1.0) / span_s } else { 0.0 },
                "stopped_by": manifest["stopped_by"]},
        "latency_ms": latency.iter().map(|((node, kind), v)| {
            json!({"node": node, "kind": kind, "stats": pct(v)})
        }).collect::<Vec<_>>(),
        "disk": disk.iter().map(|(node, (first, last))| json!({
            "node": node, "store": stores.get(node), "start_bytes": first, "end_bytes": last,
            "bytes_per_write_op": if writes_ok > 0 { (last.saturating_sub(*first)) as f64 / writes_ok as f64 } else { 0.0 },
        })).collect::<Vec<_>>(),
        "rss_max_bytes": rss_max,
        "rss_instrument": rss_instrument,
        "convergence_lag_ms": lag_groups.iter().map(|((dir, source), v)| json!({"direction": dir, "source": source, "stats": pct(v)})).collect::<Vec<_>>(),
        "lag_unseen": lag_unseen,
        "lag_sources": lag_sources,
        "checks": check_status,
        "divergence_records": divergences.len(),
        "diverged_docs": diverged_docs,
        "diverged_docs_unique": diverged_docs_unique.len(),
        "records_by_pair": records_by_pair,
        "record_doc_tags": record_tags.clone(),
        "record_doc_tag_slots": record_tags,
        "record_docs_healed_by_sweep": record_docs_healed,
        "record_docs_persistent": record_docs_persistent,
        "final_sweep_tags": sweep_tags,
        "final_sweep": final_check.map(|c| json!({"mismatches": c["mismatches"], "eligible": c["eligible"],
                                                  "sampled_pending": c["pending"]})),
        "sweep_rows": final_sweep_lines.len(),
        "sweep_unique_docs": sweep_docs.len(),
        "sweep_unique_m1_docs": m1_docs.len(),
        "sweep_unique_m1_by_missing_on": m1_by_missing.iter().map(|(n, d)| (n.to_string(), d.len())).collect::<BTreeMap<_, _>>(),
        "sweep_unique_m1_on_rust": m1_on_rust.len(),
        "sweep_unique_m1_on_go": m1_on_go.len(),
        "sweep_unique_m1_overlap": m1_on_rust.intersection(&m1_on_go).count(),
        "loss_strict": loss_by_outage(&ops, &topology, &final_sweep_lines, 0),
        "loss_plus_30s": loss_by_outage(&ops, &topology, &final_sweep_lines, RECOVERY_WINDOW_MS),
        "final_sweep_causes": causes,
        "churn": {"events": churn_kinds, "longest_outage_ms": longest_outage_ms},
    });
    fs::write(
        run_dir.join("profile.json"),
        serde_json::to_string_pretty(&profile)?,
    )?;
    fs::write(run_dir.join("profile.md"), render(&profile, &manifest))?;
    Ok(profile)
}

fn mb(v: &Value) -> String {
    format!("{:.1}", v.as_f64().unwrap_or(0.0) / 1_048_576.0)
}

fn render(p: &Value, manifest: &Value) -> String {
    let mut out = String::new();
    let o = &p["ops"];
    out += &format!(
        "# soak profile: run {} (seed {})\n\nrust {} / go {}\n\nops: {} executed ({} ok, {} failed, {} skipped), {:.2} ops/s over {:.0}s, {} mesh writes ok, stopped by {}\n\n",
        p["run_id"].as_str().unwrap_or("?"),
        p["seed"],
        manifest["rust_version"]["commit"].as_str().map(|c| &c[..c.len().min(9)]).unwrap_or("?"),
        manifest["go_version"]["commit"].as_str().map(|c| &c[..c.len().min(9)]).unwrap_or("?"),
        o["executed"], o["ok"], o["failed"], o["skipped"],
        o["achieved_ops_per_s"].as_f64().unwrap_or(0.0),
        o["span_s"].as_f64().unwrap_or(0.0),
        o["writes_ok"],
        o["stopped_by"].as_str().unwrap_or("?"),
    );
    out += "## latency ms (p50 / p95 / max, n)\n\n| node | kind | p50 | p95 | max | n |\n|---|---|---|---|---|---|\n";
    for l in p["latency_ms"].as_array().into_iter().flatten() {
        let st = &l["stats"];
        out += &format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            l["node"].as_str().unwrap_or(""),
            l["kind"].as_str().unwrap_or(""),
            st["p50"],
            st["p95"],
            st["max"],
            st["n"]
        );
    }
    out += "\n## disk (engine-inclusive: store named per node)\n\n| node | store | start MB | end MB | bytes_grown_per_mesh_write |\n|---|---|---|---|---|\n";
    for d in p["disk"].as_array().into_iter().flatten() {
        out += &format!(
            "| {} | {} | {} | {} | {:.0} |\n",
            d["node"].as_str().unwrap_or(""),
            d["store"].as_str().unwrap_or("?"),
            mb(&d["start_bytes"]),
            mb(&d["end_bytes"]),
            d["bytes_per_write_op"].as_f64().unwrap_or(0.0)
        );
    }
    out += if p["rss_instrument"] == "docker_stats" {
        "\n## max memory (docker stats MemUsage, not process RSS) MB\n\n"
    } else {
        "\n## max RSS MB (ps rss)\n\n"
    };
    for (node, b) in p["rss_max_bytes"].as_object().into_iter().flatten() {
        out += &format!("- {node}: {}\n", mb(b));
    }
    out += &format!(
        "\n## convergence lag ms (create first seen on the other side; sources {})\n\n| direction | source | n | p50_ms | p95_ms | max_ms |\n|---|---|---|---|---|---|\n",
        p["lag_sources"]
    );
    for l in p["convergence_lag_ms"].as_array().into_iter().flatten() {
        let st = &l["stats"];
        out += &format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            l["direction"].as_str().unwrap_or(""),
            l["source"].as_str().unwrap_or(""),
            st["n"],
            st["p50"],
            st["p95"],
            st["max"]
        );
    }
    let unseen: Vec<&Value> = p["lag_unseen"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|u| u["unseen"].as_u64().unwrap_or(0) > 0)
        .collect();
    if !unseen.is_empty() {
        out += "\ncreates with no lag sample on the far side (censored, absent from every percentile above):\n\n";
        for u in unseen {
            out += &format!(
                "- {} -> {}: {} of {} creates unseen\n",
                u["from"].as_str().unwrap_or(""),
                u["to"].as_str().unwrap_or(""),
                u["unseen"],
                u["creates"]
            );
        }
    }
    out += &format!(
        "\n## checks: {}; divergence records {} ({} record-doc slots, {} unique docs) by pair {}; final sweep {}\n\n`sampled_pending` is what the last full pass happened to look at (recent docs plus a cold sample of 50), not the size of the backlog.\n",
        p["checks"],
        p["divergence_records"],
        p["diverged_docs"],
        p["diverged_docs_unique"],
        p["records_by_pair"],
        p["final_sweep"]
    );
    out += &format!(
        "\nfinal sweep: {} rows, {} unique docs (M1 unique {}, rust {}, go {}, overlap {})\n",
        p["sweep_rows"],
        p["sweep_unique_docs"],
        p["sweep_unique_m1_docs"],
        p["sweep_unique_m1_on_rust"],
        p["sweep_unique_m1_on_go"],
        p["sweep_unique_m1_overlap"]
    );
    out += &format!(
        "\n## known-cause tags: record-doc slots {} ({} slots healed by the sweep, {} still present); final sweep {}\n",
        p["record_doc_tags"], p["record_docs_healed_by_sweep"], p["record_docs_persistent"], p["final_sweep_tags"]
    );
    if let Some(causes) = p["final_sweep_causes"]
        .as_object()
        .filter(|c| !c.is_empty())
    {
        out += "\n## final sweep mismatches by likely cause (last write on the doc vs the peer's outage windows)\n\n";
        for (cause, n) in causes {
            out += &format!("- {n} {cause}\n");
        }
    }
    for (key, title) in [
        ("loss_strict", "[down,up]"),
        ("loss_plus_30s", "[down,up+30s]"),
    ] {
        let rows = p[key].as_array().into_iter().flatten();
        let mut collapsed: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
        for r in rows {
            let e = collapsed
                .entry((
                    r["kind"].as_str().unwrap_or(""),
                    r["recv_rt"].as_str().unwrap_or(""),
                ))
                .or_default();
            e.0 += r["written"].as_u64().unwrap_or(0);
            e.1 += r["lost"].as_u64().unwrap_or(0);
        }
        if collapsed.is_empty() {
            continue;
        }
        out += &format!(
            "\n## loss (creates by another node in {title}, still missing_on the down node at the final sweep)\n\n| kind | recv | written | lost |\n|---|---|---|---|\n"
        );
        for ((kind, recv), (written, lost)) in collapsed {
            out += &format!("| {kind} | {recv} | {written} | {lost} |\n");
        }
    }
    out += &format!(
        "\n## churn: {} events, longest outage {:.1}s\n",
        p["churn"]["events"],
        p["churn"]["longest_outage_ms"].as_f64().unwrap_or(0.0) / 1000.0
    );
    out
}

/// The replay contract: planned op fields (index, virtual time, node, kind,
/// collection) and the churn schedule must match; docIDs must agree wherever
/// both runs learned one. Outcomes, error text and wall timing may differ.
pub fn compare(a: &Path, b: &Path) -> Result<Value> {
    let planned = |op: &Value| -> (u64, u64, String, String, String) {
        (
            op["op_index"].as_u64().unwrap_or(0),
            op["virtual_ts_ms"].as_u64().unwrap_or(0),
            s(op, "node").to_string(),
            s(op, "kind").to_string(),
            s(op, "collection").to_string(),
        )
    };
    let ops_a = read_jsonl(&a.join("ops.jsonl"));
    let ops_b = read_jsonl(&b.join("ops.jsonl"));
    let mut planned_diffs = Vec::new();
    let (mut doc_ids_agree, mut doc_ids_differ) = (0usize, 0usize);
    for (x, y) in ops_a.iter().zip(&ops_b) {
        if planned(x) != planned(y) {
            planned_diffs.push(x["op_index"].as_u64().unwrap_or(0));
        }
        match (x["doc_id"].as_str(), y["doc_id"].as_str()) {
            (Some(p), Some(q)) if p == q => doc_ids_agree += 1,
            (Some(_), Some(_)) => doc_ids_differ += 1,
            _ => {}
        }
    }
    let schedule = |dir: &Path| -> Value {
        let m: Value = fs::read_to_string(dir.join("manifest.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null);
        m["churn"]["schedule"].clone()
    };
    let (sched_a, sched_b) = (schedule(a), schedule(b));
    let contract = planned_diffs.is_empty() && doc_ids_differ == 0 && sched_a == sched_b;
    let identical = contract && ops_a.len() == ops_b.len();
    // A `--until-op` replay is a prefix of the original.
    let prefix = contract && ops_b.len() < ops_a.len();
    Ok(json!({
        "identical": identical,
        "prefix_identical": prefix,
        "ops": {"a": ops_a.len(), "b": ops_b.len(), "planned_diffs": planned_diffs.len(),
                "first_planned_diffs": planned_diffs.iter().take(5).collect::<Vec<_>>(),
                "doc_ids_agree": doc_ids_agree, "doc_ids_differ": doc_ids_differ},
        "churn_schedule_identical": sched_a == sched_b,
    }))
}

/// Writes this soon after either node came back count as made during the
/// recovery: the node answers GraphQL before its replicator link is back.
const RECOVERY_WINDOW_MS: u64 = 30_000;

/// For each final-sweep mismatch: what was the last successful write to
/// that doc, and was a member of the pair down, or the writer or a member
/// freshly recovered, at that moment? Counts by
/// `"<mechanism> missing_on=<node>: last <kind> on <node> while <state>"`.
fn classify_final_sweep(
    sweep: &[Value],
    ops: &[Value],
    topology: &[Value],
) -> BTreeMap<String, u64> {
    // Down windows per node: (start wall ms, end wall ms, kind).
    let mut ups: HashMap<u64, u64> = HashMap::new();
    for t in topology {
        if s(t, "phase") == "up" {
            ups.insert(
                t["event"].as_u64().unwrap_or(0),
                t["wall_ts_ms"].as_u64().unwrap_or(0),
            );
        }
    }
    let windows: Vec<(String, u64, u64, String)> = topology
        .iter()
        .filter(|t| s(t, "phase") == "down")
        .map(|t| {
            let ev = t["event"].as_u64().unwrap_or(0);
            (
                s(t, "node").to_string(),
                t["wall_ts_ms"].as_u64().unwrap_or(0),
                ups.get(&ev).copied().unwrap_or(u64::MAX),
                s(t, "kind").to_string(),
            )
        })
        .collect();
    let mut last_write: HashMap<&str, &Value> = HashMap::new();
    for op in ops {
        if op["ok"].as_bool() == Some(true) && is_write(s(op, "kind")) {
            if let Some(id) = op["doc_id"].as_str() {
                last_write.insert(id, op);
            }
        }
    }
    let mut out = BTreeMap::new();
    for f in sweep {
        let mech = s(f, "mechanism");
        let missing_on = f["detail"]["missing_on"]
            .as_str()
            .or_else(|| f["detail"]["undecryptable_on"].as_str())
            .map(String::from)
            .or_else(|| {
                f["detail"]["viewer"]
                    .as_str()
                    .map(|v| format!("viewer={v}"))
            })
            .unwrap_or_else(|| "-".to_string());
        let members: Vec<&str> = s(f, "pair").split('|').collect();
        let label = match last_write.get(s(f, "doc_id")) {
            None => format!("{mech} missing_on={missing_on}: no successful write on record"),
            Some(op) => {
                let node = s(op, "node");
                let wall = op["wall_ts_ms"].as_u64().unwrap_or(0);
                let involved = |n: &str| n == node || members.contains(&n);
                let state = if let Some((_, _, _, kind)) = windows
                    .iter()
                    .find(|(n, a, b, _)| n != node && involved(n) && *a <= wall && wall <= *b)
                {
                    format!("peer {kind}")
                } else if let Some((n, _, _, _)) = windows.iter().find(|(n, _, b, _)| {
                    involved(n) && *b <= wall && wall - *b <= RECOVERY_WINDOW_MS
                }) {
                    if n == node {
                        "writer recovering (<30s up)".to_string()
                    } else {
                        "peer recovering (<30s up)".to_string()
                    }
                } else {
                    "both up".to_string()
                };
                format!(
                    "{mech} missing_on={missing_on}: last {} on {node} while {state}",
                    s(op, "kind")
                )
            }
        };
        *out.entry(label).or_default() += 1;
    }
    out
}

/// A node's runtime is its name prefix; the cluster builder names them.
fn runtime(node: &str) -> &'static str {
    if node.starts_with("rust") {
        "rust"
    } else if node.starts_with("go") {
        "go"
    } else {
        "?"
    }
}

/// Loss during an outage: creates made by some *other* node while a node was
/// down, counted against the ones that node was still missing at the final
/// sweep. `extra` widens the window past the `up` record (a node answers
/// GraphQL before its replicator link is back). Keyed by outage kind, the
/// runtime of the node that was down, and the runtime of the writer.
fn loss_by_outage(ops: &[Value], topology: &[Value], sweep: &[Value], extra: u64) -> Vec<Value> {
    let ups: HashMap<u64, u64> = topology
        .iter()
        .filter(|t| s(t, "phase") == "up")
        .map(|t| {
            (
                t["event"].as_u64().unwrap_or(0),
                t["wall_ts_ms"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let windows: Vec<(&str, &str, u64, u64)> = topology
        .iter()
        .filter(|t| s(t, "phase") == "down")
        .filter_map(|t| {
            let up = ups.get(&t["event"].as_u64().unwrap_or(0))?;
            Some((
                s(t, "kind"),
                s(t, "node"),
                t["wall_ts_ms"].as_u64().unwrap_or(0),
                up + extra,
            ))
        })
        .collect();
    let mut missing_on: HashMap<&str, HashSet<&str>> = HashMap::new();
    for f in sweep {
        if s(f, "mechanism") == "M1" {
            if let (Some(doc), Some(node)) =
                (f["doc_id"].as_str(), f["detail"]["missing_on"].as_str())
            {
                missing_on.entry(node).or_default().insert(doc);
            }
        }
    }
    let mut agg: BTreeMap<(&str, &str, &str), (u64, u64)> = BTreeMap::new();
    for (kind, node, down, up) in &windows {
        for op in ops {
            if op["ok"].as_bool() != Some(true)
                || s(op, "kind") != "create"
                || s(op, "node") == *node
            {
                continue;
            }
            let Some(doc) = op["doc_id"].as_str() else {
                continue;
            };
            let wall = op["wall_ts_ms"].as_u64().unwrap_or(0);
            if wall < *down || wall > *up {
                continue;
            }
            let e = agg
                .entry((kind, runtime(node), runtime(s(op, "node"))))
                .or_default();
            e.0 += 1;
            if missing_on.get(node).is_some_and(|m| m.contains(doc)) {
                e.1 += 1;
            }
        }
    }
    agg.into_iter()
        .map(|((kind, recv, writer), (written, lost))| {
            json!({"kind": kind, "recv_rt": recv, "writer_rt": writer,
                   "written": written, "lost": lost})
        })
        .collect()
}

/// Grants change relationships, not documents, so they are not writes.
fn is_write(kind: &str) -> bool {
    !matches!(kind, "query" | "grant")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_counts_only_foreign_creates_inside_the_window() {
        let topology = vec![
            json!({"event": 1, "phase": "down", "kind": "crash_kill", "node": "go-0", "wall_ts_ms": 100}),
            json!({"event": 1, "phase": "up", "kind": "crash_kill", "node": "go-0", "wall_ts_ms": 200}),
        ];
        let ops = vec![
            // Kept, and still missing at the sweep.
            json!({"ok": true, "kind": "create", "node": "rust-0", "doc_id": "a", "wall_ts_ms": 150}),
            // Kept, arrived.
            json!({"ok": true, "kind": "create", "node": "rust-0", "doc_id": "b", "wall_ts_ms": 160}),
            // The down node's own create: not counted.
            json!({"ok": true, "kind": "create", "node": "go-0", "doc_id": "c", "wall_ts_ms": 170}),
            // After the window, inside the +30s recovery window.
            json!({"ok": true, "kind": "create", "node": "rust-0", "doc_id": "d", "wall_ts_ms": 210}),
            // Not a create.
            json!({"ok": true, "kind": "update", "node": "rust-0", "doc_id": "e", "wall_ts_ms": 150}),
            // Failed.
            json!({"ok": false, "kind": "create", "node": "rust-0", "doc_id": "f", "wall_ts_ms": 150}),
        ];
        let sweep = vec![
            json!({"mechanism": "M1", "doc_id": "a", "detail": {"missing_on": "go-0"}}),
            // M3 rows have no missing_on and must not join.
            json!({"mechanism": "M3", "doc_id": "b", "detail": {"heads_a": "x", "heads_b": "y"}}),
        ];
        let strict = loss_by_outage(&ops, &topology, &sweep, 0);
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0]["kind"], "crash_kill");
        assert_eq!(strict[0]["recv_rt"], "go");
        assert_eq!(strict[0]["writer_rt"], "rust");
        assert_eq!(strict[0]["written"], 2);
        assert_eq!(strict[0]["lost"], 1);
        let wide = loss_by_outage(&ops, &topology, &sweep, RECOVERY_WINDOW_MS);
        assert_eq!(wide[0]["written"], 3);
        assert_eq!(wide[0]["lost"], 1);
    }

    #[test]
    fn runtime_is_the_name_prefix() {
        assert_eq!(runtime("rust-2"), "rust");
        assert_eq!(runtime("go-0"), "go");
    }

    #[test]
    fn grants_and_queries_are_not_writes() {
        assert!(!is_write("grant"));
        assert!(!is_write("query"));
        assert!(is_write("update"));
    }
}
