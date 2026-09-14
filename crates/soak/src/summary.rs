//! End-of-run profile: reads the artifact's JSONL files back and writes
//! `profile.json` plus a one-screen `profile.md` (`soak summarize DIR`), and
//! the replay-contract comparison of two runs (`soak compare A B`).

use std::collections::{BTreeMap, HashMap};
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
            if s(op, "kind") != "query" {
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
    let mut lag_by_dir: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for l in &lag {
        lag_by_dir
            .entry(format!("{}->{}", s(l, "from"), s(l, "to")))
            .or_default()
            .push(l["lag_ms"].as_u64().unwrap_or(0));
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
    let mut churn_kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut longest_outage_ms = 0u64;
    for t in &topology {
        if s(t, "phase") == "up" {
            *churn_kinds.entry(s(t, "kind").to_string()).or_default() += 1;
            longest_outage_ms = longest_outage_ms.max(t["duration_ms"].as_u64().unwrap_or(0));
        }
    }
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
        "convergence_lag_ms": lag_by_dir.iter().map(|(dir, v)| json!({"direction": dir, "stats": pct(v)})).collect::<Vec<_>>(),
        "checks": check_status,
        "divergence_records": divergences.len(),
        "diverged_docs": diverged_docs,
        "final_sweep": final_check.map(|c| json!({"mismatches": c["mismatches"], "eligible": c["eligible"]})),
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
        "# soak profile: run {} (seed {})\n\nrust {} / go {}\n\nops: {} executed ({} ok, {} failed, {} skipped), {:.2} ops/s over {:.0}s, stopped by {}\n\n",
        p["run_id"].as_str().unwrap_or("?"),
        p["seed"],
        manifest["rust_version"]["commit"].as_str().map(|c| &c[..c.len().min(9)]).unwrap_or("?"),
        manifest["go_version"]["commit"].as_str().map(|c| &c[..c.len().min(9)]).unwrap_or("?"),
        o["executed"], o["ok"], o["failed"], o["skipped"],
        o["achieved_ops_per_s"].as_f64().unwrap_or(0.0),
        o["span_s"].as_f64().unwrap_or(0.0),
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
    out += "\n## disk (engine-inclusive: store named per node)\n\n| node | store | start MB | end MB | bytes per write op |\n|---|---|---|---|---|\n";
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
    out += "\n## max RSS MB\n\n";
    for (node, b) in p["rss_max_bytes"].as_object().into_iter().flatten() {
        out += &format!("- {node}: {}\n", mb(b));
    }
    out += "\n## convergence lag s (create first seen on the other side; resolution = check interval)\n\n| direction | n | p50 | p95 | max |\n|---|---|---|---|---|\n";
    for l in p["convergence_lag_ms"].as_array().into_iter().flatten() {
        let st = &l["stats"];
        let sec = |v: &Value| format!("{:.0}", v.as_f64().unwrap_or(0.0) / 1000.0);
        out += &format!(
            "| {} | {} | {} | {} | {} |\n",
            l["direction"].as_str().unwrap_or(""),
            st["n"],
            sec(&st["p50"]),
            sec(&st["p95"]),
            sec(&st["max"])
        );
    }
    out += &format!(
        "\n## checks: {}; divergence records {} ({} docs); final sweep {}\n",
        p["checks"], p["divergence_records"], p["diverged_docs"], p["final_sweep"]
    );
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
