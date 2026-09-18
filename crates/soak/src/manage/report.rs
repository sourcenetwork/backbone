//! `summary.json` and `cases.md` under `--out`, beside `manifest.json`.

use std::path::Path;

use eyre::Result;
use serde_json::json;

use super::cases::{CaseReport, Outcome};

pub fn write(out: &Path, topology: &str, reports: &[CaseReport]) -> Result<()> {
    let summary = json!({ "topology": topology, "cases": reports });
    std::fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;
    std::fs::write(out.join("cases.md"), markdown(topology, reports))?;
    Ok(())
}

fn markdown(topology: &str, reports: &[CaseReport]) -> String {
    let mut md = format!("# soak manage ({topology})\n\n| case | outcome | ops | slowest ms | detail |\n|---|---|---|---|---|\n");
    for r in reports {
        let (outcome, detail) = match &r.outcome {
            Outcome::Pass => ("pass", String::new()),
            Outcome::Fail { expected, got } => ("FAIL", format!("expected {expected}; got {got}")),
            Outcome::Skip { reason } => ("skip", reason.clone()),
            Outcome::Infra { error } => ("INFRA", error.clone()),
        };
        let slowest = r.ops.iter().map(|o| o.latency_ms).max().unwrap_or(0);
        md.push_str(&format!(
            "| {} | {outcome} | {} | {slowest} | {} |\n",
            r.name,
            r.ops.len(),
            detail.replace('|', "\\|").replace('\n', " ")
        ));
    }
    md
}
