//! `summary.json` and `cases.md` under `--out`, beside `manifest.json`.

use std::path::Path;

use eyre::Result;
use serde_json::json;

use super::cases::{CaseReport, Outcome};

pub fn write(out: &Path, topology: &str, transport: &str, reports: &[CaseReport]) -> Result<()> {
    let summary = json!({ "topology": topology, "transport": transport, "cases": reports });
    std::fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;
    std::fs::write(out.join("cases.md"), markdown(topology, transport, reports))?;
    Ok(())
}

fn markdown(topology: &str, transport: &str, reports: &[CaseReport]) -> String {
    let mut md = format!("# soak manage ({topology}, {transport})\n\n| case | outcome | ops | slowest ms | detail |\n|---|---|---|---|---|\n");
    for r in reports {
        let (outcome, detail) = match &r.outcome {
            Outcome::Pass => ("pass", r.notes.join("; ")),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_names_the_topology_and_transport() {
        assert!(markdown("3r0g", "iroh", &[]).starts_with("# soak manage (3r0g, iroh)\n"));
    }
}
