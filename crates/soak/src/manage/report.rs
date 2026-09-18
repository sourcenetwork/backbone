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
            Outcome::Pass => ("pass", String::new()),
            Outcome::Fail { expected, got } => ("FAIL", format!("expected {expected}; got {got}")),
            Outcome::Skip { reason } => ("skip", reason.clone()),
            Outcome::Infra { error } => ("INFRA", error.clone()),
        };
        let detail: Vec<&str> = std::iter::once(detail.as_str())
            .chain(r.notes.iter().map(String::as_str))
            .filter(|s| !s.is_empty())
            .collect();
        let slowest = r.ops.iter().map(|o| o.latency_ms).max().unwrap_or(0);
        md.push_str(&format!(
            "| {} | {outcome} | {} | {slowest} | {} |\n",
            r.name,
            r.ops.len(),
            detail.join("; ").replace('|', "\\|").replace('\n', " ")
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

    #[test]
    fn markdown_keeps_the_notes_beside_a_fail() {
        let failed = CaseReport {
            name: "R3",
            outcome: Outcome::Fail {
                expected: "200".into(),
                got: "403".into(),
            },
            ops: vec![],
            notes: vec!["stopped target: pass".into()],
        };
        let md = markdown("3r0g", "libp2p", &[failed]);
        assert!(
            md.ends_with("| R3 | FAIL | 0 | 0 | expected 200; got 403; stopped target: pass |\n"),
            "{md}"
        );
    }
}
