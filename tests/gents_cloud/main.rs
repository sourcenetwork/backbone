//! gents-cloud mechanics on the Source Network Rust stack with Go Vera.
//!
//! Every scenario is named after the item of `gents-cloud-v1.md` it
//! discharges (an invariant `I-n`, a hardening move `H-n`, a spike `S-n`, a
//! readiness finding `C-n`, or a ground-truth row of §1.6) and asserts what the
//! running artifacts do, not what the plan says they should do. Where the two
//! disagree the assertion message says so, and the measurement table printed
//! at the end carries the numbers the plan marks "to be measured".
//!
//! Trust plane: Vera (`verad`, github.com/sourcenetwork/vera) for ACP and the
//! bulletin, an Orbis ring for threshold signing, DefraDB cells with
//! `--document-acp-type source-hub` and `--signer-type orbis`.

#[path = "../support/mod.rs"]
mod support;

mod fixture;
mod identity;
mod p2p;
mod recovery;
mod revocation;
mod scale;
mod write_path;

use std::time::Instant;

/// One scenario: a spec reference, a one-line claim, and the body.
pub struct Scenario {
    pub id: &'static str,
    pub spec: &'static str,
    pub claim: &'static str,
}

pub fn banner(s: &Scenario) -> Instant {
    eprintln!("[gents-cloud] === {} ({}) ===", s.id, s.spec);
    eprintln!("[gents-cloud]     {}", s.claim);
    Instant::now()
}

pub fn passed(s: &Scenario, started: Instant) {
    eprintln!(
        "[gents-cloud] PASSED {} in {:.1}s",
        s.id,
        started.elapsed().as_secs_f64()
    );
}

#[tokio::test]
#[ignore = "spec test: requires verad, defra-iroh, orbis-node, and cli-tool (see backbone.toml)"]
async fn gents_cloud_mechanics() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let started = Instant::now();
    let mut stack = fixture::build().await;

    identity::run(&mut stack).await;
    revocation::run(&mut stack).await;
    write_path::run(&mut stack).await;
    p2p::run(&mut stack).await;
    recovery::run(&mut stack).await;
    scale::run(&mut stack).await;

    eprintln!("[gents-cloud] === measurements ===");
    for (name, value) in &stack.measurements {
        eprintln!("[gents-cloud]   {:<48} {}", name, value);
    }
    eprintln!(
        "[gents-cloud] all scenarios passed in {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
