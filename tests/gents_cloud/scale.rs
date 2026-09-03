//! What one tenant costs, and what that means at 100,000 of them.
//!
//! A single machine cannot host 100,000 live tenants: at the measured per-cell
//! memory that is tens of terabytes of RAM. What a machine can do is measure
//! the per-tenant costs and check the properties that must hold no matter how
//! many tenants exist, then state the arithmetic. So this scenario provisions
//! `GENTS_CLOUD_TENANTS` real tenants (default 4), measures what each one costs
//! in provisioning time, memory, and chain state, checks that a tenant's read
//! cost and isolation do not change as tenants are added, and prints the
//! projection to the target with its assumptions named.
//!
//! Nothing here claims a 100,000-tenant run happened. Every projected number
//! is labelled as projected and derives from a measurement in the same run.

use std::time::Instant;

use crate::fixture::{
    create_transcripts, transcript_schema, visible_doc_ids, Cell, CellSpec, Invalidation,
    ServiceIdentity, Stack, WriteOutcome, TRANSCRIPT_RESOURCE,
};
use crate::support::full_stack::is_acp_denied;
use crate::{banner, passed, Scenario};

const SCALE: Scenario = Scenario {
    id: "scale_per_tenant_cost",
    spec: "gents-cloud §19.1 density, §20.1 (the workspace is the shard key), §20.6 growth stages",
    claim: "per-tenant provisioning, memory, and chain cost are measured, a tenant's read latency and isolation do not degrade as tenants are added, and the 100k projection follows from those measurements",
};

/// The tenant count the launch plan must serve (gents-cloud §20.6).
const TARGET_TENANTS: u64 = 100_000;

/// Memory available to cells on the reference node in §19.1's density figure.
const NODE_MEMORY_GIB: f64 = 64.0;

pub async fn run(stack: &mut Stack) {
    let t = banner(&SCALE);
    let tenant_count = tenant_count();
    let checkpoint_every = checkpoint_every(tenant_count);
    eprintln!(
        "[gents-cloud]   provisioning {} tenants, measuring every {}",
        tenant_count, checkpoint_every
    );

    let baseline_read_ms = read_latency_ms(&stack.acme, &stack.training_svc, "Transcript").await;

    let mut tenants: Vec<Tenant> = Vec::with_capacity(tenant_count);
    let mut phases: Vec<ProvisionPhases> = Vec::with_capacity(tenant_count);
    let mut curve: Vec<CurvePoint> = Vec::new();

    for index in 0..tenant_count {
        let (tenant, phase) = provision_tenant(stack, index).await;
        tenants.push(tenant);
        phases.push(phase);

        let done = index + 1;
        if done % checkpoint_every == 0 || done == tenant_count {
            curve.push(measure_curve_point(&tenants, &phases).await);
            let point = curve.last().expect("just pushed");
            eprintln!(
                "[gents-cloud]   {} tenants: cell rss {} MiB median, {} MiB total, read p50 {} ms",
                point.tenants, point.rss_median_mib, point.rss_total_mib, point.read_p50_ms
            );
        }
    }

    // Isolation at N: no tenant reads the next tenant's cell.
    for (i, tenant) in tenants.iter().enumerate() {
        let other = &tenants[(i + 1) % tenants.len()];
        if tenants.len() < 2 {
            break;
        }
        let cross = other
            .cell
            .http
            .graphql(
                "query { Transcript { _docID } }",
                Some(&tenant.identity.private_key_hex),
            )
            .await;
        assert!(
            is_acp_denied(&cross, "/data/Transcript"),
            "tenant {} must read nothing on tenant {}'s cell",
            tenant.identity.label,
            other.identity.label
        );
    }

    // Every tenant sees exactly its own document.
    for tenant in &tenants {
        let visible = visible_doc_ids(&tenant.cell, &tenant.identity, "Transcript").await;
        assert_eq!(
            visible,
            vec![tenant.doc_id.clone()],
            "tenant {} must see exactly its own document",
            tenant.identity.label
        );
    }

    let last = *curve.last().expect("at least one checkpoint");
    let phase_p50 = phase_medians(&phases);

    stack.record("scale_tenants_provisioned", format!("{}", tenant_count));
    stack.record(
        "scale_policies_on_vera",
        format!(
            "{}",
            stack.vera_cli.list_policy_count().expect("count policies")
        ),
    );
    stack.record(
        "scale_cell_rss_median_mib",
        format!("{}", last.rss_median_mib),
    );
    stack.record(
        "scale_read_p50_ms_one_tenant",
        format!("{}", baseline_read_ms),
    );
    stack.record(
        "scale_read_p50_ms_all_tenants",
        format!("{}", last.read_p50_ms),
    );
    stack.record(
        "scale_cross_tenant_reads_denied",
        format!("{} ordered pairs", tenants.len()),
    );

    // Where provisioning time actually goes. Four of these are chain
    // transactions that wait for a block; only ignition is the cell starting.
    stack.record(
        "scale_provision_p50_total_ms",
        format!("{}", phase_p50.total_ms),
    );
    stack.record(
        "scale_provision_p50_fund_ms",
        format!("{}", phase_p50.fund_ms),
    );
    stack.record(
        "scale_provision_p50_policy_ms",
        format!("{}", phase_p50.policy_ms),
    );
    stack.record(
        "scale_provision_p50_register_object_ms",
        format!("{}", phase_p50.register_object_ms),
    );
    stack.record(
        "scale_provision_p50_grant_writer_ms",
        format!("{}", phase_p50.grant_writer_ms),
    );
    stack.record(
        "scale_provision_p50_cell_ignition_ms",
        format!("{}", phase_p50.cell_ignition_ms),
    );
    stack.record(
        "scale_provision_p50_schema_ms",
        format!("{}", phase_p50.schema_ms),
    );
    stack.record(
        "scale_provision_p50_first_write_ms",
        format!("{}", phase_p50.first_write_ms),
    );
    let chain_ms = phase_p50.fund_ms
        + phase_p50.policy_ms
        + phase_p50.register_object_ms
        + phase_p50.grant_writer_ms;
    stack.record(
        "scale_provision_p50_chain_share",
        format!(
            "{}% of the total is the four Vera transactions waiting for a block",
            percent(chain_ms, phase_p50.total_ms)
        ),
    );

    // The projection, from the measured per-cell memory.
    let cells_per_node = (NODE_MEMORY_GIB * 1024.0 / last.rss_median_mib as f64).floor();
    let nodes_for_target = (TARGET_TENANTS as f64 / cells_per_node).ceil();
    stack.record(
        "scale_projected_cells_per_64gib_node",
        format!(
            "{:.0} (projected from the measured per-cell RSS)",
            cells_per_node
        ),
    );
    stack.record(
        "scale_projected_nodes_for_100k_tenants",
        format!(
            "{:.0} (projected: one cell per tenant, no headroom for the supervisor or the guest)",
            nodes_for_target
        ),
    );

    print_curve_table(&curve, &phase_p50);
    drop(tenants);
    passed(&SCALE, t);
}

/// One row of the scaling curve: what the fleet costs at this tenant count.
#[derive(Clone, Copy)]
struct CurvePoint {
    tenants: usize,
    rss_median_mib: u64,
    rss_total_mib: u64,
    read_p50_ms: u128,
    provision_p50_ms: u128,
    ignition_p50_ms: u128,
}

async fn measure_curve_point(tenants: &[Tenant], phases: &[ProvisionPhases]) -> CurvePoint {
    let rss_kib: Vec<u64> = tenants
        .iter()
        .filter_map(|t| cell_rss_kib(&t.cell))
        .collect();
    assert_eq!(
        rss_kib.len(),
        tenants.len(),
        "every tenant cell must report its resident memory"
    );
    let rss_median_mib =
        (median(&rss_kib.iter().map(|k| u128::from(*k)).collect::<Vec<_>>()) / 1024) as u64;
    let rss_total_mib = (rss_kib.iter().sum::<u64>()) / 1024;

    // Read latency sampled across up to eight tenants, so the cost of the
    // measurement does not grow with the fleet.
    let mut read_ms = Vec::new();
    let stride = (tenants.len() / 8).max(1);
    for tenant in tenants.iter().step_by(stride) {
        read_ms.push(read_latency_ms(&tenant.cell, &tenant.identity, "Transcript").await);
    }

    let medians = phase_medians(phases);
    CurvePoint {
        tenants: tenants.len(),
        rss_median_mib,
        rss_total_mib,
        read_p50_ms: median(&read_ms),
        provision_p50_ms: medians.total_ms,
        ignition_p50_ms: medians.cell_ignition_ms,
    }
}

fn phase_medians(phases: &[ProvisionPhases]) -> ProvisionPhases {
    let pick = |f: fn(&ProvisionPhases) -> u128| median(&phases.iter().map(f).collect::<Vec<_>>());
    ProvisionPhases {
        fund_ms: pick(|p| p.fund_ms),
        policy_ms: pick(|p| p.policy_ms),
        register_object_ms: pick(|p| p.register_object_ms),
        grant_writer_ms: pick(|p| p.grant_writer_ms),
        cell_ignition_ms: pick(|p| p.cell_ignition_ms),
        schema_ms: pick(|p| p.schema_ms),
        first_write_ms: pick(|p| p.first_write_ms),
        total_ms: pick(|p| p.total_ms),
    }
}

fn percent(part: u128, whole: u128) -> u128 {
    (part * 100).checked_div(whole).unwrap_or(0)
}

/// Print the curve and the provisioning breakdown as markdown, ready to paste.
fn print_curve_table(curve: &[CurvePoint], phases: &ProvisionPhases) {
    eprintln!("[gents-cloud] === scaling curve (markdown) ===");
    eprintln!("| Tenants | Cell RSS median (MiB) | All cells (MiB) | Read p50 (ms) | Provision p50 (ms) | Cell ignition p50 (ms) |");
    eprintln!("|---|---|---|---|---|---|");
    for point in curve {
        eprintln!(
            "| {} | {} | {} | {} | {} | {} |",
            point.tenants,
            point.rss_median_mib,
            point.rss_total_mib,
            point.read_p50_ms,
            point.provision_p50_ms,
            point.ignition_p50_ms
        );
    }
    eprintln!("[gents-cloud] === provisioning breakdown (markdown) ===");
    eprintln!("| Step | p50 (ms) | Waits on |");
    eprintln!("|---|---|---|");
    eprintln!(
        "| Fund the tenant account | {} | Vera block |",
        phases.fund_ms
    );
    eprintln!("| Create the policy | {} | Vera block |", phases.policy_ms);
    eprintln!(
        "| Register the collection object | {} | Vera block |",
        phases.register_object_ms
    );
    eprintln!("| Grant writer | {} | Vera block |", phases.grant_writer_ms);
    eprintln!(
        "| Ignite the cell | {} | the process starting |",
        phases.cell_ignition_ms
    );
    eprintln!("| Add the schema | {} | local |", phases.schema_ms);
    eprintln!(
        "| First ring-signed write | {} | ring round trip and a Vera registration |",
        phases.first_write_ms
    );
    eprintln!("| **Total** | **{}** | |", phases.total_ms);
}

/// One provisioned tenant: the cell's own node identity, the service identity
/// that writes and reads as the tenant, the cell, and the document it wrote.
struct Tenant {
    /// The identity a client presents. Deliberately not the node identity:
    /// DefraDB resolves the signing config for the request DID from a
    /// process-global registry, and the node's own DID has a local key
    /// registered there, so a write made as the node identity signs locally
    /// and never reaches the ring.
    identity: ServiceIdentity,
    cell: Cell,
    doc_id: String,
}

/// Wall time of each step of provisioning one tenant, so a total can be read
/// as what it is made of rather than as one opaque number.
#[derive(Default, Clone, Copy)]
struct ProvisionPhases {
    fund_ms: u128,
    policy_ms: u128,
    register_object_ms: u128,
    grant_writer_ms: u128,
    cell_ignition_ms: u128,
    schema_ms: u128,
    first_write_ms: u128,
    total_ms: u128,
}

/// Provision one tenant end to end, the way the operator would: its own policy
/// on Vera, its own collection object and writer grant, its own cell, its own
/// schema, and one document written through the ring.
///
/// Each step is timed separately. Four of the seven are chain transactions that
/// cannot return until Vera commits a block, so a total dominated by them says
/// nothing about how fast a cell starts; `cell_ignition_ms` is the number that
/// does.
async fn provision_tenant(stack: &Stack, index: usize) -> (Tenant, ProvisionPhases) {
    let total = Instant::now();
    let mut phases = ProvisionPhases::default();
    let label = format!("scale-tenant-{}", index);
    let node_key = ServiceIdentity::new(&label);
    let identity = ServiceIdentity::new(&format!("{}-svc", label));

    let step = Instant::now();
    stack
        .vera_cli
        .fund(&node_key.vera_address)
        .unwrap_or_else(|e| panic!("fund {}: {}", label, e));
    phases.fund_ms = step.elapsed().as_millis();

    let step = Instant::now();
    let policy_id = stack
        .vera_cli
        .create_policy(&crate::fixture::ACME_POLICY_YAML.replace(
            "name: acme-training-policy",
            &format!("name: {}-policy", label),
        ))
        .unwrap_or_else(|e| panic!("create policy for {}: {}", label, e));
    phases.policy_ms = step.elapsed().as_millis();

    let step = Instant::now();
    stack
        .vera_cli
        .register_object(&policy_id, TRANSCRIPT_RESOURCE, TRANSCRIPT_RESOURCE)
        .unwrap_or_else(|e| panic!("register collection object for {}: {}", label, e));
    phases.register_object_ms = step.elapsed().as_millis();

    let step = Instant::now();
    stack
        .vera_cli
        .set_relationship(
            &policy_id,
            TRANSCRIPT_RESOURCE,
            TRANSCRIPT_RESOURCE,
            "writer",
            &identity.did_key,
        )
        .unwrap_or_else(|e| panic!("grant writer for {}: {}", label, e));
    phases.grant_writer_ms = step.elapsed().as_millis();

    let step = Instant::now();
    let cell = stack
        .start_cell(CellSpec {
            name: &label,
            identity: &node_key,
            derivation: &label,
            invalidation: Invalidation::Eager,
            ring_signed: true,
        })
        .await;
    phases.cell_ignition_ms = step.elapsed().as_millis();

    let step = Instant::now();
    cell.http
        .schema_add(&transcript_schema(&policy_id))
        .await
        .unwrap_or_else(|e| panic!("schema for {}: {}", label, e));
    phases.schema_ms = step.elapsed().as_millis();

    let step = Instant::now();
    let outcome = create_transcripts(
        &cell,
        &identity,
        &[("call-scale", "One document per tenant", "cust")],
    )
    .await;
    phases.first_write_ms = step.elapsed().as_millis();
    let doc_id = match outcome {
        WriteOutcome::Created(ids) => ids[0].clone(),
        other => panic!("{} write: {}", label, other.detail()),
    };

    phases.total_ms = total.elapsed().as_millis();
    (
        Tenant {
            identity,
            cell,
            doc_id,
        },
        phases,
    )
}

/// How many tenants to provision. `GENTS_CLOUD_TENANTS` overrides the default,
/// which is small enough to keep the suite runnable on a laptop.
fn tenant_count() -> usize {
    std::env::var("GENTS_CLOUD_TENANTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|count| *count > 0)
        .unwrap_or(4)
}

/// How often to take a curve measurement, so a run yields four to eight rows
/// whatever the tenant count.
fn checkpoint_every(tenant_count: usize) -> usize {
    (tenant_count / 4).max(1)
}

/// Resident memory of a cell's process, from `/proc/<pid>/status`.
fn cell_rss_kib(cell: &Cell) -> Option<u64> {
    let pid = cell.node.process.id()?;
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next()?.parse().ok())
}

/// Median wall time of three reads of `collection` as `identity`.
async fn read_latency_ms(cell: &Cell, identity: &ServiceIdentity, collection: &str) -> u128 {
    let mut samples = Vec::with_capacity(3);
    for _ in 0..3 {
        let start = Instant::now();
        let _ = visible_doc_ids(cell, identity, collection).await;
        samples.push(start.elapsed().as_millis());
    }
    median(&samples)
}

fn median(samples: &[u128]) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}
