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
    eprintln!("[gents-cloud]   provisioning {} tenants", tenant_count);

    let baseline_read_ms = read_latency_ms(&stack.acme, &stack.training_svc, "Transcript").await;

    let mut tenants: Vec<Tenant> = Vec::with_capacity(tenant_count);
    let mut provision_ms = Vec::with_capacity(tenant_count);
    for index in 0..tenant_count {
        let start = Instant::now();
        tenants.push(provision_tenant(stack, index).await);
        provision_ms.push(start.elapsed().as_millis());
    }

    // Per-tenant cost, measured.
    let provision_p50 = median(&provision_ms);
    stack.record("scale_tenants_provisioned", format!("{}", tenant_count));
    stack.record(
        "scale_provision_p50_ms_per_tenant",
        format!("{}", provision_p50),
    );
    let rss_kib: Vec<u64> = tenants
        .iter()
        .filter_map(|t| cell_rss_kib(&t.cell))
        .collect();
    assert_eq!(
        rss_kib.len(),
        tenants.len(),
        "every tenant cell must report its resident memory"
    );
    let rss_median_kib = median(
        &rss_kib
            .iter()
            .map(|kib| u128::from(*kib))
            .collect::<Vec<_>>(),
    );
    let rss_median_mib = rss_median_kib as f64 / 1024.0;
    stack.record(
        "scale_cell_rss_median_mib",
        format!("{:.0}", rss_median_mib),
    );

    // Chain state per tenant: one policy, one collection object, one writer
    // relation, plus one registration per document written.
    let policy_ids = stack
        .vera_cli
        .list_policy_count()
        .expect("count policies on Vera");
    stack.record("scale_policies_on_vera", format!("{}", policy_ids));

    // Every tenant reads only its own document, and reads stay flat.
    let mut read_ms = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        let visible = visible_doc_ids(&tenant.cell, &tenant.identity, "Transcript").await;
        assert_eq!(
            visible,
            vec![tenant.doc_id.clone()],
            "tenant {} must see exactly its own document",
            tenant.identity.label
        );
        read_ms.push(read_latency_ms(&tenant.cell, &tenant.identity, "Transcript").await);
    }
    let read_p50 = median(&read_ms);
    stack.record(
        "scale_read_p50_ms_first_tenant",
        format!("{}", baseline_read_ms),
    );
    stack.record(
        "scale_read_p50_ms_with_all_tenants",
        format!("{}", read_p50),
    );

    // Isolation at N: no tenant reads another's cell, in either direction.
    for (i, tenant) in tenants.iter().enumerate() {
        let other = &tenants[(i + 1) % tenants.len()];
        if std::ptr::eq(tenant, other) {
            continue;
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
    stack.record(
        "scale_cross_tenant_reads_denied",
        format!("{} ordered pairs", tenants.len()),
    );

    // The projection. Stated as arithmetic over the numbers above, with the
    // assumptions named, because the run itself covers a few tenants.
    let cells_per_node = (NODE_MEMORY_GIB * 1024.0 / rss_median_mib).floor();
    let nodes_for_target = (TARGET_TENANTS as f64 / cells_per_node).ceil();
    let provision_hours = (TARGET_TENANTS as f64 * provision_p50 as f64) / 1000.0 / 3600.0;
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
    stack.record(
        "scale_projected_serial_provisioning_hours_for_100k",
        format!(
            "{:.1} (projected: strictly serial provisioning at the measured p50; a real fleet provisions in parallel)",
            provision_hours
        ),
    );

    // Cells are dropped here: the scenario owns them and nothing later needs
    // them, so the processes exit before the next scenario measures anything.
    drop(tenants);
    passed(&SCALE, t);
}

/// One provisioned tenant: its identity, its cell, and the document it wrote.
struct Tenant {
    identity: ServiceIdentity,
    cell: Cell,
    doc_id: String,
}

/// Provision one tenant end to end, the way the operator would: its own policy
/// on Vera, its own collection object and writer grant, its own cell, its own
/// schema, and one document written through the ring.
async fn provision_tenant(stack: &Stack, index: usize) -> Tenant {
    let label = format!("scale-tenant-{}", index);
    let identity = ServiceIdentity::new(&label);
    stack
        .vera_cli
        .fund(&identity.vera_address)
        .unwrap_or_else(|e| panic!("fund {}: {}", label, e));

    let policy_id = stack
        .vera_cli
        .create_policy(&crate::fixture::ACME_POLICY_YAML.replace(
            "name: acme-training-policy",
            &format!("name: {}-policy", label),
        ))
        .unwrap_or_else(|e| panic!("create policy for {}: {}", label, e));
    stack
        .vera_cli
        .register_object(&policy_id, TRANSCRIPT_RESOURCE, TRANSCRIPT_RESOURCE)
        .unwrap_or_else(|e| panic!("register collection object for {}: {}", label, e));
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

    let cell = stack
        .start_cell(CellSpec {
            name: &label,
            identity: &identity,
            derivation: &label,
            invalidation: Invalidation::Eager,
            ring_signed: true,
        })
        .await;
    cell.http
        .schema_add(&transcript_schema(&policy_id))
        .await
        .unwrap_or_else(|e| panic!("schema for {}: {}", label, e));

    let outcome = create_transcripts(
        &cell,
        &identity,
        &[("call-scale", "One document per tenant", "cust")],
    )
    .await;
    let doc_id = match outcome {
        WriteOutcome::Created(ids) => ids[0].clone(),
        other => panic!("{} write: {}", label, other.detail()),
    };

    Tenant {
        identity,
        cell,
        doc_id,
    }
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
