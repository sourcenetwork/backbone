//! The gents-cloud stack on Go Vera: one `verad` devnet, one Orbis ring
//! (T=2, N=3) whose DKG artifact lives on Vera's bulletin, and DefraDB cells
//! that enforce document ACP against Vera and ring-sign every block.
//!
//! Every scenario in this test binary runs on one instance of this stack.
//! Building it costs roughly a minute, so scenarios share it and are ordered
//! so that none depends on state another one tore down.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use defra_harness::node::RustNode;
use defra_harness::{
    start_node, DefraClient, KeyringBackend, NodeConfig, NodeKind, OrbisSignerConfig, RunningNode,
};
use orbis_harness::cli::ed25519_identity_hex;
use orbis_harness::cli::types::RingPayload;
use orbis_harness::defradb::identity::{
    did_key_from_secp256k1, DefraHttpClient, RelationshipChange,
};
use orbis_harness::{
    allocate_source_hub_ports, generate_identity_keys, generate_run_id, source_hub_address,
    BulletinEventSubscription, OrbisCliClient, OrbisRing, SourceHubCliClient, SourceHubConfig,
    SourceHubNode,
};
use sha2::{Digest, Sha256};

use crate::support::full_stack::{configure_replication_link, wait_for_orbis_node_infos};

pub const BULLETIN_RING_NAMESPACE: &str = "orbis";
pub const TRANSCRIPT_RESOURCE: &str = "transcript";
pub const TICKET_RESOURCE: &str = "ticket";

/// Balance each ring node is funded with.
///
/// A node blocks at startup until its balance reaches its own minimum
/// (1,000,000 uopen) and then spends fees from it, so funding exactly the
/// minimum leaves it unable to restart after the DKG transactions. The margin
/// is what makes the below-threshold recovery scenario reproducible.
pub const RING_NODE_FUNDING_UOPEN: u128 = 20_000_000;

/// Query-gate cache lifetime on the cell that has no eager invalidation
/// (`--acp-cache-ttl`, seconds). H5's slow clock is bounded by this value.
pub const TTL_ONLY_CACHE_SECS: u64 = 15;

/// Tenant policies.
///
/// Neither declares an `owner` relation and no expression references one:
/// Vera's acp_core discretionary transformer adds `owner` to every resource
/// itself and rejects a policy that declares it (`'owner` is a reserved
/// relation name`) or that names it in a permission expression. The document
/// creator therefore holds owner authority implicitly, which is what makes the
/// creator-reads-own-document assertions hold without an explicit grant.
pub const ACME_POLICY_YAML: &str = r#"
name: acme-training-policy
resources:
  - name: transcript
    relations:
      - name: reader
        types:
          - actor
      - name: writer
        types:
          - actor
    permissions:
      - name: read
        expr: writer + reader
      - name: update
        expr: writer
      - name: delete
        expr: writer
"#;

pub const GLOBEX_POLICY_YAML: &str = r#"
name: globex-support-policy
resources:
  - name: ticket
    relations:
      - name: reader
        types:
          - actor
      - name: writer
        types:
          - actor
    permissions:
      - name: read
        expr: writer + reader
      - name: update
        expr: writer
      - name: delete
        expr: writer
"#;

/// A secp256k1 identity used as a DefraDB request identity, a Vera ACP actor,
/// or a DefraDB node identity. Keys derive deterministically from the label.
#[derive(Clone)]
pub struct ServiceIdentity {
    pub label: String,
    pub private_key_hex: String,
    pub did_key: String,
    /// Vera account address (`vera1...`) of this key.
    pub vera_address: String,
}

impl ServiceIdentity {
    pub fn new(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"gents-cloud-e2e-seed-v1:");
        hasher.update(label.as_bytes());
        let private_key_hex = hex::encode(hasher.finalize());
        let (did_key, _) = did_key_from_secp256k1(&private_key_hex)
            .unwrap_or_else(|e| panic!("derive did:key for {}: {}", label, e));
        let vera_address = source_hub_address(&private_key_hex)
            .unwrap_or_else(|e| panic!("derive vera address for {}: {}", label, e));
        Self {
            label: label.to_string(),
            private_key_hex,
            did_key,
            vera_address,
        }
    }
}

/// One DefraDB cell: the process, its clients, and the identity it signs
/// Vera transactions with.
pub struct Cell {
    pub name: String,
    pub node: RunningNode,
    pub http: DefraHttpClient,
    pub cli: DefraClient,
}

impl Cell {
    pub fn api_url(&self) -> &str {
        &self.node.api_url
    }
}

/// How a cell learns about Vera ACP changes (H5's read-path clock).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    /// CometBFT websocket subscription: every ACP transaction clears the
    /// affected cache entries as soon as its block is committed.
    Eager,
    /// No subscription: a cached decision lives until `TTL_ONLY_CACHE_SECS`.
    TtlOnly,
}

pub struct CellSpec<'a> {
    pub name: &'a str,
    pub identity: &'a ServiceIdentity,
    pub derivation: &'a str,
    pub invalidation: Invalidation,
    pub ring_signed: bool,
}

/// The running stack. Field order is drop order: cells first, then the ring,
/// then Vera, then the run directory that held all of their data.
pub struct Stack {
    pub acme: Cell,
    pub globex: Cell,
    pub platform: Cell,
    pub ring: OrbisRing,
    pub vera: SourceHubNode,
    pub vera_cli: SourceHubCliClient,
    pub orbis_cli: OrbisCliClient,
    pub ring_id: String,
    pub ring_pk_hex: String,
    pub defra_binary: PathBuf,
    pub acme_policy_id: String,
    pub globex_policy_id: String,
    pub training_svc: ServiceIdentity,
    pub inference_svc: ServiceIdentity,
    pub audit_svc: ServiceIdentity,
    pub globex_svc: ServiceIdentity,
    pub acme_node_key: ServiceIdentity,
    /// Funded at genesis so a later scenario can start an unsigned cell.
    pub unsigned_node_key: ServiceIdentity,
    /// Never funded: the "dry account" cell of scenario `dry_account`.
    pub dry_node_key: ServiceIdentity,
    /// Transcripts written on acme by `training_svc`; filled by the first
    /// identity scenario and read by every later one.
    pub transcript_doc_ids: Vec<String>,
    /// Tickets written on globex by `globex_svc`.
    pub ticket_doc_ids: Vec<String>,
    pub measurements: Vec<(String, String)>,
    run_dir: test_infra::TestRunDir,
}

impl Stack {
    /// Record a measured number for the final report. Values are printed as
    /// given; nothing here is a target, only what was observed.
    pub fn record(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        eprintln!("[gents-cloud]   measured {} = {}", name, value);
        self.measurements.push((name.to_string(), value));
    }

    /// Start a DefraDB cell against this stack's Vera and ring.
    pub async fn start_cell(&self, spec: CellSpec<'_>) -> Cell {
        start_cell(
            &self.defra_binary,
            &self.run_dir,
            &self.vera,
            &self.ring,
            &self.ring_id,
            spec,
        )
        .await
    }
}

fn comet_ws_url(comet_rpc_url: &str) -> String {
    let host = comet_rpc_url
        .strip_prefix("http://")
        .unwrap_or(comet_rpc_url);
    format!("ws://{}/websocket", host)
}

async fn start_cell(
    defra_binary: &Path,
    run_dir: &test_infra::TestRunDir,
    vera: &SourceHubNode,
    ring: &OrbisRing,
    ring_id: &str,
    spec: CellSpec<'_>,
) -> Cell {
    let ports = test_infra::allocate_ports(2).expect("allocate cell ports");
    let dir = run_dir.node_dir(spec.name).expect("cell dir");
    let log_dir = dir.join("logs");
    let rootdir = dir.join("data");
    let http_addr = format!("127.0.0.1:{}", ports[0]);

    let mut config = NodeConfig::new(spec.name, rootdir.clone(), log_dir, http_addr);
    config.p2p_enabled = true;
    config.p2p_addr = Some(format!("/ip4/127.0.0.1/tcp/{}", ports[1]));
    // Regolith is the persistent store; the memory store is banned in cloud
    // (gents-cloud §26) and would defeat the kill -9 recovery scenario.
    config.store = Some("regolith".to_string());
    config.identity = Some(spec.identity.private_key_hex.clone());
    config.acp_document_type = Some("source-hub".to_string());
    config.source_hub = Some(SourceHubConfig::from(vera));
    config.keyring = KeyringBackend::File {
        path: rootdir.join("keys"),
        secret: "e2e-test-password".to_string(),
    };
    if spec.ring_signed {
        // A ring signature is BLS, which Go peers cannot verify, so the node
        // refuses to emit one unless the operator opts in. Ring-signed writes
        // (gents-cloud H3) are therefore a deployment decision, not a per-key
        // one, and a cloud that wants them must set this on every cell.
        config.extra_envs.push((
            "DEFRA_ALLOW_NON_GO_VERIFIABLE_SIGNING".to_string(),
            "1".to_string(),
        ));
        config.orbis_signer = Some(OrbisSignerConfig {
            endpoint: ring.node(0).grpc_addr(),
            ring_id: ring_id.to_string(),
            derivation: spec.derivation.to_string(),
            // The ring authenticates bearer tokens as EdDSA only, and the
            // cell's `--identity` must stay secp256k1 to sign Vera
            // transactions. Two keys, one cell: gents-cloud H1 in miniature.
            service_identity: Some(ed25519_identity_hex(&spec.identity.private_key_hex)),
        });
    }
    match spec.invalidation {
        Invalidation::Eager => config.extra_args.extend([
            "--source-hub-events-ws".to_string(),
            comet_ws_url(&vera.comet_rpc_url),
        ]),
        Invalidation::TtlOnly => config.acp_cache_ttl = Some(TTL_ONLY_CACHE_SECS),
    }

    let node = start_node(
        &RustNode::from_binary(defra_binary),
        config,
        Duration::from_secs(60),
    )
    .await
    .unwrap_or_else(|e| panic!("cell {} should start: {:?}", spec.name, e));

    let http =
        DefraHttpClient::new(&node.api_url).with_authorized_account(&spec.identity.vera_address);
    let cli = DefraClient::new(defra_binary, &node.http_addr, NodeKind::Rust);
    eprintln!(
        "[gents-cloud]   cell {} ready at {} (node DID {}, vera {})",
        spec.name, node.api_url, spec.identity.did_key, spec.identity.vera_address
    );
    Cell {
        name: spec.name.to_string(),
        node,
        http,
        cli,
    }
}

/// Bring the whole stack up. Panics with the failing step named.
pub async fn build() -> Stack {
    let t0 = Instant::now();
    let run_id = generate_run_id();
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("e2e")
        .join("gents-cloud");
    let run_dir = test_infra::TestRunDir::new(&base_dir, "BACKBONE_E2E_KEEP").expect("run dir");
    eprintln!("[gents-cloud] run dir: {}", run_dir.path().display());

    let defra_binary = test_infra::BinaryResolver::new("DEFRA", "defra-iroh")
        .cargo_package("cli")
        .resolve()
        .expect("resolve defra-iroh binary")
        .path;

    let orbis_operator_keys = generate_identity_keys(&run_id, 3);
    let acme_node_key = ServiceIdentity::new("acme-cell");
    let globex_node_key = ServiceIdentity::new("globex-cell");
    let platform_node_key = ServiceIdentity::new("platform-cell");
    let unsigned_node_key = ServiceIdentity::new("unsigned-cell");
    let dry_node_key = ServiceIdentity::new("dry-cell");
    let training_svc = ServiceIdentity::new("training-svc");
    let inference_svc = ServiceIdentity::new("inference-svc");
    let audit_svc = ServiceIdentity::new("audit-svc");
    let globex_svc = ServiceIdentity::new("globex-svc");

    // Step 1. Vera devnet. Every key that must pay for a transaction is funded
    // at genesis; the dry cell's key deliberately is not.
    eprintln!("[gents-cloud] Step 1: starting Vera (verad) devnet...");
    let mut funded_keys = orbis_operator_keys.clone();
    funded_keys.extend([
        acme_node_key.private_key_hex.clone(),
        globex_node_key.private_key_hex.clone(),
        platform_node_key.private_key_hex.clone(),
        unsigned_node_key.private_key_hex.clone(),
    ]);
    let vera_ports = allocate_source_hub_ports().expect("vera ports");
    let vera_home = run_dir.node_dir("vera").expect("vera dir");
    let vera_log_dir = vera_home.join("logs");
    std::fs::create_dir_all(&vera_log_dir).expect("vera log dir");
    let vera = SourceHubNode::start(
        vera_home,
        vera_log_dir,
        &vera_ports,
        &funded_keys,
        Duration::from_secs(90),
    )
    .await
    .expect("Vera devnet should start");
    let vera_cli = SourceHubCliClient::from_node(&vera).expect("resolve verad binary");
    eprintln!(
        "[gents-cloud]   Vera ready in {:.1}s: lcd={} comet={} grpc={}",
        t0.elapsed().as_secs_f64(),
        vera.lcd_url,
        vera.comet_rpc_url,
        vera.grpc_url
    );

    // Step 2. Orbis ring in Vera mode (authz, bulletin, and chain via Vera).
    eprintln!("[gents-cloud] Step 2: starting Orbis ring (3 nodes, threshold 2)...");
    let mut ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(orbis_operator_keys)
        .sourcehub_config(SourceHubConfig::from(&vera))
        .build()
        .await
        .expect("ring should start");

    // An Orbis node generates its Vera signing key on first start and writes
    // the address to `data/public_key.txt`. It also reads its account number
    // once, at connect time, and an account that does not exist yet reads as
    // number 0. Funding it afterwards therefore leaves the process signing
    // with a stale account number, and every transaction it sends fails
    // signature verification. So: let the nodes mint their keys, fund the
    // addresses, then restart the nodes onto the same data directories so
    // they read the account numbers the funding created.
    let mut ring_addresses = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        ring_addresses.push(wait_for_orbis_chain_address(ring.node(i).data_dir(), i).await);
    }
    for i in 0..ring.node_count() {
        ring.node_mut(i).kill();
    }
    for (i, address) in ring_addresses.iter().enumerate() {
        eprintln!("[gents-cloud]   funding orbis node{} at {}", i, address);
        vera_cli
            .fund_amount(address, RING_NODE_FUNDING_UOPEN)
            .unwrap_or_else(|e| panic!("fund orbis node{}: {}", i, e));
    }
    for i in 0..ring.node_count() {
        ring.node_mut(i)
            .restart()
            .unwrap_or_else(|e| panic!("restart orbis node{} after funding: {}", i, e));
    }
    ring.wait_ready(Duration::from_secs(90))
        .await
        .expect("ring nodes should become healthy");
    let node_infos = wait_for_orbis_node_infos(ring.grpc_addrs(), Duration::from_secs(60))
        .await
        .expect("ring nodes should report info");
    let orbis_cli = OrbisCliClient::new().expect("resolve cli-tool binary");

    // Step 3. Bulletin namespace on Vera, collaborators, DKG, ring artifact.
    eprintln!("[gents-cloud] Step 3: DKG with the artifact posted to Vera's bulletin...");
    vera_cli
        .register_namespace(BULLETIN_RING_NAMESPACE)
        .expect("register bulletin namespace");
    for info in &node_infos {
        vera_cli
            .add_collaborator(BULLETIN_RING_NAMESPACE, &info.public_address)
            .unwrap_or_else(|e| panic!("add collaborator {}: {}", info.public_address, e));
    }
    let events = BulletinEventSubscription::connect(&vera.comet_rpc_url)
        .await
        .expect("bulletin event subscription");
    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();
    let dkg_start = Instant::now();
    let dkg = orbis_cli
        .do_dkg(&ring.node(0).grpc_addr(), ring.threshold(), &peer_ids)
        .expect("DKG should succeed");
    let post = events
        .wait_for_artifact(&dkg.session_id, Duration::from_secs(120))
        .await
        .expect("DKG artifact event on Vera");
    let payload = vera_cli
        .read_post(BULLETIN_RING_NAMESPACE, &post.post_id)
        .expect("read ring payload from Vera");
    let ring_payload: RingPayload = serde_json::from_slice(&payload).expect("parse RingPayload");
    let ring_id = post.post_id;
    let ring_pk_hex = ring_payload.ring_pk;
    eprintln!(
        "[gents-cloud]   DKG complete in {:.1}s: ring_id={}... ring_pk={}...",
        dkg_start.elapsed().as_secs_f64(),
        &ring_id[..16.min(ring_id.len())],
        &ring_pk_hex[..16.min(ring_pk_hex.len())]
    );

    // Step 4. Tenant policies on Vera, collection-level objects, writer grants.
    eprintln!("[gents-cloud] Step 4: tenant ACP policies on Vera...");
    let acme_policy_id = vera_cli
        .create_policy(ACME_POLICY_YAML)
        .expect("create acme policy");
    let globex_policy_id = vera_cli
        .create_policy(GLOBEX_POLICY_YAML)
        .expect("create globex policy");
    vera_cli
        .register_object(&acme_policy_id, TRANSCRIPT_RESOURCE, TRANSCRIPT_RESOURCE)
        .expect("register transcript collection object");
    vera_cli
        .set_relationship(
            &acme_policy_id,
            TRANSCRIPT_RESOURCE,
            TRANSCRIPT_RESOURCE,
            "writer",
            &training_svc.did_key,
        )
        .expect("grant training_svc writer on transcript collection object");
    vera_cli
        .register_object(&globex_policy_id, TICKET_RESOURCE, TICKET_RESOURCE)
        .expect("register ticket collection object");
    vera_cli
        .set_relationship(
            &globex_policy_id,
            TICKET_RESOURCE,
            TICKET_RESOURCE,
            "writer",
            &globex_svc.did_key,
        )
        .expect("grant globex_svc writer on ticket collection object");
    eprintln!(
        "[gents-cloud]   acme policy {} / globex policy {}",
        acme_policy_id, globex_policy_id
    );

    // Step 4a. The ring must sign with the key it advertises.
    //
    // DefraDB asks the ring for the public key of its derivation label once at
    // startup and stamps that key into every block it signs; every peer then
    // verifies the block signature against it. If the ring signs from the root
    // key instead, nothing fails at signing time and the mismatch only surfaces
    // on a peer as `BLST_VERIFY_FAIL`, after the write was acknowledged. So
    // check the two keys agree before any cell exists.
    let derivation_hex = hex::encode(b"acme-corp");
    let advertised = orbis_cli
        .derive_public_key(&ring.node(0).grpc_addr(), &ring_id, &derivation_hex)
        .expect("derive the acme derivation public key");
    let probe_message = b"gents-cloud ring key consistency probe";
    let signed = orbis_cli
        .do_sign(
            &ring.node(0).grpc_addr(),
            &ring_id,
            &hex::encode(probe_message),
            Some(&derivation_hex),
            Some(&ServiceIdentity::new("ring-probe").private_key_hex),
            None,
        )
        .expect("sign with the acme derivation");
    assert_eq!(
        signed.public_key.to_lowercase(),
        advertised.derived_public_key.to_lowercase(),
        "the ring signed under a different key than DerivePublicKey advertises: \
         every block signed through this derivation is unverifiable on a peer"
    );
    assert!(
        bls_verify(
            &advertised.derived_public_key,
            probe_message,
            &signed.signature
        ),
        "the ring's threshold signature does not verify under the key it advertises, \
         using the same BLS primitive and domain tag DefraDB verifies blocks with"
    );
    eprintln!(
        "[gents-cloud]   ring signature verifies under the advertised derived key ({}...)",
        &advertised.derived_public_key[..16.min(advertised.derived_public_key.len())]
    );

    // Step 5. Cells. Acme and platform invalidate eagerly; globex is the
    // TTL-only cell that measures H5's slow clock.
    eprintln!("[gents-cloud] Step 5: starting DefraDB cells...");
    let acme = start_cell(
        &defra_binary,
        &run_dir,
        &vera,
        &ring,
        &ring_id,
        CellSpec {
            name: "acme",
            identity: &acme_node_key,
            derivation: "acme-corp",
            invalidation: Invalidation::Eager,
            ring_signed: true,
        },
    )
    .await;
    let globex = start_cell(
        &defra_binary,
        &run_dir,
        &vera,
        &ring,
        &ring_id,
        CellSpec {
            name: "globex",
            identity: &globex_node_key,
            derivation: "globex-inc",
            invalidation: Invalidation::TtlOnly,
            ring_signed: true,
        },
    )
    .await;
    let platform = start_cell(
        &defra_binary,
        &run_dir,
        &vera,
        &ring,
        &ring_id,
        CellSpec {
            name: "platform",
            identity: &platform_node_key,
            derivation: "platform",
            invalidation: Invalidation::Eager,
            ring_signed: true,
        },
    )
    .await;

    // Step 6. Schemas with @policy, and platform as the replica peer of both.
    eprintln!("[gents-cloud] Step 6: schemas and replication links...");
    let transcript_schema = transcript_schema(&acme_policy_id);
    let ticket_schema = ticket_schema(&globex_policy_id);
    acme.http
        .schema_add(&transcript_schema)
        .await
        .expect("acme transcript schema");
    platform
        .http
        .schema_add(&transcript_schema)
        .await
        .expect("platform transcript schema");
    globex
        .http
        .schema_add(&ticket_schema)
        .await
        .expect("globex ticket schema");
    platform
        .http
        .schema_add(&ticket_schema)
        .await
        .expect("platform ticket schema");
    configure_replication_link(
        &acme.cli,
        acme.api_url(),
        &platform.cli,
        &["Transcript"],
        "acme -> platform",
    )
    .await;
    configure_replication_link(
        &globex.cli,
        globex.api_url(),
        &platform.cli,
        &["SupportTicket"],
        "globex -> platform",
    )
    .await;

    eprintln!(
        "[gents-cloud] stack ready in {:.1}s",
        t0.elapsed().as_secs_f64()
    );
    let mut stack = Stack {
        acme,
        globex,
        platform,
        ring,
        vera,
        vera_cli,
        orbis_cli,
        ring_id,
        ring_pk_hex,
        defra_binary,
        acme_policy_id,
        globex_policy_id,
        training_svc,
        inference_svc,
        audit_svc,
        globex_svc,
        acme_node_key,
        unsigned_node_key,
        dry_node_key,
        transcript_doc_ids: Vec::new(),
        ticket_doc_ids: Vec::new(),
        measurements: Vec::new(),
        run_dir,
    };
    stack.record(
        "stack_bring_up_secs",
        format!("{:.1}", t0.elapsed().as_secs_f64()),
    );
    stack
}

pub fn transcript_schema(policy_id: &str) -> String {
    format!(
        r#"type Transcript @policy(id: "{}", resource: "{}") {{ call_id: String  content: String  customer: String }}"#,
        policy_id, TRANSCRIPT_RESOURCE
    )
}

pub fn ticket_schema(policy_id: &str) -> String {
    format!(
        r#"type SupportTicket @policy(id: "{}", resource: "{}") {{ ticket_id: String  subject: String  body: String  priority: String }}"#,
        policy_id, TICKET_RESOURCE
    )
}

/// Outcome of a GraphQL mutation, classified for the write-path scenarios.
#[derive(Debug)]
pub enum WriteOutcome {
    /// The mutation returned document ids.
    Created(Vec<String>),
    /// The node answered but refused the write; the text is the error list.
    Refused(String),
    /// The HTTP layer failed (5xx, connection reset); the text is the error.
    Failed(String),
}

impl WriteOutcome {
    pub fn is_refused_or_failed(&self) -> bool {
        !matches!(self, WriteOutcome::Created(_))
    }

    pub fn detail(&self) -> String {
        match self {
            WriteOutcome::Created(ids) => format!("created {:?}", ids),
            WriteOutcome::Refused(e) | WriteOutcome::Failed(e) => e.clone(),
        }
    }
}

/// Create transcripts in one batch mutation as `identity`.
pub async fn create_transcripts(
    cell: &Cell,
    identity: &ServiceIdentity,
    rows: &[(&str, &str, &str)],
) -> WriteOutcome {
    let inputs = rows
        .iter()
        .map(|(call_id, content, customer)| {
            format!(
                "{{ call_id: {}, content: {}, customer: {} }}",
                graphql_string_literal(call_id),
                graphql_string_literal(content),
                graphql_string_literal(customer)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mutation = format!(
        "mutation {{ add_Transcript(input: [{}]) {{ _docID call_id }} }}",
        inputs
    );
    classify_write(
        cell.http
            .graphql(&mutation, Some(&identity.private_key_hex))
            .await,
        "/data/add_Transcript",
    )
}

/// Create tickets in one batch mutation as `identity`.
pub async fn create_tickets(
    cell: &Cell,
    identity: &ServiceIdentity,
    rows: &[(&str, &str, &str, &str)],
) -> WriteOutcome {
    let inputs = rows
        .iter()
        .map(|(ticket_id, subject, body, priority)| {
            format!(
                "{{ ticket_id: {}, subject: {}, body: {}, priority: {} }}",
                graphql_string_literal(ticket_id),
                graphql_string_literal(subject),
                graphql_string_literal(body),
                graphql_string_literal(priority)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mutation = format!(
        "mutation {{ add_SupportTicket(input: [{}]) {{ _docID ticket_id }} }}",
        inputs
    );
    classify_write(
        cell.http
            .graphql(&mutation, Some(&identity.private_key_hex))
            .await,
        "/data/add_SupportTicket",
    )
}

fn classify_write(result: eyre::Result<serde_json::Value>, pointer: &str) -> WriteOutcome {
    let body = match result {
        Ok(body) => body,
        Err(e) => return WriteOutcome::Failed(e.to_string()),
    };
    if let Some(errors) = body.get("errors").and_then(|v| v.as_array()) {
        if !errors.is_empty() {
            let messages = errors
                .iter()
                .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                .collect::<Vec<_>>()
                .join("; ");
            return WriteOutcome::Refused(messages);
        }
    }
    match body.pointer(pointer).and_then(|v| v.as_array()) {
        Some(rows) if !rows.is_empty() => WriteOutcome::Created(
            rows.iter()
                .filter_map(|r| r.get("_docID").and_then(|v| v.as_str()))
                .map(str::to_string)
                .collect(),
        ),
        _ => WriteOutcome::Refused(format!("no documents in response: {}", body)),
    }
}

/// Document ids `identity` can currently read from `collection` on `cell`.
pub async fn visible_doc_ids(
    cell: &Cell,
    identity: &ServiceIdentity,
    collection: &str,
) -> Vec<String> {
    let query = format!("query {{ {} {{ _docID }} }}", collection);
    let body = cell
        .http
        .graphql(&query, Some(&identity.private_key_hex))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}: query {} as {}: {}",
                cell.name, collection, identity.label, e
            )
        });
    body.pointer(&format!("/data/{}", collection))
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.get("_docID").and_then(|v| v.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Poll until `condition` holds, returning how long it took, or `None` when
/// `timeout` passes first. For a property that may legitimately not happen.
pub async fn wait_until_or_timeout<F, Fut>(timeout: Duration, mut condition: F) -> Option<Duration>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    loop {
        if condition().await {
            return Some(start.elapsed());
        }
        if start.elapsed() > timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Poll until `condition` holds or `timeout` passes; returns the elapsed time.
pub async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut condition: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    loop {
        if condition().await {
            return start.elapsed();
        }
        if start.elapsed() > timeout {
            panic!("{}: condition not met within {:?}", label, timeout);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// One access question for Vera: may `actor_did` do `permission` on
/// `resource:object_id` under `policy_id`?
#[derive(Clone, Copy)]
pub struct AccessCheck<'a> {
    pub policy_id: &'a str,
    pub actor_did: &'a str,
    pub resource: &'a str,
    pub object_id: &'a str,
    pub permission: &'a str,
}

/// Poll Vera until its own answer matches `expected`, returning how long that
/// took.
///
/// This is the authoritative clock the cell-side clocks are measured against:
/// the chain's answer, with no cache in front of it.
pub fn wait_for_vera_access(
    vera_cli: &SourceHubCliClient,
    check: AccessCheck<'_>,
    expected: bool,
    timeout: Duration,
) -> Duration {
    let start = Instant::now();
    loop {
        let valid = vera_cli
            .verify_access(
                check.policy_id,
                check.actor_did,
                check.resource,
                check.object_id,
                check.permission,
            )
            .unwrap_or_else(|e| panic!("verify-access-request on Vera: {}", e));
        if valid == expected {
            return start.elapsed();
        }
        if start.elapsed() > timeout {
            panic!(
                "Vera did not report {}={} for {} on {}:{} within {:?}",
                check.permission,
                expected,
                check.actor_did,
                check.resource,
                check.object_id,
                timeout
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn graphql_string_literal(value: &str) -> String {
    serde_json::to_string(value).expect("serialize GraphQL string literal")
}

/// Grant `relation` on one document to `actor_did`, as the document's owner.
///
/// Vera authorises a relationship write against the object's manager, and the
/// manager of a document is the identity that created it, not the account that
/// registered the collection-level object. So a per-document grant is issued
/// through the owner's own node, which mints a bearer token for that DID and
/// sends the policy command as the owner. A chain-side grant signed by the
/// validator is refused with `actor is not a manager of relation`.
pub async fn grant_document_relation(
    cell: &Cell,
    owner: &ServiceIdentity,
    collection: &str,
    doc_id: &str,
    relation: &str,
    actor_did: &str,
) {
    cell.http
        .acp_relationship(
            RelationshipChange::Add,
            collection,
            doc_id,
            relation,
            actor_did,
            &owner.private_key_hex,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}: grant {} on {} to {} as {}: {}",
                cell.name, relation, doc_id, actor_did, owner.label, e
            )
        });
}

/// Revoke `relation` on one document, as the document's owner.
pub async fn revoke_document_relation(
    cell: &Cell,
    owner: &ServiceIdentity,
    collection: &str,
    doc_id: &str,
    relation: &str,
    actor_did: &str,
) {
    cell.http
        .acp_relationship(
            RelationshipChange::Delete,
            collection,
            doc_id,
            relation,
            actor_did,
            &owner.private_key_hex,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}: revoke {} on {} from {} as {}: {}",
                cell.name, relation, doc_id, actor_did, owner.label, e
            )
        });
}

/// Verify a BLS12-381 signature exactly as a DefraDB peer verifies a block:
/// `blst` min_pk (public key in G1, signature in G2) with the IETF domain tag
/// both implementations declare.
fn bls_verify(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(public_key) = blst::min_pk::PublicKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(signature) = blst::min_pk::Signature::from_bytes(&sig_bytes) else {
        return false;
    };
    signature.verify(true, message, DST, &[], &public_key, true) == blst::BLST_ERROR::BLST_SUCCESS
}

/// Orbis nodes write their Vera account address to `data/public_key.txt`
/// shortly after start; the ring cannot post to the bulletin until funded.
async fn wait_for_orbis_chain_address(node_dir: &Path, index: usize) -> String {
    let pk_path = node_dir.join("data").join("public_key.txt");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(addr) = std::fs::read_to_string(&pk_path) {
            let addr = addr.trim().to_string();
            if !addr.is_empty() {
                return addr;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "orbis node{} did not write {} within 30s",
                index,
                pk_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
