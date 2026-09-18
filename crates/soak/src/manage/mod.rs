//! `soak manage`: pass/fail cases on the P2P management channel, on a
//! NAC-enabled Rust mesh. The caller POSTs to a relay node's HTTP API and
//! that node relays a signed request over P2P to the target.

pub mod actors;
pub mod authz;
pub mod cases;
pub mod client;
pub mod report;
pub mod routing;
pub mod state;

use std::path::Path;

use eyre::{ensure, eyre, Result, WrapErr};
use futures::future::LocalBoxFuture;
use serde_json::{json, Value};

use crate::nodes::Nodes;
use crate::{flag, has_flag, start_nodes, RunArgs, Topology};
use actors::{Actor, Actors};
use cases::{Channel, OpRecord, Verb};

const SCHEMA: &str = "type User { name: String age: Int }";

pub async fn run(out: &Path, a: RunArgs) -> Result<()> {
    let topology = a
        .topology
        .ok_or_else(|| eyre!("manage needs --topology <n>r<m>g"))?;
    ensure!(topology.rust >= 2, "manage needs at least two Rust nodes");
    ensure!(topology.go == 0, "manage: Go nodes in the mesh are step 3");
    ensure!(
        !a.docker && !has_flag("docker"),
        "manage --docker: unsupported yet"
    );
    let table = cases::all();
    let selected = cases::select(&table, flag("cases").as_deref())?;
    let mut nodes = start_nodes(out, &a).await?;
    let result = drive(out, topology, &mut nodes, &selected).await;
    let shutdown = nodes.shutdown().await;
    result?;
    shutdown
}

async fn drive(
    out: &Path,
    topology: Topology,
    nodes: &mut Nodes,
    selected: &[&cases::Case],
) -> Result<()> {
    let owner = match &*nodes {
        Nodes::Process { cluster, .. } => cluster.startup_identity(),
        Nodes::Docker(_) => None,
    }
    .ok_or_else(|| eyre!("NAC cluster has no startup identity"))?
    .to_string();
    let n = nodes.len();
    let mut addrs = Vec::new();
    for i in 0..n {
        let info = nodes
            .client(i)
            .p2p_info_with_identity(&owner)
            .wrap_err_with(|| format!("p2p info on {}", nodes.name(i)))?;
        let addr = info[0]
            .as_str()
            .ok_or_else(|| eyre!("{} has no P2P address: {info}", nodes.name(i)))?;
        addrs.push(addr.to_string());
    }
    let peer_ids: Vec<String> = addrs
        .iter()
        .map(|a| a.rsplit("/p2p/").next().unwrap_or(a).to_string())
        .collect();
    for (i, pid) in peer_ids.iter().enumerate() {
        println!("{} at {} peer id {pid}", nodes.name(i), nodes.api_url(i));
    }
    wire_mesh(nodes, &owner, &addrs)?;
    let actors = Actors::generate(&nodes.binaries()?[0])?;
    for i in 0..n {
        actors.grant_on(nodes, i, &owner)?;
    }
    println!(
        "actors: admin {} operator {} ({}) outsider {}",
        actors.admin.did,
        actors.operator.did,
        actors::OPERATOR_GRANTS.join(","),
        actors.outsider.did
    );
    let manifest = json!({
        "arm": "manage",
        "topology": topology.label(),
        "nodes": (0..n).map(|i| json!({
            "name": nodes.name(i), "api_url": nodes.api_url(i), "p2p_addr": addrs[i], "peer_id": peer_ids[i],
        })).collect::<Vec<_>>(),
        "owner_key_hex": owner,
        "actors": actors,
        "rust_binary": std::env::var("DEFRA_RUST_BINARY").unwrap_or_default(),
        "cases": selected.iter().map(|c| c.name).collect::<Vec<_>>(),
    });
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    let mut live = Live {
        http: crate::executor::http_client(std::time::Duration::from_secs(60)),
        urls: (0..n).map(|i| nodes.api_url(i)).collect(),
        nodes,
        addrs,
        peer_ids,
        courier: owner,
        actors,
        records: Vec::new(),
    };
    let reports = cases::run_all(&mut live, selected, topology.rust).await;
    report::write(out, &topology.label(), &reports)?;
    println!("report: {}", out.join("cases.md").display());
    Ok(())
}

/// Schema, peer connections and a replicator per ordered pair, every verb
/// as the NAC owner. No collection subscribe: replicators are the only
/// delivery path, and `CollectionAdd` stays a clean toggle for the cases.
fn wire_mesh(nodes: &Nodes, owner: &str, addrs: &[String]) -> Result<()> {
    let n = nodes.len();
    for i in 0..n {
        let name = nodes.name(i);
        let client = nodes.client(i);
        client
            .schema_add_with_identity(SCHEMA, owner)
            .wrap_err_with(|| format!("schema on {name}"))?;
        let others: Vec<&str> = (0..n)
            .filter(|j| *j != i)
            .map(|j| addrs[j].as_str())
            .collect();
        client
            .p2p_connect_with_identity(&others, owner)
            .wrap_err_with(|| format!("connect from {name}"))?;
        for j in &others {
            client
                .p2p_replicator_set_with_identity(&[cases::COLLECTION], j, owner)
                .wrap_err_with(|| format!("replicator {name} -> {j}"))?;
        }
    }
    Ok(())
}

/// The real channel: actors' tokens, the relay's HTTP API, one record per
/// request. After a mutate it reads the target's list for that op's
/// family as admin, so the report shows the state every op left behind.
/// Verbs go to the harness.
struct Live<'n> {
    nodes: &'n mut Nodes,
    http: reqwest::Client,
    urls: Vec<String>,
    addrs: Vec<String>,
    peer_ids: Vec<String>,
    courier: String,
    actors: Actors,
    records: Vec<OpRecord>,
}

fn family_list(kind: &str) -> Option<&'static str> {
    ["Replicator", "Collection", "Document"]
        .into_iter()
        .find(|f| kind.starts_with(f))
        .map(|f| match f {
            "Replicator" => "ReplicatorList",
            "Collection" => "CollectionList",
            _ => "DocumentList",
        })
}

impl Live<'_> {
    async fn post(
        &mut self,
        relay: usize,
        target: usize,
        audience: usize,
        actor: Actor,
        op: &Value,
    ) -> Result<client::Reply> {
        let token = self.actors.token(actor, &self.peer_ids[audience])?;
        client::post(
            &self.http,
            &self.urls[relay],
            &self.courier,
            &self.addrs[target],
            &token,
            op,
        )
        .await
    }
}

impl Channel for Live<'_> {
    fn len(&self) -> usize {
        self.urls.len()
    }

    fn addr(&self, node: usize) -> String {
        self.addrs[node].clone()
    }

    fn peer_id(&self, node: usize) -> String {
        self.peer_ids[node].clone()
    }

    fn send_for<'a>(
        &'a mut self,
        relay: usize,
        target: usize,
        audience: usize,
        actor: Actor,
        op: Value,
    ) -> LocalBoxFuture<'a, Result<client::Reply>> {
        Box::pin(async move {
            let kind = op["Kind"].as_str().unwrap_or_default().to_string();
            let reply = self.post(relay, target, audience, actor, &op).await?;
            let target_state = match family_list(&kind).filter(|_| !client::is_query(&op)) {
                Some(list) => Some(
                    match self
                        .post(
                            relay,
                            target,
                            target,
                            Actor::Admin,
                            &json!({ "Kind": list }),
                        )
                        .await
                    {
                        Ok(r) => r.body,
                        Err(e) => json!({ "error": format!("{e:#}") }),
                    },
                ),
                None => None,
            };
            self.records.push(OpRecord {
                relay,
                target,
                actor,
                kind,
                status: reply.status,
                latency_ms: reply.latency_ms,
                target_state,
            });
            Ok(reply)
        })
    }

    fn control<'a>(&'a mut self, verb: Verb) -> LocalBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            match verb {
                Verb::Stop(i) => self.nodes.stop(i).await,
                Verb::Start(i) => self.nodes.start_stopped(i).await,
            }
        })
    }

    fn take_records(&mut self) -> Vec<OpRecord> {
        std::mem::take(&mut self.records)
    }
}
