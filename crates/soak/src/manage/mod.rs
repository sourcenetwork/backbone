//! `soak manage`: pass/fail cases on the P2P management channel, on a
//! NAC-enabled Rust mesh. The caller POSTs to a relay node's HTTP API and
//! that node relays a signed request over P2P to the target.

pub mod actors;
pub mod authz;
pub mod bounds;
pub mod cases;
pub mod client;
pub mod data;
pub mod partition;
pub mod report;
pub mod routing;
pub mod state;

use std::cell::RefCell;
use std::path::Path;

use eyre::{ensure, eyre, Result, WrapErr};
use futures::future::{BoxFuture, LocalBoxFuture};
use serde_json::{json, Value};

use crate::auth::auth_token;
use crate::nodes::{NodeKind, Nodes};
use crate::{flag, has_flag, start_nodes, RunArgs, Topology, Transport};
use actors::{Actor, Actors};
use cases::{Channel, OpRecord, Verb};

/// `age` is immutable so a replication filter may use it (S3). Go has no
/// `@immutable`; the directive does not enter the collection id, so a Go
/// node takes the plain form and shares the collection.
const SCHEMA: &str = "type User { name: String age: Int @immutable }";
const GO_SCHEMA: &str = "type User { name: String age: Int }";

/// Past this many doc refs a mutate's after-state is not report material
/// (the bounds cases send hundreds of thousands).
const STATE_READ_MAX_DOCS: usize = 100;

pub async fn run(out: &Path, a: RunArgs) -> Result<()> {
    let topology = a
        .topology
        .ok_or_else(|| eyre!("manage needs --topology <n>r<m>g"))?;
    accept(topology, a.transport)?;
    ensure!(
        !a.docker && !has_flag("docker"),
        "manage --docker: unsupported yet"
    );
    let table = cases::all();
    let mut selected = cases::select(&table, flag("cases").as_deref())?;
    if has_flag("locate-size-bound") && !selected.iter().any(|c| c.name == "B3") {
        selected.extend(table.iter().filter(|c| c.name == "B3"));
    }
    let mut nodes = start_nodes(out, &a).await?;
    let result = drive(out, topology, a.transport, &mut nodes, &selected).await;
    let shutdown = nodes.shutdown().await;
    result?;
    shutdown
}

/// Every manage target is Rust; Go nodes are replication peers only, and
/// only over libp2p, the one transport Go speaks.
fn accept(topology: Topology, transport: Transport) -> Result<()> {
    ensure!(topology.rust >= 2, "manage needs at least two Rust nodes");
    ensure!(
        topology.go == 0 || transport == Transport::Libp2p,
        "manage --transport iroh: Go nodes cannot speak iroh; use --topology {}r0g",
        topology.rust
    );
    Ok(())
}

async fn drive(
    out: &Path,
    topology: Topology,
    transport: Transport,
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
    let peer_ids: Vec<String> = addrs.iter().map(|a| peer_id_of(a).to_string()).collect();
    for (i, pid) in peer_ids.iter().enumerate() {
        println!("{} at {} peer id {pid}", nodes.name(i), nodes.api_url(i));
    }
    wire_mesh(nodes, &owner, &addrs)?;
    let actors = Actors::generate(&nodes.binaries()?[0])?;
    for i in 0..topology.rust {
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
        "transport": transport.label(),
        "nodes": (0..n).map(|i| json!({
            "name": nodes.name(i), "runtime": nodes.kind(i), "api_url": nodes.api_url(i),
            "p2p_addr": addrs[i], "peer_id": peer_ids[i],
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
        rust: topology.rust,
        transport,
        addrs,
        peer_ids,
        courier: owner,
        actors,
        records: RefCell::default(),
        notes: Vec::new(),
    };
    let reports = cases::run_all(&mut live, selected, topology.rust).await;
    report::write(out, &topology.label(), transport.label(), &reports)?;
    println!("report: {}", out.join("cases.md").display());
    Ok(())
}

/// The peer id `/p2p/info` reports: the multiaddr's last `/p2p/` segment
/// under libp2p, the endpoint id after `host:port/p2p/` under iroh.
fn peer_id_of(addr: &str) -> &str {
    addr.rsplit("/p2p/").next().unwrap_or(addr)
}

/// Schema, peer connections and a replicator per ordered pair, Go nodes
/// included, every verb as the NAC owner. No collection subscribe:
/// replicators are the only delivery path, `CollectionAdd` stays a clean
/// toggle for the cases, and a Go node forwards only what a replicator
/// gave it.
fn wire_mesh(nodes: &Nodes, owner: &str, addrs: &[String]) -> Result<()> {
    let n = nodes.len();
    for i in 0..n {
        let name = nodes.name(i);
        let client = nodes.client(i);
        let schema = match nodes.kind(i) {
            NodeKind::Rust => SCHEMA,
            NodeKind::Go => GO_SCHEMA,
        };
        client
            .schema_add_with_identity(schema, owner)
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
/// Verbs go to the harness, except the NAC toggle, which is the node's own
/// `/acp/node/{disable,re-enable}` route as the owner.
struct Live<'n> {
    nodes: &'n mut Nodes,
    /// Nodes `0..rust` are Rust, the rest Go.
    rust: usize,
    transport: Transport,
    http: reqwest::Client,
    urls: Vec<String>,
    addrs: Vec<String>,
    peer_ids: Vec<String>,
    courier: String,
    actors: Actors,
    records: RefCell<Vec<OpRecord>>,
    notes: Vec<String>,
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
    fn pid(&self, node: usize) -> Result<u32> {
        self.nodes
            .pid(node)
            .ok_or_else(|| eyre!("{}: no process to signal", self.nodes.name(node)))
    }

    /// POST to `node`'s own `/api/v0/{route}` as the owner.
    async fn post_own(&self, node: usize, route: &str, body: Option<&Value>) -> Result<()> {
        let url = &self.urls[node];
        let mut req = self
            .http
            .post(format!("{url}/api/v0/{route}"))
            .bearer_auth(auth_token(&self.courier, url)?);
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req
            .send()
            .await
            .wrap_err_with(|| format!("{route} at {url}"))?;
        let status = resp.status();
        ensure!(
            status.is_success(),
            "{route} at {url}: {status} {}",
            resp.text().await.unwrap_or_default()
        );
        Ok(())
    }

    async fn post(
        &self,
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
        self.rust
    }

    fn go_nodes(&self) -> Vec<usize> {
        (self.rust..self.urls.len()).collect()
    }

    fn transport(&self) -> Transport {
        self.transport
    }

    fn addr(&self, node: usize) -> String {
        self.addrs[node].clone()
    }

    fn peer_id(&self, node: usize) -> String {
        self.peer_ids[node].clone()
    }

    fn send_for<'a>(
        &'a self,
        relay: usize,
        target: usize,
        audience: usize,
        actor: Actor,
        op: Value,
    ) -> LocalBoxFuture<'a, Result<client::Reply>> {
        Box::pin(async move {
            let kind = op["Kind"].as_str().unwrap_or_default().to_string();
            let reply = self.post(relay, target, audience, actor, &op).await?;
            let small = op["docs"].as_array().map_or(0, Vec::len) <= STATE_READ_MAX_DOCS;
            let target_state = match family_list(&kind).filter(|_| !client::is_query(&op) && small)
            {
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
            self.records.borrow_mut().push(OpRecord {
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
                Verb::Regrant(i) => self.actors.grant_on(self.nodes, i, &self.courier),
                Verb::Grant {
                    node,
                    actor,
                    relation,
                } => self
                    .nodes
                    .client(node)
                    .acp_node_relationship_add(
                        relation,
                        &self.actors.identity(actor).did,
                        &self.courier,
                    )
                    .map(drop),
                Verb::Revoke {
                    node,
                    actor,
                    relation,
                } => self
                    .nodes
                    .client(node)
                    .acp_node_relationship_delete(
                        relation,
                        &self.actors.identity(actor).did,
                        &self.courier,
                    )
                    .map(drop),
                Verb::Nac { node, on } => {
                    let route = if on { "re-enable" } else { "disable" };
                    self.post_own(node, &format!("acp/node/{route}"), None)
                        .await
                }
                Verb::Partition(i) => self.nodes.partition(i).await,
                Verb::Rejoin(i) => self.nodes.rejoin(i).await,
                Verb::PauseAfter { node, delay_ms } => {
                    let pid = self.pid(node)?;
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        if let Err(e) = crate::nodes::signal(pid, "-STOP") {
                            eprintln!("pause of pid {pid}: {e:#}");
                        }
                    });
                    Ok(())
                }
                Verb::Resume(i) => crate::nodes::signal(self.pid(i)?, "-CONT"),
                Verb::LocalReplicatorAdd {
                    node,
                    peer,
                    filters,
                } => {
                    let body = json!({
                        "Collections": [cases::COLLECTION],
                        "Addresses": [self.addrs[peer]],
                        "Filters": filters,
                    });
                    self.post_own(node, "p2p/replicators", Some(&body)).await
                }
            }
        })
    }

    fn gql(&self, node: usize, query: String) -> BoxFuture<'static, Result<Value>> {
        let http = self.http.clone();
        let url = self.urls[node].clone();
        let token = auth_token(&self.courier, &url);
        Box::pin(async move {
            crate::executor::gql_as(&http, &url, &query, Some(&token?))
                .await
                .map_err(|e| eyre!("{e} at {url}"))
        })
    }

    fn replicators(&self, node: usize) -> Result<Value> {
        self.nodes
            .client(node)
            .p2p_replicator_list_with_identity(&self.courier)
            .wrap_err_with(|| format!("replicator list on {}", self.nodes.name(node)))
    }

    fn can_partition(&self) -> bool {
        self.nodes.supports_partition()
    }

    fn note(&mut self, text: String) {
        self.notes.push(text);
    }

    fn take_records(&mut self) -> Vec<OpRecord> {
        self.records.take()
    }

    fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_nodes_join_on_libp2p_only() {
        let t = |rust, go| Topology { rust, go };
        assert!(accept(t(2, 0), Transport::Libp2p).is_ok());
        assert!(accept(t(2, 2), Transport::Libp2p).is_ok());
        assert!(accept(t(3, 0), Transport::Iroh).is_ok());
        let refused = accept(t(2, 2), Transport::Iroh).unwrap_err().to_string();
        assert!(refused.contains("Go nodes cannot speak iroh"), "{refused}");
        assert!(accept(t(1, 2), Transport::Libp2p).is_err());
    }

    #[test]
    fn peer_id_of_reads_the_libp2p_and_iroh_address_forms() {
        assert_eq!(
            peer_id_of("/ip4/127.0.0.1/tcp/9171/p2p/12D3KooWabc"),
            "12D3KooWabc"
        );
        assert_eq!(peer_id_of("127.0.0.1:9171/p2p/1a2b3c"), "1a2b3c");
        assert_eq!(peer_id_of("1a2b3c"), "1a2b3c");
    }
}
