//! Node-control seam: the same soak driver runs against harness-spawned
//! processes or docker containers on a user network.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use defra_harness::{extract_p2p_addr, DefraClient, StoppedNode, TestCluster};
use eyre::{bail, ensure, Result, WrapErr};
use serde::{Deserialize, Serialize};

use crate::executor::gql;

/// The harness's file-keyring secret (`defra_harness::cluster::builder`).
const KEYRING_SECRET: &str = "integration-test-secret";
const API_PORT: &str = "9181";
const P2P_PORT: &str = "9171";
const STOP_TIMEOUT: &str = "10";
const READY_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Rust,
    Go,
}

impl NodeKind {
    fn harness(self) -> defra_harness::NodeKind {
        match self {
            NodeKind::Rust => defra_harness::NodeKind::Rust,
            NodeKind::Go => defra_harness::NodeKind::Go,
        }
    }

    /// Host-side CLI used to talk to a container of this kind.
    fn host_binary(self) -> Result<PathBuf> {
        Ok(match self {
            NodeKind::Rust => PathBuf::from(
                std::env::var("DEFRA_RUST_BINARY").wrap_err("DEFRA_RUST_BINARY must be set")?,
            ),
            NodeKind::Go => PathBuf::from("defradb"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub name: String,
    pub kind: NodeKind,
    pub store: String,
    /// Partition side, "A" or "B".
    pub host: &'static str,
}

fn spec(name: &str, kind: NodeKind, store: &str, host: &'static str) -> NodeSpec {
    NodeSpec {
        name: name.into(),
        kind,
        store: store.into(),
        host,
    }
}

/// The M2 topology: three nodes per partition side, both runtimes on each.
pub fn m2_specs() -> Vec<NodeSpec> {
    vec![
        spec("rust-0", NodeKind::Rust, "regolith", "A"),
        spec("rust-1", NodeKind::Rust, "regolith", "A"),
        spec("go-0", NodeKind::Go, "badger", "A"),
        spec("rust-2", NodeKind::Rust, "regolith", "B"),
        spec("go-1", NodeKind::Go, "badger", "B"),
        spec("go-2", NodeKind::Go, "badger", "B"),
    ]
}

#[derive(Debug, Clone)]
pub struct Container {
    pub spec: NodeSpec,
    pub image: String,
    /// Host port published to the container's API port.
    pub api_port: u16,
    /// Host directory mounted at `/data`.
    pub rootdir: PathBuf,
    pub ip: Option<String>,
    pub peer_addr: Option<String>,
}

impl Container {
    fn api_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.api_port)
    }
}

/// `docker run` arguments for `c`; the flag order per runtime mirrors the
/// harness builders (`rust_node.rs` / `go_node.rs`).
pub fn docker_run_argv(c: &Container, network: &str, secret: &str) -> Vec<String> {
    let mut v: Vec<String> = [
        "run",
        "-d",
        "--name",
        &format!("{network}-{}", c.spec.name),
        "--network",
        network,
        "-p",
        &format!("127.0.0.1:{}:{API_PORT}", c.api_port),
        "-v",
        &format!("{}:/data", c.rootdir.display()),
        "-e",
        &format!("DEFRA_KEYRING_SECRET={secret}"),
        &c.image,
        "--rootdir",
        "/data",
    ]
    .map(String::from)
    .to_vec();
    let url = ["--url", &format!("0.0.0.0:{API_PORT}")].map(String::from);
    let keyring = ["--keyring-backend", "file", "--keyring-path", "/data/keys"].map(String::from);
    match c.spec.kind {
        NodeKind::Rust => {
            v.extend(url);
            v.push("--no-log-color".into());
            v.extend(keyring);
            v.push("start".into());
        }
        NodeKind::Go => {
            v.push("--no-log-color".into());
            v.extend(keyring);
            v.push("start".into());
            v.extend(url);
        }
    }
    v.extend(
        [
            "--store",
            &c.spec.store,
            "--no-telemetry",
            "--no-encryption",
            "--no-searchable-encryption",
            "--no-signing",
            "--p2paddr",
            &format!("/ip4/0.0.0.0/tcp/{P2P_PORT}"),
        ]
        .map(String::from),
    );
    v
}

/// Bytes from the usage half of a `docker stats` MEM USAGE / LIMIT cell.
pub fn parse_mem_usage(s: &str) -> Option<u64> {
    let used = s.split('/').next()?.trim();
    let digits = used
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(used.len());
    let value: f64 = used[..digits].parse().ok()?;
    let unit: f64 = match used[digits..].trim() {
        "B" => 1.0,
        "kB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * unit) as u64)
}

/// Run one `docker` command and return its stdout. `DOCKER_CONTEXT` is
/// inherited from the environment.
async fn docker(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .wrap_err_with(|| format!("docker {args:?}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    ensure!(out.status.success(), "docker {args:?}: {}", stderr.trim());
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Names of every `soak-*` network on the docker host.
pub async fn existing_networks() -> Result<Vec<String>> {
    let out = docker(&[
        "network",
        "ls",
        "--filter",
        "name=soak-",
        "--format",
        "{{.Name}}",
    ])
    .await?;
    Ok(out.lines().map(String::from).collect())
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct DockerNodes {
    network: String,
    containers: Vec<Container>,
    http: reqwest::Client,
    secret: String,
    /// Unix seconds of the last `dump_logs` per container.
    last_dump: Vec<u64>,
}

impl DockerNodes {
    /// Create the `soak-<run_id>` network, then run and wait for every spec.
    pub async fn start(
        run_id: &str,
        run_dir: &Path,
        specs: Vec<NodeSpec>,
        images: (&str, &str),
    ) -> Result<Self> {
        let network = format!("soak-{run_id}");
        docker(&["network", "create", &network]).await?;
        let mut nodes = Self {
            network,
            containers: Vec::with_capacity(specs.len()),
            http: reqwest::Client::new(),
            secret: KEYRING_SECRET.to_string(),
            last_dump: vec![0; specs.len()],
        };
        let started = async {
            for spec in specs {
                let rootdir = run_dir.join("target").join("docker").join(&spec.name);
                std::fs::create_dir_all(&rootdir)
                    .wrap_err_with(|| format!("creating {}", rootdir.display()))?;
                let image = match spec.kind {
                    NodeKind::Rust => images.0,
                    NodeKind::Go => images.1,
                };
                nodes.containers.push(Container {
                    spec,
                    image: image.to_string(),
                    api_port: free_port()?,
                    rootdir,
                    ip: None,
                    peer_addr: None,
                });
                let i = nodes.containers.len() - 1;
                let argv = docker_run_argv(&nodes.containers[i], &nodes.network, &nodes.secret);
                let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
                docker(&argv).await?;
                nodes.wait_ready(i).await?;
            }
            Ok(())
        }
        .await;
        match started {
            Ok(()) => Ok(nodes),
            Err(e) => {
                nodes.teardown().await.ok();
                Err(e)
            }
        }
    }

    /// Best-effort removal of every container, then the network; the first
    /// error is returned at the end. A container that was never created
    /// (a partial `start`) is not an error.
    async fn teardown(&self) -> Result<()> {
        let mut first_err = None;
        for i in 0..self.containers.len() {
            if let Err(e) = docker(&["rm", "-f", &self.container_name(i)]).await {
                if !e.to_string().contains("No such container") {
                    first_err.get_or_insert(e);
                }
            }
        }
        if let Err(e) = docker(&["network", "rm", &self.network]).await {
            first_err.get_or_insert(e);
        }
        first_err.map_or(Ok(()), Err)
    }

    fn container_name(&self, i: usize) -> String {
        format!("{}-{}", self.network, self.containers[i].spec.name)
    }

    /// Poll the API until it answers, then record the container's addresses.
    async fn wait_ready(&mut self, i: usize) -> Result<()> {
        let url = self.containers[i].api_url();
        let deadline = Instant::now() + READY_TIMEOUT;
        while gql(&self.http, &url, "{ __typename }").await.is_err() {
            ensure!(
                Instant::now() < deadline,
                "{}: API not ready within {READY_TIMEOUT:?}",
                self.container_name(i)
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        self.record_addr(i).await
    }

    /// Record the container's address on the soak network and its libp2p
    /// peer address. The node reports `/ip4/0.0.0.0/...`, so the host part
    /// is the inspected address; it may change after a `rejoin`.
    async fn record_addr(&mut self, i: usize) -> Result<()> {
        let name = self.container_name(i);
        let url = self.containers[i].api_url();
        let ip = docker(&[
            "inspect",
            "-f",
            &format!(
                "{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}",
                self.network
            ),
            &name,
        ])
        .await?
        .trim()
        .to_string();
        ensure!(!ip.is_empty(), "{name}: no address on {}", self.network);
        // After a rejoin the API answers before p2p info does; give it a moment.
        let mut peer_id = None;
        for _ in 0..10 {
            peer_id = crate::churn::peer_id(&self.http, &url).await;
            if peer_id.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let Some(peer_id) = peer_id else {
            bail!("{name}: no peer id from {url}");
        };
        let c = &mut self.containers[i];
        c.peer_addr = Some(format!("/ip4/{ip}/tcp/{P2P_PORT}/p2p/{peer_id}"));
        c.ip = Some(ip);
        Ok(())
    }

    /// Append the container's output since the last dump to
    /// `rootdir/logs/{stdout,stderr}.log`.
    pub async fn dump_logs(&mut self, i: usize) -> Result<()> {
        use std::io::Write;
        let name = self.container_name(i);
        let since = self.last_dump[i].to_string();
        let now = unix_secs();
        let out = tokio::process::Command::new("docker")
            .args(["logs", "--since", &since, &name])
            .output()
            .await
            .wrap_err_with(|| format!("docker logs {name}"))?;
        ensure!(
            out.status.success(),
            "docker logs {name}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        let dir = self.containers[i].rootdir.join("logs");
        std::fs::create_dir_all(&dir)?;
        for (file, bytes) in [("stdout.log", &out.stdout), ("stderr.log", &out.stderr)] {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(file))?
                .write_all(bytes)?;
        }
        self.last_dump[i] = now;
        Ok(())
    }
}

/// One value per run, so the size gap between the variants is moot.
#[allow(clippy::large_enum_variant)]
pub enum Nodes {
    Process {
        cluster: TestCluster,
        stopped: HashMap<usize, StoppedNode>,
    },
    Docker(DockerNodes),
}

impl Nodes {
    pub fn len(&self) -> usize {
        match self {
            Nodes::Process { cluster, .. } => cluster.len(),
            Nodes::Docker(d) => d.containers.len(),
        }
    }

    pub fn name(&self, i: usize) -> &str {
        match self {
            Nodes::Process { cluster, .. } => &cluster.nodes[i].name,
            Nodes::Docker(d) => &d.containers[i].spec.name,
        }
    }

    pub fn api_url(&self, i: usize) -> String {
        match self {
            Nodes::Process { cluster, .. } => cluster.api_url(i).to_string(),
            Nodes::Docker(d) => d.containers[i].api_url(),
        }
    }

    pub fn store(&self, i: usize) -> &str {
        match self {
            Nodes::Process { .. } => crate::STORES[i],
            Nodes::Docker(d) => &d.containers[i].spec.store,
        }
    }

    pub fn rootdir(&self, i: usize) -> PathBuf {
        match self {
            Nodes::Process { cluster, .. } => cluster.nodes[i].rootdir.clone(),
            Nodes::Docker(d) => d.containers[i].rootdir.clone(),
        }
    }

    /// Host pid of the node process; `None` for a container.
    pub fn pid(&self, i: usize) -> Option<u32> {
        match self {
            Nodes::Process { cluster, .. } => cluster.nodes[i].process.id(),
            Nodes::Docker(_) => None,
        }
    }

    /// The container behind node `i`; `None` for a process.
    pub fn container(&self, i: usize) -> Option<&Container> {
        match self {
            Nodes::Process { .. } => None,
            Nodes::Docker(d) => Some(&d.containers[i]),
        }
    }

    /// Resident memory of the node: `ps` for a process, `docker stats` for
    /// a container.
    pub async fn rss_bytes(&self, i: usize) -> Option<u64> {
        match self {
            Nodes::Process { .. } => self.pid(i).and_then(crate::meter::rss_bytes),
            Nodes::Docker(d) => docker(&[
                "stats",
                "--no-stream",
                "--format",
                "{{.MemUsage}}",
                &d.container_name(i),
            ])
            .await
            .ok()
            .and_then(|s| parse_mem_usage(&s)),
        }
    }

    /// Host-side binary per node index, for CLI-only ops.
    pub fn binaries(&self) -> Result<Vec<PathBuf>> {
        match self {
            Nodes::Process { .. } => crate::binaries(),
            Nodes::Docker(d) => d
                .containers
                .iter()
                .map(|c| c.spec.kind.host_binary())
                .collect(),
        }
    }

    pub fn client(&self, i: usize) -> DefraClient {
        match self {
            Nodes::Process { cluster, .. } => cluster.client(i),
            Nodes::Docker(d) => {
                let c = &d.containers[i];
                let bin = c
                    .spec
                    .kind
                    .host_binary()
                    .expect("host binary for the docker client");
                DefraClient::new(
                    bin,
                    format!("127.0.0.1:{}", c.api_port),
                    c.spec.kind.harness(),
                )
            }
        }
    }

    /// The node's dialable libp2p address.
    pub fn p2p_addr(&self, i: usize) -> String {
        match self {
            Nodes::Process { cluster, .. } => extract_p2p_addr(cluster, i),
            Nodes::Docker(d) => d.containers[i]
                .peer_addr
                .clone()
                .expect("peer address is recorded at start"),
        }
    }

    pub fn log_dir(&self, i: usize) -> PathBuf {
        match self {
            Nodes::Process { cluster, .. } => cluster.nodes[i].process.log_dir().to_path_buf(),
            Nodes::Docker(d) => d.containers[i].rootdir.join("logs"),
        }
    }

    /// Flush container output to `log_dir`; the harness already writes
    /// process logs there.
    pub async fn dump_logs(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { .. } => Ok(()),
            Nodes::Docker(d) => d.dump_logs(i).await,
        }
    }

    pub async fn restart(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { cluster, .. } => {
                cluster.restart_node(i, Duration::from_secs(60)).await
            }
            Nodes::Docker(d) => {
                docker(&["restart", "-t", STOP_TIMEOUT, &d.container_name(i)]).await?;
                Ok(())
            }
        }
    }

    pub async fn kill(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { cluster, .. } => {
                cluster.nodes[i].process.kill();
                Ok(())
            }
            Nodes::Docker(d) => {
                docker(&["kill", &d.container_name(i)]).await?;
                Ok(())
            }
        }
    }

    pub async fn respawn(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { cluster, .. } => cluster.nodes[i].process.respawn(),
            Nodes::Docker(d) => {
                docker(&["start", &d.container_name(i)]).await?;
                Ok(())
            }
        }
    }

    pub async fn stop(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { cluster, stopped } => {
                let node = cluster.stop_node(i).await?;
                stopped.insert(i, node);
                Ok(())
            }
            Nodes::Docker(d) => {
                docker(&["stop", "-t", STOP_TIMEOUT, &d.container_name(i)]).await?;
                Ok(())
            }
        }
    }

    pub async fn start_stopped(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { cluster, stopped } => {
                let Some(node) = stopped.remove(&i) else {
                    bail!("node {i} is not stopped");
                };
                cluster
                    .start_stopped_node(node, Duration::from_secs(60))
                    .await
            }
            Nodes::Docker(d) => {
                docker(&["start", &d.container_name(i)]).await?;
                Ok(())
            }
        }
    }

    #[allow(dead_code)] // wired in by the partition churn kind
    pub fn supports_partition(&self) -> bool {
        matches!(self, Nodes::Docker(_))
    }

    /// Cut the node off the soak network. Docker unpublishes the API port
    /// with the network, so the driver cannot reach the node either: from
    /// the driver's side this is a crash-kill whose process keeps running.
    /// The port returns on `rejoin`, which re-reads the container's address.
    #[allow(dead_code)] // wired in by the partition churn kind
    pub async fn partition(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { .. } => bail!("process backend cannot partition"),
            Nodes::Docker(d) => {
                let name = d.container_name(i);
                docker(&["network", "disconnect", &d.network, &name]).await?;
                Ok(())
            }
        }
    }

    #[allow(dead_code)] // wired in by the partition churn kind
    pub async fn rejoin(&mut self, i: usize) -> Result<()> {
        match self {
            Nodes::Process { .. } => bail!("process backend cannot partition"),
            Nodes::Docker(d) => {
                let name = d.container_name(i);
                docker(&["network", "connect", &d.network, &name]).await?;
                d.record_addr(i).await
            }
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        match self {
            Nodes::Process { .. } => Ok(()),
            Nodes::Docker(d) => d.teardown().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_run_argv_shape() {
        let c = Container {
            spec: NodeSpec {
                name: "rust-0".into(),
                kind: NodeKind::Rust,
                store: "regolith".into(),
                host: "A",
            },
            image: "soak-defra:8d8bb299f".into(),
            api_port: 41181,
            rootdir: "/tmp/r0".into(),
            ip: None,
            peer_addr: None,
        };
        let v = docker_run_argv(&c, "soak-test", "s3cret");
        let s = v.join(" ");
        assert!(s.starts_with("run -d --name soak-test-rust-0 --network soak-test -p 127.0.0.1:41181:9181 -v /tmp/r0:/data -e DEFRA_KEYRING_SECRET=s3cret soak-defra:8d8bb299f "));
        assert!(s.contains("--rootdir /data --url 0.0.0.0:9181 --no-log-color --keyring-backend file --keyring-path /data/keys start --store regolith --no-telemetry --no-encryption --no-searchable-encryption --no-signing --p2paddr /ip4/0.0.0.0/tcp/9171"));
        let g = Container {
            spec: NodeSpec {
                name: "go-0".into(),
                kind: NodeKind::Go,
                store: "badger".into(),
                host: "A",
            },
            image: "soak-defradb:53f0e76a3".into(),
            ..c
        };
        assert!(docker_run_argv(&g, "soak-test", "s").join(" ").contains("soak-defradb:53f0e76a3 --rootdir /data --no-log-color --keyring-backend file --keyring-path /data/keys start --url 0.0.0.0:9181 --store badger --no-telemetry --no-encryption --no-searchable-encryption --no-signing --p2paddr /ip4/0.0.0.0/tcp/9171"));
    }

    #[test]
    fn mem_usage_parses_docker_stats() {
        assert_eq!(
            parse_mem_usage("12.5MiB / 7.7GiB"),
            Some((12.5 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(
            parse_mem_usage("1.2GiB / 7.7GiB"),
            Some((1.2 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(parse_mem_usage("900kB / 1GB"), Some(900_000));
        assert_eq!(parse_mem_usage("garbage"), None);
    }

    #[test]
    fn m2_specs_split_hosts() {
        let s = m2_specs();
        assert_eq!(s.len(), 6);
        assert_eq!(s.iter().filter(|n| n.host == "A").count(), 3);
        assert_eq!(
            s.iter()
                .filter(|n| matches!(n.kind, NodeKind::Rust))
                .count(),
            3
        );
        assert_eq!(
            s.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["rust-0", "rust-1", "go-0", "rust-2", "go-1", "go-2"]
        );
    }
}
