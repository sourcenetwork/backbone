pub(crate) mod genesis;
pub mod identity;
mod node;

pub use identity::source_hub_address;
pub use node::SourceHubNode;

/// Ports assigned to a SourceHub node.
pub struct SourceHubPorts {
    /// Cosmos LCD/REST API port (default 1317).
    pub lcd: u16,
    /// CometBFT RPC port (default 26657).
    pub comet_rpc: u16,
    /// gRPC port (default 9090).
    pub grpc: u16,
    /// P2P port (default 26656).
    pub p2p: u16,
}

/// Allocate ports for a single SourceHub instance.
pub fn allocate_source_hub_ports() -> eyre::Result<SourceHubPorts> {
    let ports = test_infra::allocate_ports(4)?;
    Ok(SourceHubPorts {
        lcd: ports[0],
        comet_rpc: ports[1],
        grpc: ports[2],
        p2p: ports[3],
    })
}

/// Resolve the sourcehubd binary.
///
/// Uses `BinaryResolver` with the `SOURCEHUB` prefix. Set `SOURCEHUB_BINARY`
/// to an explicit path, or ensure `sourcehubd` is on PATH.
pub fn resolve_binary() -> eyre::Result<std::path::PathBuf> {
    let resolved = test_infra::BinaryResolver::new("SOURCEHUB", "sourcehubd").resolve()?;
    Ok(resolved.path)
}
