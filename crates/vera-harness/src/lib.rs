pub mod genesis;
pub mod identity;
mod node;

pub use identity::vera_address;
pub use node::VeraNode;

// Keep existing Orbis harness consumers source-compatible.
pub use allocate_vera_ports as allocate_source_hub_ports;
pub use identity::vera_address as source_hub_address;
pub use VeraConfig as SourceHubConfig;
pub use VeraNode as SourceHubNode;
pub use VeraPorts as SourceHubPorts;

/// Connection info for a Vera node.
///
/// A lightweight data carrier that can be passed to DefraDB or Orbis config
/// without coupling to the full `VeraNode` process handle.
#[derive(Clone, Debug)]
pub struct VeraConfig {
    pub lcd_url: String,
    pub comet_rpc_url: String,
    pub grpc_url: String,
    pub chain_id: String,
}

impl From<&VeraNode> for VeraConfig {
    fn from(node: &VeraNode) -> Self {
        Self {
            lcd_url: node.lcd_url.clone(),
            comet_rpc_url: node.comet_rpc_url.clone(),
            grpc_url: node.grpc_url.clone(),
            chain_id: node.chain_id.clone(),
        }
    }
}

/// Ports assigned to a Vera node.
pub struct VeraPorts {
    /// Cosmos LCD/REST API port (default 1317).
    pub lcd: u16,
    /// CometBFT RPC port (default 26657).
    pub comet_rpc: u16,
    /// gRPC port (default 9090).
    pub grpc: u16,
    /// P2P port (default 26656).
    pub p2p: u16,
}

/// Allocate ports for a single Vera instance.
pub fn allocate_vera_ports() -> eyre::Result<VeraPorts> {
    let ports = test_infra::allocate_ports(4)?;
    Ok(VeraPorts {
        lcd: ports[0],
        comet_rpc: ports[1],
        grpc: ports[2],
        p2p: ports[3],
    })
}

/// Resolve the verad binary.
///
/// Uses `BinaryResolver` with the `VERA` prefix. Set `VERA_BINARY`
/// to an explicit path, or ensure `verad` is on PATH.
pub fn resolve_binary() -> eyre::Result<std::path::PathBuf> {
    let resolved = test_infra::BinaryResolver::new("VERA", "verad").resolve()?;
    Ok(resolved.path)
}
