pub mod identity;
mod node;

pub use node::{DefraDbNode, OrbisSignerConfig, SourceHubConfig};

/// Ports assigned to a DefraDB node.
pub struct DefraDbPorts {
    /// HTTP API port (default 9181). Serves GraphQL, REST, and health checks.
    pub http: u16,
    /// P2P port (default 9171). libp2p for node-to-node sync.
    pub p2p: u16,
}

/// Allocate ports for a single DefraDB instance.
pub fn allocate_defra_ports() -> eyre::Result<DefraDbPorts> {
    let ports = test_infra::allocate_ports(2)?;
    Ok(DefraDbPorts {
        http: ports[0],
        p2p: ports[1],
    })
}

/// Resolve the defra binary.
///
/// Uses `BinaryResolver` with the `DEFRA` prefix. Set `DEFRA_BINARY`
/// to an explicit path, or ensure `defra` is on PATH.
pub fn resolve_binary() -> eyre::Result<std::path::PathBuf> {
    let resolved = test_infra::BinaryResolver::new("DEFRA", "defra")
        .cargo_package("cli")
        .resolve()?;
    Ok(resolved.path)
}
