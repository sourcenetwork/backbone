use std::net::TcpListener;

use eyre::{Result, WrapErr};

/// Ports assigned to a single node, with guard listeners held until release.
///
/// The guards keep the ports reserved until `release()` is called. This
/// prevents other parallel tests from grabbing the same port between
/// allocation and node startup.
pub struct NodePorts {
    pub http: u16,
    pub p2p: u16,
    guards: Option<Vec<TcpListener>>,
}

impl NodePorts {
    /// Release the port guards. Call immediately before spawning the node
    /// process so the ports are free for it to bind.
    pub fn release(&mut self) {
        self.guards = None;
    }
}

/// Allocate port pairs (http, p2p) for `n` nodes, holding guard listeners.
pub fn allocate_node_ports(n: usize) -> Result<Vec<NodePorts>> {
    let count = n * 2;
    let listeners: Vec<TcpListener> = (0..count)
        .map(|i| {
            TcpListener::bind("127.0.0.1:0")
                .wrap_err_with(|| format!("failed to bind ephemeral port {}/{}", i + 1, count))
        })
        .collect::<Result<_>>()?;

    let mut result = Vec::with_capacity(n);
    let mut iter = listeners.into_iter();
    for _ in 0..n {
        let l1 = iter.next().unwrap();
        let l2 = iter.next().unwrap();
        let http = l1.local_addr()?.port();
        let p2p = l2.local_addr()?.port();
        result.push(NodePorts {
            http,
            p2p,
            guards: Some(vec![l1, l2]),
        });
    }

    Ok(result)
}
