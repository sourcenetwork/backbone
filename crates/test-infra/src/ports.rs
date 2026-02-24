use std::net::TcpListener;

use anyhow::{Context, Result};

/// Allocate `n` unique ephemeral ports using bind-hold-release.
///
/// Binds all ports simultaneously before releasing any, preventing
/// two calls from getting the same port.
pub fn allocate_ports(n: usize) -> Result<Vec<u16>> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|i| {
            TcpListener::bind("127.0.0.1:0")
                .with_context(|| format!("failed to bind ephemeral port {}/{}", i + 1, n))
        })
        .collect::<Result<_>>()?;

    let ports = listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()))
        .collect::<std::io::Result<Vec<u16>>>()
        .context("failed to get local address")?;

    // All listeners drop here, releasing ports simultaneously
    Ok(ports)
}
