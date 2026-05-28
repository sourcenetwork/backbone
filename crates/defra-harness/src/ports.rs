use std::net::{TcpListener, UdpSocket};

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

/// Ports for a single node running multiple libp2p transports
/// (TCP, QUIC over UDP, WebSocket over TCP) plus the HTTP API.
///
/// All four ports are reserved with bind-hold-release guards until
/// `release()` is called. Call `release()` immediately before spawning
/// the node so the child process can bind them.
pub struct TransportNodePorts {
    pub http: u16,
    pub tcp: u16,
    pub quic: u16,
    pub ws: u16,
    tcp_guards: Option<Vec<TcpListener>>,
    udp_guard: Option<UdpSocket>,
}

impl TransportNodePorts {
    /// Release all port guards. Call right before spawning the node.
    pub fn release(&mut self) {
        self.tcp_guards = None;
        self.udp_guard = None;
    }

    /// Multiaddr list for libp2p: TCP + QUIC + WebSocket, comma-separated.
    pub fn p2p_addr_arg(&self) -> String {
        format!(
            "/ip4/127.0.0.1/tcp/{},/ip4/127.0.0.1/udp/{}/quic-v1,/ip4/127.0.0.1/tcp/{}/ws",
            self.tcp, self.quic, self.ws
        )
    }

    /// QUIC-only multiaddr, useful for dialing tests that target a
    /// single transport.
    pub fn quic_p2p_addr_arg(&self) -> String {
        format!("/ip4/127.0.0.1/udp/{}/quic-v1", self.quic)
    }
}

/// Allocate transport-port quads for `n` nodes.
///
/// Binds all guard listeners (3 TCP + 1 UDP per node) before reading
/// any local addresses, preventing parallel callers from getting the
/// same port.
pub fn allocate_transport_ports(n: usize) -> Result<Vec<TransportNodePorts>> {
    let mut tcp_listeners: Vec<TcpListener> = Vec::with_capacity(n * 3);
    let mut udp_sockets: Vec<UdpSocket> = Vec::with_capacity(n);

    for i in 0..n {
        for kind in ["http", "tcp", "ws"] {
            tcp_listeners.push(
                TcpListener::bind("127.0.0.1:0")
                    .wrap_err_with(|| format!("failed to bind {} guard for node {}", kind, i))?,
            );
        }
        udp_sockets.push(
            UdpSocket::bind("127.0.0.1:0")
                .wrap_err_with(|| format!("failed to bind quic guard for node {}", i))?,
        );
    }

    let mut result = Vec::with_capacity(n);
    let mut tcp_iter = tcp_listeners.into_iter();
    let mut udp_iter = udp_sockets.into_iter();
    for _ in 0..n {
        let http_guard = tcp_iter.next().unwrap();
        let tcp_guard = tcp_iter.next().unwrap();
        let ws_guard = tcp_iter.next().unwrap();
        let udp_guard = udp_iter.next().unwrap();
        let http = http_guard.local_addr()?.port();
        let tcp = tcp_guard.local_addr()?.port();
        let ws = ws_guard.local_addr()?.port();
        let quic = udp_guard.local_addr()?.port();
        result.push(TransportNodePorts {
            http,
            tcp,
            quic,
            ws,
            tcp_guards: Some(vec![http_guard, tcp_guard, ws_guard]),
            udp_guard: Some(udp_guard),
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn allocate_transport_ports_returns_unique_ports() {
        let ports = allocate_transport_ports(2).expect("allocate");
        assert_eq!(ports.len(), 2);

        let mut tcp_seen: HashSet<u16> = HashSet::new();
        let mut udp_seen: HashSet<u16> = HashSet::new();
        for p in &ports {
            assert!(tcp_seen.insert(p.http), "duplicate http port {}", p.http);
            assert!(tcp_seen.insert(p.tcp), "duplicate tcp port {}", p.tcp);
            assert!(tcp_seen.insert(p.ws), "duplicate ws port {}", p.ws);
            assert!(udp_seen.insert(p.quic), "duplicate quic port {}", p.quic);
        }
        assert_eq!(tcp_seen.len(), 6, "expected 6 unique TCP ports for n=2");
        assert_eq!(udp_seen.len(), 2, "expected 2 unique UDP ports for n=2");
    }

    #[test]
    fn release_frees_ports_for_rebinding() {
        let mut p = allocate_transport_ports(1)
            .expect("allocate")
            .pop()
            .unwrap();
        let (http, tcp, ws, quic) = (p.http, p.tcp, p.ws, p.quic);
        p.release();

        // Tiny TOCTOU window: between release() and the binds below, another
        // process on the host could grab one of these ephemeral ports.
        // In practice the window is microseconds and the test asserts the
        // *behavior* of release() (the OS actually freeing the fds) which
        // can only be verified by rebinding.
        TcpListener::bind(("127.0.0.1", http)).expect("rebind http");
        TcpListener::bind(("127.0.0.1", tcp)).expect("rebind tcp");
        TcpListener::bind(("127.0.0.1", ws)).expect("rebind ws");
        UdpSocket::bind(("127.0.0.1", quic)).expect("rebind quic");
    }

    #[test]
    fn p2p_addr_arg_lists_all_three_transports() {
        let p = TransportNodePorts {
            http: 1,
            tcp: 2,
            quic: 3,
            ws: 4,
            tcp_guards: None,
            udp_guard: None,
        };
        assert_eq!(
            p.p2p_addr_arg(),
            "/ip4/127.0.0.1/tcp/2,/ip4/127.0.0.1/udp/3/quic-v1,/ip4/127.0.0.1/tcp/4/ws"
        );
        assert_eq!(p.quic_p2p_addr_arg(), "/ip4/127.0.0.1/udp/3/quic-v1");
    }
}
