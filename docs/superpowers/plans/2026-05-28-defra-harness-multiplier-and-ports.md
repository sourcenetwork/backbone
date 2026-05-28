# defra-harness: signed-docs multiplier and transport port helper — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `TransportNodePorts` + `allocate_transport_ports` to `defra-harness::ports`, and add a `DEFRA_MULTIPLIERS=signed-docs` hook with per-test opt-out to `TestClusterBuilder`. Unblocks defradb.rs #978 and #949.

**Architecture:** Two files change in `crates/defra-harness/src/`: `ports.rs` gains a sibling struct + allocator for tests that need TCP+QUIC+WS listeners; `cluster/builder.rs` gains a pure env helper, a builder field/method, and a 3-line branch in `build()`. No `lib.rs` re-exports needed (consumers already use `defra_harness::ports::*`).

**Tech Stack:** Rust, `std::net::{TcpListener, UdpSocket}`, `eyre` for error handling.

**Spec:** `docs/superpowers/specs/2026-05-28-defra-harness-multiplier-and-ports-design.md`

---

## File Structure

- **Modify** `crates/defra-harness/src/ports.rs` — append `TransportNodePorts` struct, `allocate_transport_ports(n)` fn, and a `#[cfg(test)] mod tests` block. Existing `NodePorts` + `allocate_node_ports` are untouched.
- **Modify** `crates/defra-harness/src/cluster/builder.rs` — add a module-level `signed_docs_multiplier_active()` + private pure helper `signed_docs_in(env: Option<&str>)`, add `signing_multiplier_opt_out: bool` field, init it in `new()`, add `.no_signing_multiplier()` method, add 3-line branch in `build()` before port allocation, add `#[cfg(test)] mod tests` for the pure helper and the setter.

No new files. No public API removals or signature changes.

---

## Task 1: Add `TransportNodePorts` and `allocate_transport_ports` to `ports.rs`

**Files:**
- Modify: `crates/defra-harness/src/ports.rs` (append after line 49)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Append to `crates/defra-harness/src/ports.rs`:

```rust
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
        let mut ports = allocate_transport_ports(1).expect("allocate");
        let p = ports.pop().unwrap();
        let http = p.http;
        let tcp = p.tcp;
        let ws = p.ws;
        let quic = p.quic;
        let mut p = p;
        p.release();

        // After release, each port should be rebind-able.
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p defra-harness --lib ports::tests`
Expected: FAIL with compile errors — `TransportNodePorts`, `allocate_transport_ports`, `p2p_addr_arg`, `quic_p2p_addr_arg`, `release` all undefined.

- [ ] **Step 3: Implement the struct and allocator**

First, change the existing import at line 1 of `crates/defra-harness/src/ports.rs`:

```rust
use std::net::TcpListener;
```

to:

```rust
use std::net::{TcpListener, UdpSocket};
```

Then append the implementation to the same file (after the existing `allocate_node_ports` function, before the `#[cfg(test)] mod tests` block from Step 1):

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p defra-harness --lib ports::tests`
Expected: PASS — 3 tests pass.

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy -p defra-harness --all-targets -- -D warnings && cargo fmt --all`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/defra-harness/src/ports.rs
git commit -m "$(cat <<'EOF'
feat(harness): add TransportNodePorts for QUIC/WS p2p tests

Adds allocate_transport_ports(n) and a TransportNodePorts struct that
reserves HTTP + TCP + QUIC (UDP) + WS (TCP) listeners with the same
bind-hold-release pattern as allocate_node_ports.

Unblocks defradb.rs #949.
EOF
)"
```

---

## Task 2: Add `signed_docs_multiplier_active` env helper to `builder.rs`

**Files:**
- Modify: `crates/defra-harness/src/cluster/builder.rs` (insert helper near top, add tests at bottom)

- [ ] **Step 1: Write the failing tests**

Append to `crates/defra-harness/src/cluster/builder.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_docs_in_handles_all_cases() {
        assert!(!signed_docs_in(None), "unset → false");
        assert!(!signed_docs_in(Some("")), "empty → false");
        assert!(signed_docs_in(Some("signed-docs")), "exact → true");
        assert!(signed_docs_in(Some(" signed-docs ")), "padded → true");
        assert!(signed_docs_in(Some("signed-docs,foo")), "first of list → true");
        assert!(signed_docs_in(Some("foo,signed-docs")), "second of list → true");
        assert!(signed_docs_in(Some("foo, signed-docs ,bar")), "padded middle → true");
        assert!(!signed_docs_in(Some("foo")), "other only → false");
        assert!(!signed_docs_in(Some("foo,bar")), "no match → false");
        assert!(!signed_docs_in(Some("SIGNED-DOCS")), "case-sensitive → false");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p defra-harness --lib cluster::builder::tests`
Expected: FAIL with compile error — `signed_docs_in` undefined.

- [ ] **Step 3: Implement the helpers**

Insert in `crates/defra-harness/src/cluster/builder.rs` after the `OnceLock` statics (after line 17):

```rust
/// Returns true if `DEFRA_MULTIPLIERS` is set and contains `signed-docs`.
///
/// `DEFRA_MULTIPLIERS` is a comma-separated list of test multipliers.
/// Only `signed-docs` is honored today; unknown entries are ignored
/// (forward-compatible with future multipliers).
fn signed_docs_multiplier_active() -> bool {
    signed_docs_in(std::env::var("DEFRA_MULTIPLIERS").ok().as_deref())
}

/// Pure form of `signed_docs_multiplier_active` for testability —
/// no env access, just parses the value.
fn signed_docs_in(value: Option<&str>) -> bool {
    value
        .map(|v| v.split(',').any(|s| s.trim() == "signed-docs"))
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p defra-harness --lib cluster::builder::tests`
Expected: PASS.

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy -p defra-harness --all-targets -- -D warnings && cargo fmt --all`
Expected: clean. Note: `signed_docs_multiplier_active` is currently unused — clippy may warn. If so, allow the warning for this task with `#[allow(dead_code)]` on the function; Task 3 will use it and the allow can be removed then. If clippy is silent (function isn't pub), proceed.

- [ ] **Step 6: Commit**

```bash
git add crates/defra-harness/src/cluster/builder.rs
git commit -m "$(cat <<'EOF'
feat(harness): add DEFRA_MULTIPLIERS env helper

Adds signed_docs_multiplier_active() and a pure helper signed_docs_in()
for parsing the comma-separated DEFRA_MULTIPLIERS env var. Wiring into
TestClusterBuilder lands in the next commit.

Refs defradb.rs #978.
EOF
)"
```

---

## Task 3: Wire `.no_signing_multiplier()` into `TestClusterBuilder` and `build()`

**Files:**
- Modify: `crates/defra-harness/src/cluster/builder.rs`:
  - struct field at line ~42 (after `acp_receipt_timeout`)
  - init at line ~76 (after `acp_receipt_timeout: None,`)
  - method after `with_signing()` at line ~150
  - branch in `build()` immediately before `let mut all_ports = allocate_node_ports(total)?;` at line ~294
  - test in existing `mod tests`

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` in `crates/defra-harness/src/cluster/builder.rs`:

```rust
#[test]
fn no_signing_multiplier_sets_opt_out_flag() {
    let b = TestClusterBuilder::new();
    assert!(!b.signing_multiplier_opt_out, "default is opt-in");

    let b = TestClusterBuilder::new().no_signing_multiplier();
    assert!(b.signing_multiplier_opt_out, "after call, opt-out is true");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p defra-harness --lib cluster::builder::tests::no_signing_multiplier_sets_opt_out_flag`
Expected: FAIL with compile error — `signing_multiplier_opt_out` field and `no_signing_multiplier` method undefined.

- [ ] **Step 3: Add the struct field**

In `crates/defra-harness/src/cluster/builder.rs`, in the `pub struct TestClusterBuilder` definition (currently ends at line 43 with `acp_receipt_timeout: Option<u64>,`), append the new field so the struct ends:

```rust
    acp_request_timeout: Option<u64>,
    acp_receipt_timeout: Option<u64>,
    signing_multiplier_opt_out: bool,
}
```

- [ ] **Step 4: Initialize the field in `new()`**

In the same file, in `impl TestClusterBuilder { pub fn new() -> Self { Self { ... } } }` (around lines 52-78), append the new field initialization. The `Self { ... }` block currently ends:

```rust
            acp_request_timeout: None,
            acp_receipt_timeout: None,
        }
    }
```

Change to:

```rust
            acp_request_timeout: None,
            acp_receipt_timeout: None,
            signing_multiplier_opt_out: false,
        }
    }
```

- [ ] **Step 5: Add the `.no_signing_multiplier()` method**

Insert immediately after the existing `with_signing()` method (which is at lines 147-150). The existing method is:

```rust
    pub fn with_signing(mut self) -> Self {
        self.signing_enabled = true;
        self
    }
```

Insert after it:

```rust
    /// Opt this cluster out of the `signed-docs` test multiplier.
    ///
    /// When `DEFRA_MULTIPLIERS` contains `signed-docs`, `build()` would
    /// normally force `signing_enabled = true`. Call this on tests that
    /// are known to be incompatible with signing.
    pub fn no_signing_multiplier(mut self) -> Self {
        self.signing_multiplier_opt_out = true;
        self
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p defra-harness --lib cluster::builder::tests::no_signing_multiplier_sets_opt_out_flag`
Expected: PASS.

- [ ] **Step 7: Wire the multiplier into `build()`**

In `pub async fn build(mut self) -> Result<TestCluster>` (starts at line 216), find the line:

```rust
        // Allocate ports for all nodes
        let mut all_ports = allocate_node_ports(total)?;
```

Insert immediately before that comment:

```rust
        // Apply DEFRA_MULTIPLIERS=signed-docs unless this builder opted out.
        if signed_docs_multiplier_active() && !self.signing_multiplier_opt_out {
            self.signing_enabled = true;
        }

```

- [ ] **Step 8: Remove the `#[allow(dead_code)]` from Task 2 if it was added**

If you added `#[allow(dead_code)]` to `signed_docs_multiplier_active` in Task 2, remove it now — the build() branch above is the consumer.

- [ ] **Step 9: Run full check**

Run: `cargo test -p defra-harness --lib && cargo clippy -p defra-harness --all-targets -- -D warnings && cargo fmt --all`
Expected: all defra-harness lib tests pass, clippy clean, fmt no-op.

- [ ] **Step 10: Run a workspace-wide check to catch downstream breakage**

Run: `cargo check --workspace`
Expected: clean.

- [ ] **Step 11: Commit**

```bash
git add crates/defra-harness/src/cluster/builder.rs
git commit -m "$(cat <<'EOF'
feat(harness): wire signed-docs multiplier into TestClusterBuilder

Adds .no_signing_multiplier() opt-out and a branch in build() that
flips signing_enabled when DEFRA_MULTIPLIERS=signed-docs is set.
Idempotent with .with_signing(); no-op when env var unset.

Closes the backbone half of defradb.rs #978.
EOF
)"
```

---

## Final verification

- [ ] **Run the full defra-harness test suite**

Run: `cargo test -p defra-harness`
Expected: all tests pass (including any existing integration tests in `tests/sourcehub/`).

- [ ] **Verify the branch is ready**

Run: `git log --oneline main..HEAD`
Expected: 4 commits — the spec commit from brainstorming, then one commit per task above (3 implementation commits).

- [ ] **Hand off to the finishing-a-development-branch skill** to decide between PR, merge to main, or further work. The cross-repo follow-ups (defradb.rs #949 and #978 consuming PRs) live in the defradb.rs repo and are outside this plan's scope.
