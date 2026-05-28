# defra-harness: signed-docs multiplier and transport port helper

**Date:** 2026-05-28
**Tracks:** defradb.rs [#978](https://github.com/sourcenetwork/defradb.rs/issues/978), [#949](https://github.com/sourcenetwork/defradb.rs/issues/949)
**Status:** approved

## Motivation

Two defradb.rs issues are blocked on backbone-side changes to `defra-harness`:

- **#978 — port Go's `signed-docs` test multiplier.** Go DefraDB ships a `DEFRA_MULTIPLIERS=signed-docs` env var that re-runs the entire integration suite with `TestCase.EnableSigning = true`. The value isn't testing signing itself (covered separately) — it's catching regressions in unrelated features that only surface when blocks carry `Signature` links. Rolling out the Go multiplier surfaced a real replicator bug ([defradb #4742](https://github.com/sourcenetwork/defradb/issues/4742) — signed counter deltas double-applied across peers). Rust has no equivalent suite-wide sweep yet.
- **#949 — move port allocation into `defra-harness`.** PR [defradb.rs #948](https://github.com/sourcenetwork/defradb.rs/pull/948) added a `TransportNodePorts` helper inline in `tools/integration-test/tests/p2p/transports.rs` to reserve HTTP + TCP + QUIC (UDP) + WS (TCP) ports. It mirrors `defra-harness::ports::allocate_node_ports` but adds a UDP guard and a second TCP guard. Keeping it in-tree was fine for one PR; the next transport test will copy it.

Both fix points live in `defra-harness` and ship together on one branch.

## Surface area

Two files change, both in `crates/defra-harness/src/`:

- **`ports.rs`** — add `TransportNodePorts` struct and `allocate_transport_ports(n)` helper. Existing `NodePorts` and `allocate_node_ports` are untouched.
- **`cluster/builder.rs`** — add `signing_multiplier_opt_out: bool` field, `.no_signing_multiplier()` method, and a 3-line branch in `build()` that consults `DEFRA_MULTIPLIERS` before constructing per-node `NodeConfig`.

No `lib.rs` re-exports needed — consumers already use `defra_harness::ports::*` directly (consistent with how `NodePorts` is consumed today).

## Port helper

```rust
// crates/defra-harness/src/ports.rs

pub struct TransportNodePorts {
    pub http: u16,
    pub tcp: u16,
    pub quic: u16,    // UDP
    pub ws: u16,      // TCP
    tcp_guards: Option<Vec<TcpListener>>,
    udp_guard: Option<UdpSocket>,
}

impl TransportNodePorts {
    pub fn release(&mut self) {
        self.tcp_guards = None;
        self.udp_guard = None;
    }

    pub fn p2p_addr_arg(&self) -> String {
        format!(
            "/ip4/127.0.0.1/tcp/{},/ip4/127.0.0.1/udp/{}/quic-v1,/ip4/127.0.0.1/tcp/{}/ws",
            self.tcp, self.quic, self.ws
        )
    }

    pub fn quic_p2p_addr_arg(&self) -> String {
        format!("/ip4/127.0.0.1/udp/{}/quic-v1", self.quic)
    }
}

pub fn allocate_transport_ports(n: usize) -> Result<Vec<TransportNodePorts>>;
```

The allocator binds all guards (3 TCP + 1 UDP per node, so `3n + n` total) **before** reading any `local_addr`. This preserves the bind-hold-release pattern that prevents parallel-test collisions: if two test threads allocate at the same time, the OS guarantees they get different ports because both listeners exist simultaneously.

The struct fields and methods mirror `TransportNodePorts` from `defradb.rs/tools/integration-test/tests/p2p/transports.rs:18-59` exactly, so the consuming PR is a pure import swap.

## Multiplier

```rust
// crates/defra-harness/src/cluster/builder.rs

fn signed_docs_multiplier_active() -> bool {
    std::env::var("DEFRA_MULTIPLIERS")
        .ok()
        .map(|v| v.split(',').any(|s| s.trim() == "signed-docs"))
        .unwrap_or(false)
}

// New field on TestClusterBuilder:
signing_multiplier_opt_out: bool,

// New method:
pub fn no_signing_multiplier(mut self) -> Self {
    self.signing_multiplier_opt_out = true;
    self
}

// In build(), before allocating ports:
if signed_docs_multiplier_active() && !self.signing_multiplier_opt_out {
    self.signing_enabled = true;
}
```

**Semantics:**

- `DEFRA_MULTIPLIERS` is a comma-separated list. Only `signed-docs` is honored today; unknown names are ignored (forward-compatible with future multipliers).
- `.no_signing_multiplier()` is the opt-out for tests known to be incompatible with signing.
- Idempotent with `.with_signing()`: if signing is already on, the env var is a no-op.

## Testing

- **`ports.rs` unit tests** — `allocate_transport_ports(2)` returns 8 unique TCP ports + 2 unique UDP ports; `release()` actually frees the underlying sockets (verified by binding the same ports again after release).
- **`builder.rs` unit test** — `signed_docs_multiplier_active()` handles `"signed-docs"`, `" signed-docs "`, `"signed-docs,foo"`, `"foo"`, and unset. Tests that mutate `DEFRA_MULTIPLIERS` must run serially (`std::env::set_var` is process-global); use a `Mutex` guard or place them in a single `#[test]` that sequences cases.
- **No end-to-end test of the flip behavior in this crate.** Spinning real defra binaries to verify "signing turns on" duplicates what defradb.rs's own CI will exercise once the consuming PR lands. The pure-function test on `signed_docs_multiplier_active()` plus a code-level branch readable in 3 lines is sufficient confidence here.

## Known wrinkle (out of scope)

The `for_each_runtime!`, `for_each_p2p_topology!`, and `for_each_p2p_topology_3!` macros in `crates/defra-harness/src/lib.rs:62-216` build clusters inline. Tests using those macros cannot insert `.no_signing_multiplier()` without an extra macro variant. If the defradb.rs rollout encounters a signing-incompatible test that uses one of these macros, we'll add a `_no_signing_multiplier!` variant in a follow-up PR — not solved here because it's speculative until a real incompatible test surfaces.

## Cross-repo rollout

1. **Backbone PR (this work)** — lands first. Pure additions, no existing API changes.
2. **defradb.rs #949 PR** — replaces the inline `TransportNodePorts` in `tools/integration-test/tests/p2p/transports.rs` with `use defra_harness::ports::{TransportNodePorts, allocate_transport_ports};`.
3. **defradb.rs #978 PR** — adds a CI workflow that runs `cargo test -p integration-test` with `DEFRA_MULTIPLIERS=signed-docs`, and applies `.no_signing_multiplier()` to any tests that surface as incompatible during the first run.

## Out of scope

- Extending `TestClusterBuilder` with a `.with_libp2p_transports()` method that auto-wires QUIC/WS multiaddrs into `NodeConfig`. Today's transport tests bypass the builder entirely, so this isn't required for #949. Can be added later if a builder-using test needs it.
- Generalizing the opt-out mechanism to `exclude_multiplier(name: &str)` for future multipliers. Concrete flag per multiplier is fine for one entry; we'll generalize when the second multiplier shows up.
