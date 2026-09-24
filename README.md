# Backbone

The cryptographic and infrastructural foundation for the Source Network stack.

Backbone wires together the three core Rust components — **defra.rs** (data), **hub.rs** (consensus + policy), and **orbis.rs** (identity + DKG) — into a unified system where data encryption, access control, and P2P replication work as autonomic infrastructure.

## The Stack

```
┌─────────────────────────────────────────────────────────┐
│                      Applications                       │
│  Git encryption, ML pipelines, company operating system │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                      Backbone                           │
│  Full-stack integration tests, cross-component wiring   │
└──┬──────────────────┬──────────────────┬────────────────┘
   │                  │                  │
   ▼                  ▼                  ▼
┌────────┐     ┌────────────┐     ┌────────────┐
│defra.rs│     │   hub.rs   │     │  orbis.rs  │
│        │     │            │     │            │
│ Data   │     │ Consensus  │     │ Identity   │
│ CRDTs  │     │ Zanzibar   │     │ DKG        │
│ P2P    │     │ Registry   │     │ Threshold  │
│ Query  │     │ Proofs     │     │ Delegation │
└────────┘     └────────────┘     └────────────┘
```

## Crate Structure

```
backbone/
├── crates/
│   ├── test-infra/       # Shared primitives (process mgmt, ports, log tracking)
│   ├── defra-harness/    # DefraDB node manager + CLI client + fixtures
│   ├── vera-harness/     # Go Vera process harness
│   ├── acp-light-client/ # Native Rust Vera proof verification
│   ├── soak/             # Mixed-runtime DefraDB workload harness
│   └── orbis-harness/    # Orbis ring builder + DKG fixtures
└── tests/                # Full-stack integration tests
```

### test-infra

The shared foundation that all harnesses build on:

- `ManagedProcess` — child process lifecycle (SIGTERM → wait → SIGKILL)
- `TestRunDir` — isolated test directories with RAII cleanup
- `LogTracker` — async log tailing with pattern matching and event broadcasting
- Port allocation — ephemeral OS-assigned ports for parallel test execution
- Health check polling — configurable readiness detection

### defra-harness

Everything needed to start, configure, and interact with DefraDB nodes:

- `DefraNode` trait — abstraction over Rust and Go binaries
- `TestClusterBuilder` — fluent API for multi-node clusters with P2P, ACP, encryption
- `DefraClient` — CLI-based client wrapping all DefraDB operations
- Test macros — `for_each_runtime!`, `for_each_p2p_topology!`
- Fixtures — ACP policies, schemas, identity generators

### Vera harnesses

The local `crates/vera-harness` manages Go Vera processes. Native Rust integration
tests use the separately pinned `vera-harness` package from `sourcenetwork/vera.rs`.
That package starts and observes Rust validator clusters:

- `TestClusterBuilder` — BFT-aware cluster setup with key generation
- `KeySet` — deterministic ed25519 + BLS threshold scheme generation
- `ClusterState` — unified observability (log tracking + RPC polling)
- `GenesisBuilder` — validator genesis and native execution configuration

### orbis-harness

Everything needed to orchestrate Orbis DKG rings:

- `OrbisRingBuilder` — multi-node ring setup with threshold configuration
- `DkgFixture` — complete Vera + Orbis ring with DKG ceremony
- Event-based synchronization — WebSocket subscriptions for DKG completion

### acp-light-client

Permission requests verify complete ACP evidence at an authenticated finalized revision
and run the shared policy evaluator. Record reads also support a cache bound to the
verified module root.

`AcpLightClient::new` accepts revisions younger than 30 seconds and permits up to
15 seconds of future timestamp skew. `new_with_freshness` accepts explicit
`FreshnessPolicy` bounds. The certificate authenticates the timestamp; notifications
cannot override it. All current reads, including cache hits, require fresh state. Proof fetches check
freshness again before returning. Monotonic elapsed time prevents a local clock rollback from extending
an already observed revision's lifetime. Disconnection and replay do not renew it.
A fresh newer revision restores reads. This requires a reasonably synchronized local
clock and bounds staleness; it does not establish that an endpoint supplied the
latest revision.

Proof HTTP calls share bounded streaming reads and a ten-second total request
timeout. State-proof and permission responses are limited to 4 MiB plus a 1 KiB
RPC envelope; light-block responses to 16 MiB plus 64 KiB. These are client acceptance
limits, not consensus payload limits or aggregate memory budgets. Oversized declared
or streamed bodies, HTTP failures and invalid JSON-RPC envelopes return errors.
Header WebSocket frames and assembled messages are limited to 64 KiB; connection
setup has a ten-second timeout. Subscription metadata is checked before processing
notifications. The WebSocket write buffer is bounded to 256 KiB.

`verify_access_decision` validates a persisted successful decision against an exact
`DecisionRequest`: deployment, policy, submitting identity and sequence, actor and
ordered operations. It also checks issuance metadata and revision-based expiry at
fresh authenticated state. This proves authorization at issuance; callers still
need to bind any payload or ticket use and enforce later revocation semantics.

`HeaderChain::state` is diagnostic and may return stale state. Use `fresh_state` for
current state. `ProofClient` methods for explicitly requested historical revisions
verify authenticity without applying current-read freshness bounds.

## How Component Repos Use Backbone

Each component repo imports its harness crate for integration tests:

```toml
# In defradb.rs/tools/integration-test/Cargo.toml
[dependencies]
defra-harness = { git = "https://github.com/sourcenetwork/backbone" }

# In hub.rs/crates/hub-e2e/Cargo.toml
[dependencies]
hub-harness = { git = "https://github.com/sourcenetwork/backbone" }

# In orbis-rs/crates/orbis-e2e/Cargo.toml
[dependencies]
orbis-harness = { git = "https://github.com/sourcenetwork/backbone" }
```

Full-stack tests that need multiple components live in `backbone/tests/`.

## The Idea

The data is the source. Its encryption, its access controls, and where it lives are the most important things when building a system. Backbone is the foundation that makes data sovereign — encrypted to real identities, replicated by policy, verifiable by proof.


Light blocks can authenticate a requested revision through a bounded chain of
canonical descendants ending in a threshold certificate. The shared verifier
checks parent hashes and contiguous heights, and returns the requested revision's
roots and timestamp. It accepts at most 64 descendants and 8 MiB of decoded
artifacts. A newer certified descendant does not renew the requested revision's
freshness. Direct-certificate responses retain their existing shape.
