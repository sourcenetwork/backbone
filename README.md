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
│   ├── hub-harness/      # Hub.rs cluster builder + observability
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

### hub-harness

Everything needed to start and observe Hub.rs validator clusters:

- `TestClusterBuilder` — BFT-aware cluster setup with key generation
- `KeySet` — deterministic ed25519 + BLS threshold scheme generation
- `ClusterState` — unified observability (log tracking + RPC polling)
- `GenesisBuilder` — EVM-compatible genesis configuration

### orbis-harness

Everything needed to orchestrate Orbis DKG rings:

- `OrbisRingBuilder` — multi-node ring setup with threshold configuration
- `DkgFixture` — complete SourceHub + Orbis ring with DKG ceremony
- Event-based synchronization — WebSocket subscriptions for DKG completion

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
