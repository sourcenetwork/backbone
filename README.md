# Backbone

The cryptographic and infrastructural foundation for the Source Network stack.

Backbone wires together the three core Rust components — **defra.rs** (data), **vera.rs** (consensus + policy), and **orbis.rs** (identity + DKG) — into a unified system where data encryption, access control, and P2P replication work as autonomic infrastructure.

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
│defra.rs│     │  vera.rs   │     │  orbis.rs  │
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
│   ├── vera-support/     # Native Vera deployments and administration
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

### vera-support

`VeraDeployment` starts a vera.rs validator cluster and names the trust
material DefraDB and Orbis are configured with (deployment id, consensus key,
genesis id); `VeraAccount` submits native requests to it. Clusters come from
the `vera-harness` package of `sourcenetwork/vera.rs`, pinned in the workspace:

- `TestClusterBuilder` — BFT-aware cluster setup with key generation
- `KeySet` — deterministic ed25519 + BLS threshold scheme generation
- `ClusterState` — unified observability (log tracking + RPC polling)
- `GenesisBuilder` — validator genesis and native execution configuration

### orbis-harness

Everything needed to orchestrate Orbis DKG rings:

- `OrbisRingBuilder` — orbis-node processes configured for a `VeraDeployment`
- `RingAdmin` — node authorization, ring creation, documents and key
  derivations through native Vera requests
- `DkgFixture` — a deployment, a 3-node ring and its finalized key

### Light client

The proof-validated ACP light client is Vera's `vera-light-client` crate,
pinned in the workspace with the other vera.rs crates and imported as
`acp_light_client`. Its unit and transport tests live in vera.rs;
`tests/vera_light_client.rs` runs it against a native Vera cluster here.

## How Component Repos Use Backbone

Each component repo imports its harness crate for integration tests:

```toml
# In defradb.rs/tools/integration-test/Cargo.toml
[dependencies]
defra-harness = { git = "https://github.com/sourcenetwork/backbone" }

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

### Native stack CI

The Native deployment qualification workflow can also be run manually against a selected checkout.

The Full Stack job builds pinned Vera once, then runs BLS12-381 and Jubjub Orbis
builds sequentially. Both curves exercise native startup, signing, PRE, revocation,
restart, resharing, and certified fault reports. A separate PET scenario on each
curve checks paired DKG, stored and inline decryption, document and audit
permissions, revocation and regrant, both polynomials after resharing, and restart.
It does not qualify time-scheduled refresh. The BLS build also exercises Defra
signing and replication. Orbis takes the light client from Vera, and the job
checks that every vera.rs dependency of the Orbis fixture names the revision
Backbone pins `vera-light-client` at. Defra is linked into the signing fixture at
the revision in `backbone.toml`. No external release artifacts or floating component branches
are used. These Vera and Orbis pins require fresh native state and matching
deployment roots.

Run `bash .github/scripts/test-native-stack.sh` with Rust 1.99.1 and protoc
installed. The script uses a temporary source checkout and retains build artifacts
under `target/native-stack` and per-curve logs and scenario evidence under
`target/native-stack-runs`. Orbis state and logs remain in each attempt's private
`orbis-clusters` directory and are not included in CI artifacts. The
`tests/full_stack.rs` fixture administers Vera through native requests from the
test process and is not the native CI entry point. Native coverage checks
Orbis authorization and signed document replication; it does not yet cover
Defra collection-level strict ACP enforcement on replicated updates.
