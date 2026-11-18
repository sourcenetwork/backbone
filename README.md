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

Headers and responses carry the term of the device that proposed the revision.
A header is published only when its term matches the certified block, and a later
revision whose term is below an observed revision's term is refused.

Every device of an account's deployment holds its consensus key, so the blocks of a
device that was replaced verify like those of the device that replaced it. A term
certificate, approved under the deployment's operator policy, says which device
proposes from a term on and names the last block of the term before as its cut.
`AcpLightClient::for_deployment` and `ProofClient::for_deployment` take the
identifier of the deployment's genesis block, which the caller holds independently of
the node. Such a client accepts a revision of a term above 0 only once the node's
certificate of that term verifies, with the operator policy read from certified state
(`ProofClient::verified_term`). A client built without the identifier refuses every
term above 0.

When the certificate is accepted, the revision the client had reached is dropped if
the term voids it: a block above the cut, another block at the cut's height, or a
block below the cut unless the node shows the same block at that height. The client
then goes on from the new term's blocks, which may be at a lower height, and
`HeaderChain::voided` reports the dropped revision with the term that voided it.
Whatever a caller decided from that revision rests on state the deployment does not
have. A header of a later term is read even when its height is at or below the
client's. A read cannot move the client below its height, because it asks for a
revision at or above it; it fails until a header of the new term arrives.

The operator policy is read from the node that serves the certificate. A device that
holds the consensus key and forges state can therefore also forge the policy. The
check tells a client which of two honest devices to follow and what a switch voided;
it does not protect against a stolen device.

`ProofClient::fetch_and_verify_receipt` checks a submission's receipt against the
revision's `vera/receipts/v2` commitment under configured trust. A refused native
request carries its module and kind, which the commitment binds; the refusal message
is the serving node's text. Receipt responses are limited to the light-block budget
plus 8 MiB. An absent response does not show that a submission was refused or never
accepted.

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

### Native stack CI

The Native deployment qualification workflow can also be run manually against a selected checkout.

The Full Stack job builds pinned Vera once, then runs BLS12-381 and Jubjub Orbis
builds sequentially. Both curves exercise native startup, signing, PRE, revocation,
restart, resharing, and certified fault reports. A separate PET scenario on each
curve checks paired DKG, stored and inline decryption, document and audit
permissions, revocation and regrant, both polynomials after resharing, and restart.
It does not qualify time-scheduled refresh. The BLS build also exercises Defra
signing and replication. It tests this checkout's ACP light client through a local
Cargo source override. Defra is linked into the signing fixture at the revision
in `backbone.toml`. No external release artifacts or floating component branches
are used. These Vera and Orbis pins require fresh native state and matching
deployment roots.

Run `bash .github/scripts/test-native-stack.sh` with Rust 1.99.1 and protoc
installed. The script uses a temporary source checkout and retains build artifacts
under `target/native-stack` and per-curve logs and scenario evidence under
`target/native-stack-runs`. Orbis state and logs remain in each attempt's private
`orbis-clusters` directory and are not included in CI artifacts. The older
`tests/full_stack.rs` fixture uses EVM
administration and is not the native CI entry point. Native coverage checks
Orbis authorization and signed document replication; it does not yet cover
Defra collection-level strict ACP enforcement on replicated updates.
