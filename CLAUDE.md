# Backbone

Full-stack integration test infrastructure and coordination repo for the Source Network Rust stack.

## Hot path: ACP Light Client (#18)

The primary workstream is building a shared proof-validated ACP cache consumed by both DefraDB (query gate) and Orbis (signing gate). This is the critical path to making `tests/full_stack.rs` pass end-to-end with vera.rs as the Vera backend.

### Trust chain (every document write is cryptographically verified)

```
Service Identity (P-256/secp256k1, hardware keyring)
  → JWT authenticates to DefraDB
    → DefraDB requests Orbis ring to sign the block
      → Orbis ring checks ACP on vera.rs
        → vera.rs validators reach consensus
          → Ring threshold-signs the block (BLS12-381)
            → Any node verifies BLS signature on merge
              → Valid signature = ACP was enforced
```

### Cross-repo dependency map

```
vera.rs #61 (state proofs) + #44 (event gossip) + #68 (query wrappers)
  → Shared ACP Light Client crate (backbone #18)
    → defradb.rs #516 (query gate) + orbis-rs PR #60 (signing gate)
      → defradb.rs #530 (BLS verification on merge)
        → backbone tests/full_stack.rs (the canonical e2e test)
```

### Key issues by repo

| Repo | Issues | Focus |
|------|--------|-------|
| **backbone** | #11-16, #18 | Test infra, coordination, ACP light client design |
| **defradb.rs** | #514, #516, #530, #531 | VeraRsProvider, ACP caching epic, BLS verification, YubiKey |
| **vera.rs** | #44, #61, #67, #68 | Event propagation, state proofs, P2P interconnect, query wrappers |
| **orbis-rs** | PR #60 | ACP enforcement on signing path |

See `docs/architecture.md` for the full security architecture.

## Architecture

```
backbone/
├── crates/
│   ├── test-infra/       # Shared primitives (ManagedProcess, ports, log tracking, run dirs)
│   ├── vera-harness/     # Go Vera node manager used by defra-harness
│   ├── defra-harness/    # DefraDB node manager + CLI client + test fixtures
│   ├── orbis-harness/    # Orbis ring builder + DKG fixtures for vera.rs
│   ├── acp-light-client/ # Native Rust Vera proof verification
│   └── soak/             # Mixed-runtime DefraDB workload harness
├── tests/                # Full-stack integration tests (all components wired)
│                         # vera.rs clusters come from vera.rs's own vera-harness crate
└── docs/                 # Architecture and design docs
```

## Related Repos

Related repositories are independent checkouts under `github.com/sourcenetwork`:

| Repo | Purpose | Key integration |
|------|---------|----------------|
| **defradb.rs** | CRDT data store, P2P, ACP, query engine | Consumes ACP light client, Orbis signer |
| **vera.rs** | Commonware chain of native modules: Zanzibar ACP, bulletin, identity, node registry | Native BLS requests, state proofs, header stream, ACP authority |
| **orbis-rs** | DKG, threshold BLS sigs, identity delegation | Consumes ACP light client for signing gate |

## Three DID types

| Type | Multicodec | Purpose |
|------|------------|---------|
| BLS12-381 (0xea) | `did:key:z...` | Compartment identity (ring-derived, signs blocks) |
| secp256k1 (0xe7) | `did:key:zQ3s...` | Service identity (JWT auth, ACP grants) |
| Ed25519 (0xed) | `did:key:z6Mk...` | Validator/ring node identity (consensus, signer auth) |

## Building

```bash
cargo check                        # Type-check workspace
cargo test --workspace             # Run all tests
cargo clippy --all -- -D warnings  # Lint
cargo fmt --all                    # Format
```

## Running the canonical test

```bash
# Requires verad, defra, and orbis-node binaries on PATH
cargo test --test full_stack -- --ignored --nocapture
```

## Development Principles

Same as defradb.rs: no commented-out code, no TODOs, no speculative docs. Create issues instead.
