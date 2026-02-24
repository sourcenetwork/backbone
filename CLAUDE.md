# Backbone

Full-stack integration test infrastructure for the Source Network Rust components.

## Architecture

```
backbone/
├── crates/
│   ├── test-infra/       # Shared primitives (ManagedProcess, ports, log tracking, run dirs)
│   ├── defra-harness/    # DefraDB node manager + CLI client + test fixtures
│   ├── hub-harness/      # Hub.rs node manager + cluster builder + observability
│   └── orbis-harness/    # Orbis ring builder + DKG fixtures + event subscriptions
└── tests/                # Full-stack integration tests (all components wired)
```

## Related Repos

All repos at `/Users/johnzampolin/go/src/github.com/sourcenetwork/`:

| Repo | Purpose | Integration test status |
|------|---------|----------------------|
| **defradb.rs** | CRDT data store, P2P, ACP, query engine | Most mature — imports `defra-harness` |
| **hub.rs** | Commonware chain, Zanzibar, node registry | Strong — imports `hub-harness` |
| **orbis-rs** | DKG, threshold sigs, identity delegation | Early — imports `orbis-harness` |

## Building

```bash
cargo check                        # Type-check workspace
cargo test --workspace             # Run all tests
cargo clippy --all -- -D warnings  # Lint
cargo fmt --all                    # Format
```

## Development Principles

Same as defradb.rs: no commented-out code, no TODOs, no speculative docs. Create issues instead.
