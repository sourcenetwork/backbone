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

## What Lives Here

- **Integration tests** that span the full stack (defra + hub + orbis working together)
- **Application prototypes** built on the stack (Git encryption, multi-tenant data isolation)
- **Issue generation** — tests here produce concrete work items for the component repos

## The Idea

The data is the source. Its encryption, its access controls, and where it lives are the most important things when building a system. Backbone is the foundation that makes data sovereign — encrypted to real identities, replicated by policy, verifiable by proof.

Each component repo has its own integration tests for internal correctness. Backbone's tests verify that the components compose correctly: a defra node with a hub-backed ACP engine and orbis-managed identities behaves as a single coherent system.
