# Backbone Security Architecture

How the canonical full-stack test (`tests/full_stack.rs`) maps to a verifiable,
hardware-backed access control system.

## Trust chain

Every document write carries cryptographic proof of ACP authorization, rooted
in hardware keys at every link:

```
Service Identity (P-256, Secure Enclave)
  → JWT authenticates to DefraDB
    → DefraDB requests Orbis ring to sign the block
      → Orbis ring checks ACP on hub.rs (Ed25519, YubiKey)
        → Hub.rs validators reach consensus (Ed25519, YubiKey)
          → Ring threshold-signs the block (BLS12-381)
            → Any node can verify the BLS signature
              → Valid signature = ACP was enforced
```

An attacker who compromises a single DefraDB instance cannot forge a BLS
signature. Other nodes reject unsigned or mis-signed blocks on merge. This is
the system's core security invariant.

## Three DID types

The system uses three distinct `did:key` types, each serving a different layer:

| DID Type | Multicodec | Curve | Purpose |
|----------|------------|-------|---------|
| BLS12-381 | 0xea | G1 | Compartment identity — ring-derived, signs blocks |
| secp256k1 | 0xe7 | secp256k1 | Service identity — JWT auth, ACP grants |
| Ed25519 | 0xed | Ed25519 | Ring signer authorization, validator consensus |

Hub.rs accepts all three in its ACP module. BLS identities work via native BLS
transactions; secp256k1 via EVM transactions; Ed25519 via consensus signing.

## Identity hierarchy

```
Orbis Ring (BLS12-381 master key, threshold T-of-N)
  │
  ├── derive("acme-corp")          → ACME_DID      (BLS, compartment identity)
  ├── derive("globex-inc")         → GLOBEX_DID    (BLS, compartment identity)
  └── derive("platform")           → PLATFORM_DID  (BLS, platform root)

Service Identities (secp256k1 or P-256, device keyring)
  │
  ├── TRAINING_SVC    → did:key:zQ3s... (writer on acme)
  ├── INFERENCE_SVC   → did:key:zQ3s... (reader on acme)
  ├── AUDIT_SVC       → did:key:zQ3s... (reader on both)
  └── GLOBEX_SVC      → did:key:zQ3s... (writer+reader on globex)

Node Operator Keys (Ed25519, YubiKey OpenPGP)
  │
  ├── Hub.rs validators  → consensus signing
  ├── Orbis ring nodes   → P2P identity + ring ACP signer authorization
  └── DefraDB nodes      → authorized to request ring threshold signatures
```

## Hardware roots of trust

| Key | Curve | Hardware | Role |
|-----|-------|----------|------|
| Hub.rs validator | Ed25519 | YubiKey (OpenPGP) | Consensus signing, ACP state authority |
| Orbis ring node | Ed25519 | YubiKey (OpenPGP) | DKG participation, threshold signing |
| Service identity | P-256 | Secure Enclave | JWT auth to DefraDB |
| Service identity | P-256 | YubiKey (PIV) | JWT auth to DefraDB |
| EVM bootstrap | secp256k1 | Software only | Initial policy creation (one-time) |
| DKG shares | BLS12-381 scalar | Software only | Threshold-distributed by design |

The EVM bootstrap key and DKG shares cannot be hardware-backed: the bootstrap
key because YubiKey/Secure Enclave don't support secp256k1, and DKG shares
because they're generated during the ceremony and distributed across nodes
(single-device storage would defeat the purpose).

## ACP enforcement points

ACP is enforced at two independent points, both requiring the same hub.rs
client infrastructure:

### 1. Orbis ring (signing gate)

When a service requests the ring to sign a block:

1. Service presents JWT with its `did:key` (secp256k1/P-256)
2. Each ring node independently checks ACP on hub.rs
3. If the service lacks the required permission, the node refuses to participate
4. Without a threshold of participating nodes, no BLS signature is produced
5. The block cannot exist without ACP authorization

This is orbis-rs PR #60 (ACP enforcement on the signing path).

### 2. DefraDB (query gate)

When a service queries documents:

1. Service presents JWT with its `did:key`
2. DefraDB checks ACP on hub.rs for each document
3. Reads: unauthorized documents silently filtered from results
4. Writes: unauthorized mutations return an error
5. Document auto-registration via `@policy` directive

### Shared ACP client

Both enforcement points need the same high-performance ACP client:

- **Light-client validated cache** — local ACP state validated against hub.rs
  consensus proofs, not blind trust in a single RPC endpoint
- **Event-driven invalidation** — subscribe to hub.rs events for policy/grant
  changes, invalidate cache entries immediately
- **Proof verification** — verify that cached ACP decisions match the on-chain
  state using hub.rs light client proofs

This shared ACP client should be a common library consumed by both DefraDB's
`HubRsProvider` and Orbis's signing path ACP checker.

## What the test proves

The canonical test (`tests/full_stack.rs`) exercises the full trust chain
across 30 steps in 5 phases:

| Phase | Steps | What it proves |
|-------|-------|----------------|
| Infrastructure | 1-4 | SourceHub + Orbis ring + DKG + ring signing policy |
| Identity setup | 5-10 | 3 unique BLS compartment DIDs, service identities, ring signer auth |
| Acme compartment | 11-18 | Schema with @policy, writer writes, reader reads, reader can't write |
| Globex + isolation | 19-24 | Second compartment, cross-compartment isolation both directions |
| Audit + lifecycle | 25-30 | Cross-compartment reader, write denial, revocation, key rotation |

## Tracking issues

### Backbone (coordination + test infrastructure)

| Issue | What |
|-------|------|
| #11 | Hub.rs ACP client for DefraDB (replace CosmosProvider) |
| #12 | Hub.rs node harness as SourceHub backend |
| #13 | Test-side policy management client for hub.rs |
| #14 | Verify relation-based ACP grant enforcement e2e |
| #15 | Orbis ring signing ACP authorization via hub.rs |
| #16 | Bulletin board on hub.rs for DKG |
| **#18** | **ACP Light Client — shared proof-validated cache (design)** |

### DefraDB.rs (query gate)

| Issue | What |
|-------|------|
| #514 | Hub.rs native integration (HubRsProvider) |
| #516 | SourceHub ACP Performance & Proof-Validated Caching (epic) |
| #530 | BLS signature verification in merge handler |
| #531 | YubiKey-backed keyring backend |

### Hub.rs (consensus + ACP state authority)

| Issue | What |
|-------|------|
| #44 | ACP event propagation via gossip + light client verification |
| #61 | Module state proof specs (Merkle inclusion proofs) |
| #67 | P2P interconnect between hub.rs and defra.rs |
| #68 | Bearer token methods and query wrappers |

### Orbis-rs (signing gate)

| Issue | What |
|-------|------|
| PR #60 | Utility services + ACP enforcement on signing path |
