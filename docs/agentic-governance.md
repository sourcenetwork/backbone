# Agentic Governance

## The Problem

AI agents are becoming core infrastructure. They execute tasks, manage sessions, call tools, produce artifacts, and operate across organizational boundaries — often with broad access to sensitive data and systems. Today, governing these agents relies on application-level controls: API keys, OAuth scopes, prompt-level instructions, and platform trust boundaries. These controls share a fundamental weakness: they are enforced in software, by the same systems the agents operate within. A misconfigured token, a compromised service account, or a platform vulnerability, and the boundary is gone.

As organizations deploy agents across proprietary data, internal tools, and cross-team workflows, the governance question becomes unavoidable: **how do you cryptographically prove what an agent accessed, what it produced, and that it never exceeded its authority?**

## The Approach: Governance at the Data Layer

Source Network's agentic governance framework moves enforcement from the application layer to the data layer. Rather than trusting agents to follow rules, the system makes unauthorized access cryptographically impossible.

Three primitives make this work:

**Cryptographic identity** — Every agent, human, and service gets a decentralized identifier (DID) backed by real cryptographic keys. Agent identities are not API tokens. They are key pairs rooted in hardware (secure enclaves, HSMs) or distributed across a DKG ring, where no single machine ever holds the complete private key.

**Consensus-backed access control** — Permissions are not database rows. They are recorded on a Commonware-consensus chain with EVM execution, where every grant, revocation, and policy change requires consensus. This produces an immutable, auditable record of who was authorized to do what, and when. The access control model is Google Zanzibar — the same relation-based system that governs permissions across Google's infrastructure — running on a dedicated consensus layer.

**Identity-based encryption** — Data is encrypted to identities, not to servers or storage locations. Data encrypted to a specific agent identity can be replicated, cached, backed up, or stored anywhere. It remains ciphertext to everyone except identities with verified permissions. When an authorized reader needs access, the Orbis ring performs **proxy re-encryption** — transforming the ciphertext for that reader without ever reconstructing the plaintext. There is no master key.

## How It Works: Agents Governed by Construction

The conventional approach to agent governance treats it as an add-on: build the agent, then layer controls around it. Source Network inverts this. Agents operate through a data layer where every operation — every request, response, tool call, and artifact — is a cryptographically governed document. You do not add governance to the agent. The agent is governed because that is how it operates.

### The Stack

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Runtime                        │
│               (defra-agent and others)                  │
│   Formally verified lifecycle, document-driven control  │
└────────────────────────┬────────────────────────────────┘
                         │ Authenticated reads and writes
┌────────────────────────▼────────────────────────────────┐
│                      DefraDB                            │
│                                                         │
│  CRDT document store with iroh P2P replication          │
│  All data encrypted to authorized identities            │
│  Access control enforcement on every operation          │
│  Every document is a governed, auditable record         │
└──┬──────────────────────────────────────┬───────────────┘
   │                                      │
   ▼                                      ▼
┌──────────────┐                    ┌──────────────┐
│    Hub.rs    │                    │    Orbis     │
│              │                    │              │
│  Commonware  │                    │   DKG ring   │
│  consensus   │                    │              │
│  + EVM exec  │                    │  Proxy re-   │
│              │                    │  encryption  │
│  ACP /       │                    │              │
│  Bulletin /  │                    │  Threshold   │
│  Identity    │                    │  signing     │
│  precompiles │                    │              │
│              │                    │  No single   │
│  Zanzibar    │                    │  key holder  │
└──────────────┘                    └──────────────┘
```

### Agent Identity: Key Material

Every agent receives a cryptographic identity — a DID backed by key material that is either hardware-rooted (secure enclave, YubiKey) or distributed across an Orbis DKG ring.

The identity model for *key material* has three layers:

| Layer | What | Why |
|-------|------|-----|
| **Orbis Identity** | Persistent real identity, DKG-distributed across ring nodes | No single key to steal. Ring survives node failure. |
| **Node Identity** | Hardware-rooted key on the machine running the agent | Proves which physical machine an action came from. |
| **Service Identity** | The agent's operational key, authenticated via signed JWT | Ties every operation to a verifiable principal. |

An AI agent gets the same cryptographic treatment as a human operator. Its Orbis identity ties it to a real principal — the human or organization that authorized it. Its node identity ties it to specific hardware. Its service identity authenticates every operation it performs.

Identity provisioning follows the same path for agents and humans. An administrator registers a device (or agent node) as a candidate, links it to an identity, and assigns roles and permissions. The agent delegation flow adds one step: an agent that needs new capabilities submits a request through the approval inbox, a human reviews the policy, and signs an approval or rejection. The signed decision is recorded on the consensus layer. There is no backdoor.

Part 2 describes a second identity model in the runtime — **Principal / Behavior / Deployment** — which is orthogonal to key material. It is about what an agent *is* and what it *does*, not about what key signs for it.

### Governed by Construction

The key architectural insight is that agents do not operate alongside the governance system — they operate *through* it. Every agent interaction is a document in DefraDB:

| Operation | What Gets Stored | Governed How |
|-----------|------------------|--------------|
| **Request** | Task or prompt submitted to the agent | Encrypted to agent's identity, ACP on write |
| **Response** | Agent's streamed output (text, artifacts, decisions) | Encrypted to authorized identities, ACP on read |
| **Inference call** | Backend, call kind, state, queue/timing/token counts | Per-request record, signed by agent |
| **Session** | Running conversation identity, status, timing | Encrypted to session participants |
| **Conversation** | Title, preview, latest request | Encrypted to session participants |
| **Message** | Ordered transcript entry (role, content, timestamp) | Encrypted to session participants |
| **Tool call** | Tool name, arguments, result, timestamps | Encrypted, access-controlled, signed by agent |
| **Tool result** | Normalized output, truncation state | Same as tool call |
| **Compaction entry** | Summary replacing older messages, message and token counts | Encrypted to session participants |
| **Scheduled task** | Recurring prompt, interval, last status | Configuration; updated by scheduler |
| **Runtime state** | Process state, active generation, last reconcile result | Operational observability |

Because every operation is a DefraDB document, every operation automatically gets identity-based encryption, consensus-backed access control, and a cryptographic audit trail. The agent does not need to "opt in" to governance. It cannot opt out.

### The Agent Lifecycle

An agent's operational cycle works through document exchange, with P2P replication carrying data between participants:

```
Client                    DefraDB (P2P mesh)              Agent Daemon
  |                            |                            |
  |-- write AgentRequest ----->|                            |
  |                            |-- P2P replication -------->|
  |                            |                            |
  |                            |           authenticate,    |
  |                            |           check permissions|
  |                            |                            |
  |                            |           claim admission, |
  |                            |           record inference |
  |                            |           call; each tool  |
  |                            |           call stored as   |
  |                            |           a governed doc   |
  |                            |                            |
  |                            |<-- write AgentResponse ----|
  |<-- P2P replication --------|                            |
  |                            |                            |
  |   (plaintext only if       |   (ciphertext in transit   |
  |    identity authorized)    |    and at rest)            |
```

1. A client writes an `AgentRequest` document to DefraDB. The document is encrypted to the agent's identity.
2. P2P replication carries the request to the agent daemon's node. The daemon detects it via the event bus.
3. The daemon authenticates using its service identity (signed JWT) and loads the request — but only if ACP confirms read permission.
4. The daemon claims admission, records an `InferenceCall`, and executes. Each tool invocation writes `AgentToolCall` and `AgentToolResult`: tool name, arguments, output, timestamps. Tool access is governed by the same ACP policies as data access.
5. The daemon streams output as updates to an `AgentResponse` document with a monotonically increasing `progress_seq`, so clients can tell real progress from replay.
6. On terminal state, the response is final. P2P replication carries it back to the client.

Every step produces a governed document. The agent's operational record *is* the audit trail.

### Data and Permissions

Governance has two surfaces: **what data can the agent access**, and **what is the agent permitted to do**. Both are enforced at the data layer, not the application layer.

**Data access** — DefraDB enforces access control on every read and every write. When an agent queries for documents, the query gate checks the agent's permissions against a local ACP cache validated by Hub.rs consensus proofs. Unauthorized reads return nothing. Unauthorized writes fail. Data the agent is not authorized for remains encrypted — the cryptographic path to the plaintext does not exist.

**Permissions** — The signing gate governs what the agent can produce. When an agent writes a document, DefraDB requests the Orbis threshold ring to sign the operation. Each ring node independently checks the agent's permissions against Hub.rs. If a threshold of nodes agree the agent is authorized, the signature is produced. If not, the operation cannot be signed. Unsigned operations are rejected by all other nodes on merge.

The combination means: an agent cannot read data it is not authorized for (encryption + query gate), and it cannot produce valid operations without authorization (signing gate). Both checks are performed by independent infrastructure, not by the agent's own runtime.

### Human Oversight

Cryptographic governance does not mean unsupervised agents. The identity management layer provides humans with direct control over agent capabilities through three mechanisms:

**Identity provisioning** — Administrators manage agent identities through the same identity directory used for human operators. They register agent nodes, link them to identities, assign roles and compartments, and set permissions. An agent's scope is defined before it begins operating.

**Permission management** — Zanzibar-style relation tuples define what each agent identity can access. An administrator can grant or revoke relations at any time: "Agent X is a reader of Collection Y," "Agent Z is an operator of Tool W." Permissions are binary and take effect immediately — revocation propagates through the consensus protocol and invalidates local caches within seconds.

**Approval inbox** — A policy signing queue where agents can request new capabilities and humans review them. An agent that needs access to a new data collection, or delegation to act on behalf of a user, submits a request. The request appears in the target identity's inbox. The human reviews the policy, sees exactly what is being requested in human-readable form, and signs an approval or rejection. The signed decision is recorded on the consensus layer.

```
Agent                    System                   Human's Inbox
  |                        |                         |
  |-- request access ----->|                         |
  |   to Collection Y      |-- request appears ----->|
  |                        |                         |
  |                        |          review policy  |
  |                        |          details        |
  |                        |                         |
  |                        |<-- signed approval -----|
  |                        |                         |
  |<-- access granted -----|-- recorded on-chain --->|
  |                        |                         |
  |-- operates within      |                         |
  |   granted scope ------>|                         |
```

This is not a trust-based system. The human does not trust the agent to stay within scope. The cryptographic infrastructure enforces it.

### Provenance and Audit

Every action in the system produces a cryptographically verifiable record:

| Action | Signed By | Verifiable Claim |
|--------|-----------|------------------|
| Agent request | Client identity | "User X requested Agent Y to perform task Z" |
| Tool execution | Agent's service identity + Orbis ring | "Agent Y executed Tool W with these arguments at time T" |
| Agent response | Agent's service identity + Orbis ring | "Agent Y produced this output, authorized by policy P" |
| Data read | ACP proof from Hub.rs consensus | "Agent Y was authorized to read this data at time T" |
| Permission grant | Hub.rs validator consensus | "Human X granted Agent Y access at time T" |
| Permission revocation | Hub.rs validator consensus | "Human X revoked Agent Y's access at time T" |
| Delegation approval | Human's device key (signed transaction) | "Human X approved Agent Y's delegation request at time T" |

This is not application-level logging. Every entry is backed by consensus and threshold cryptography. An auditor can independently verify the entire chain — which agent executed which operations, what data it had access to, who authorized that access, and when access was revoked — without trusting any single system component.

## Key Properties

**No single point of compromise** — Signing authority is distributed across the Orbis ring via distributed key generation (DKG). Compromising one node yields nothing. An attacker would need to simultaneously compromise a threshold of independent nodes — potentially operated by different organizations, on different infrastructure, with keys in different hardware security modules.

**Hardware roots of trust** — Node identities are bound to secure enclaves and hardware security modules. Validator consensus keys live on YubiKeys. This means that even with root access to a machine, an attacker cannot extract the signing key — it never leaves the hardware.

**Real-time revocation** — When an agent's authorization is revoked (employee offboarded, contract expired, agent decommissioned), the permission change propagates through the consensus protocol and invalidates local caches within seconds. The agent's cryptographic path to the data is severed. This is not a "please stop" — it is a key that stops working.

**P2P replication with confidentiality** — Data encrypted to identities can be replicated peer-to-peer across nodes without compromising confidentiality. The ciphertext is safe to distribute because only authorized identities can decrypt. This enables distributed architectures where data is replicated for availability but access is still governed centrally by Hub.rs policy.

**Compatible with existing infrastructure** — DefraDB exposes standard interfaces that existing agent frameworks and tooling can connect to without modification. Organizations do not need to rewrite their agent infrastructure. They connect it to DefraDB, and every operation is automatically encrypted, access-controlled, and auditable.

---

# Part 2 — The Agent Runtime: defra-agent

## Why a Runtime

An agent's operational state — what it is doing now, what it already did, what it is about to do — has to be visible to the governance system, not hidden inside a service with private state. A runtime built as a separate service cannot be governed by construction: there is always a gap between what the agent does and what the data layer sees.

**defra-agent** closes the gap by making the document store the control plane. The runtime has no operational state that matters outside DefraDB. You configure it by writing documents. You trigger work by writing documents. You debug by reading documents. Every lifecycle transition produces a record. The governance system sees everything because there is nothing else to see.

## Document-Driven Control Plane

defra-agent resolves every question — what agent identity is this, what tools can it use, what backend does it call, what is it working on right now, what did it do an hour ago — by reading documents.

### Configuration collections

The agent's desired state is described by seven collections:

| Collection | Purpose |
|------------|---------|
| `AgentPrincipal` | DID-backed identity; permission and audit boundary |
| `AgentBehavior` | Prompt, model, tool selection, backend, inference profile |
| `ToolSelection` | Which local and remote tools the behavior can use |
| `InferenceBackend` | LLM endpoint, model list, concurrency and queue limits |
| `InferenceProfile` | Context window, output budget, temperature, deadlines |
| `ScheduledTask` | Recurring prompt with interval and last status |
| `ToolServiceRegistry` | Discoverable MCP-style remote tool services |

### Observability collection

One collection describes what the runtime is doing right now:

| Collection | Purpose |
|------------|---------|
| `AgentRuntime` | Process state, reconcile phase, active generation, last reconcile result |

### Interaction history

Per-request operational records, all encrypted to session participants:

`AgentRequest`, `AgentResponse`, `InferenceCall`, `AgentSession`, `AgentConversation`, `AgentMessage`, `AgentToolCall`, `AgentToolResult`, `CompactionEntry`.

### Resolution chain

When the runtime reconciles, it resolves a runnable configuration by following this chain:

```
AgentPrincipal
  → AgentBehavior
      → InferenceBackend
      → ToolSelection (intersected with operator ceiling)
      → InferenceProfile (optional)
  → publish AgentRuntime
```

If the backend is missing, disabled, or unhealthy, the behavior is unrunnable, and the runtime publishes that fact.

### Source-of-truth boundaries

The configuration-apply path owns desired-state fields (config, prompts, backend references). The runtime owns live-state fields (probe status, run counts, lifecycle state). Neither clobbers the other. Configuration collections are current desired state. Operational collections are branchable, preserving observable history.

## Identity in the Runtime: Principal / Behavior / Deployment

Part 1 described the identity model for *key material* — Orbis, Node, and Service keys that sign operations. defra-agent introduces an orthogonal model for what an identity *is* and what it *does*:

| Concept | Role |
|---------|------|
| **Principal** | DID-backed identity. The permission and audit boundary. What Hub.rs recognizes. What signs documents. |
| **Behavior** | Prompt, tools, model, backend policy. One principal can have many behaviors. |
| **Deployment** | Where a principal's behavior actually runs. Binds hardware. |

The separation matters. An organization deploying a coding assistant and a general-purpose assistant does not need two separate identities — both are *behaviors* of one principal, sharing its permissions and audit trail. A background rumination task that should not see sensitive data uses a separate *principal* with narrower permissions, not a flag on the same one.

Principals are least-privilege boundaries. Behaviors are reusable interfaces. Deployments are hardware bindings. You do not mint a new identity every time you add a new prompt.

## Formally Verified Lifecycle

The runtime's lifecycle is not code wrapped in types that resemble a state machine. It is a **Lean 4 model with proven theorems**, and the Rust implementation is tested for refinement against the model.

### State machines

Three layers, executable and proven:

| Layer | States |
|-------|--------|
| **Process** | Uninitialized, Recovering, Ready, ShuttingDown, Shutdown |
| **Request** | Pending, Claimed, Processing, InputRequired, Completed, Failed, Superseded, Dead |
| **Persistence** | Uncommitted, Committing, Committed, Lost |

Composed state space: 5 × 8 × 4 = 160 states.

### Safety properties

Proven as theorems, not asserted in comments:

| ID | Property |
|----|----------|
| **S1** | Terminal requests stay terminal. A completed or failed request cannot silently re-enter processing. |
| **S3** | `progress_seq` never decreases. Clients can treat progress as monotonic and avoid rewind bugs. |
| **S4** | Completion cannot hide a deadline violation. A request that reaches `completed` did not get there through deadline expiry. |
| **S5** | Recovery blocks claims. New work is not admitted while recovery is still repairing stuck state. |
| **S6** | Completion implies persistence. The model does not allow `completed` without a committed durable state. |
| **S7** | Scheduler capacity invariants are preserved. Running-slot counts stay within backend limits. |
| **S8** | Slot accounting is preserved. Scheduler counts stay aligned with per-request admission state. |
| **S9** | Terminal work releases capacity; unavailable backends cannot acquire. Slots are not leaked; unrunnable backends do not admit new work. |

### Liveness properties

| ID | Property |
|----|----------|
| **L1** | Real phase changes decrease a termination measure. Endless phase churn is ruled out. |
| **L2** | Claimed work has a constructive path to a terminal state. No "stuck forever before inference begins." |
| **L3** | Recovery converges. A finite set of stuck requests can be driven to terminal outcomes in finite steps. |

Two cross-cutting models are also proven: **session retry and reissue** (a reissued request stays in the same session; latest-request semantics stay coherent; retry counts are bounded) and **reconcile generation publication** (generations only move forward; sessions stay pinned by behavior identity; a generation is not retired while in-flight work depends on it).

### Conformance

The Lean model defines the legal transition vocabulary. Rust conformance tests — run against persisted DefraDB state — assert that the implementation refines the legal traces. A code change that introduces an illegal transition fails the tests. A code change that silently drops an invariant fails the tests. The model is the primary specification; the tests keep the implementation honest against it.

## Runtime Shape

The operational shape of the runtime in five moving pieces.

### Request flow

A client writes an `AgentRequest`. The admission controller claims a backend slot (or queues the request). The runtime records the claim as an `InferenceCall`. The inference and tool loop produces streamed output, written to an `AgentResponse` with a monotonically increasing `progress_seq`. Each tool invocation writes `AgentToolCall` and `AgentToolResult`. On terminal state — `completed`, `failed`, `superseded`, or `dead` — the response is final.

### Reconciliation

When a configuration document changes — `AgentPrincipal`, `AgentBehavior`, `ToolSelection`, `InferenceProfile`, or the referenced `InferenceBackend` — the runtime reconciles. Each reconcile resolves the chain, applies it, and publishes a new `AgentRuntime` generation. In-flight work stays pinned to its claiming generation. The previous generation is not retired until its work drains. The proofs guarantee that generations only move forward and that sessions stay coherent across transitions.

### Scheduler

Admission is per-backend. `max_concurrent` and `max_queue_depth` live on the `InferenceBackend` document. The scheduler tracks running and queued slots and maintains the capacity invariants proven in Lean: slots are not leaked, terminal work releases capacity, and unavailable backends cannot acquire.

### Tool surfaces

Three layers, independent by design:

1. **Local tools** — file and bash, bounded by an operator-owned ceiling that caps what any behavior can use, regardless of what the behavior requests. The operator keeps the safety ceiling even when the behavior is misconfigured.
2. **Remote MCP services** — discovered at runtime through `ToolServiceRegistry` entries carrying endpoints and status. The runtime connects to the service and imports its tool manifest.
3. **Behavior-specific selection** — `ToolSelection` picks which tools the behavior is exposed to. The final tool surface is the intersection of the behavior's selection and the operator's ceiling.

### Scheduled execution

`ScheduledTask` documents carry a recurring prompt, an interval, and the target behavior. The scheduler claims tasks when they come due, runs them through the same request flow, and updates their status.

### Replication

The desktop client pairs with a local runtime over iroh P2P on localhost, then replicates the entire control plane — configuration and operational documents alike. The same governance machinery that protects cross-organization deployments protects the local loopback pairing.

---

# Part 3 — Close

## Architecture Summary

| Component | Role | Key Property |
|-----------|------|-------------|
| **DefraDB** | CRDT document store, iroh P2P replication, agent operation backend | Every operation is ACP-gated; data encrypted to identities |
| **Hub.rs** | Commonware-consensus chain with EVM execution; ACP, Bulletin, and Identity precompile modules; native BLS transaction path | Immutable permission records, validator consensus, state proofs |
| **Orbis** | DKG-generated ring keys, proxy re-encryption for authorized readers, threshold signing | No single key holder, ring survives node loss, hardware-rooted |
| **defra-agent** | Formally verified agent runtime over DefraDB, document-driven control plane | Every operation is a governed document; lifecycle is a Lean-proved state machine |

## Trust Chain

```
Agent Identity (hardware-rooted or DKG-distributed)
  → Authenticates to DefraDB via signed JWT
    → DefraDB requests Orbis ring to sign the operation
      → Each ring node independently checks ACP on Hub.rs
        → Hub.rs validators reach consensus on authorization
          → Ring threshold-signs the operation (BLS12-381)
            → Any node can independently verify the signature
              → Valid signature = ACP was enforced, provenance is proven
```

An attacker who compromises a single node cannot forge a threshold signature. Other nodes reject unsigned or mis-signed operations on merge. This is the system's core security invariant.

## Current State

Source Network's agentic governance framework runs across every layer. **DefraDB** runs as a CRDT document store with iroh P2P replication and a local ACP gate backed by Hub.rs consensus proofs. **Hub.rs** runs on Commonware consensus with EVM execution, native BLS transactions, and the ACP, Bulletin, and Identity precompile modules exercising the full Zanzibar policy engine. **Orbis** runs as a DKG ring with proxy re-encryption and threshold signing, open-sourced. **defra-agent** runs as a Rust agent runtime with a formally verified lifecycle, a document-driven control plane, a CLI, and a desktop client that pairs over iroh P2P. The full trust chain — cryptographic identity, consensus-backed access control, identity-based encryption, and governed-by-construction operation — is exercised end-to-end through Backbone's integration harnesses.
