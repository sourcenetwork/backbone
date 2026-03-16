# Identity Management UI Design

This document defines the screens and flows for the identity management UI layer
of the Source Network stack. The design is tech-stack agnostic and focuses on
the user-facing surfaces needed to manage cryptographic identities, devices,
permissions, and approval workflows.

## Mental Model

A user's real identity is a BLS12-381 key held inside an Orbis DKG ring. Users
never interact with this key directly. Instead, they control it through a set of
**device keys** (passkeys, secure enclave keys, YubiKeys) which act as their
interface to the system. Each device key is a secp256k1 service identity.

The core abstraction: **I am my devices, and my devices collectively control my
on-chain identity.**

### Device Lifecycle

1. A device registers itself as a **candidate** ("I exist, here is my public
   key"). At this point it is unlinked to any identity.
2. An **admin links** the candidate device to an identity, either existing or
   newly created.
3. Once linked, the device can authenticate and act on behalf of that identity.
4. Any authenticated device on an identity can add or remove other devices from
   that identity.

### Bootstrapping

System bootstrapping follows the same flow as normal onboarding. The first
operator spins up the DKG, registers their device (e.g. a phone) as a
candidate, then performs the admin-link to create the first identity with admin
privileges. No special bootstrapping path is needed.

## Screen Inventory

Nine screens organized into three groups.

### Group 1: Identity & Devices (self-service)

#### Screen 1 - My Devices

The user's view of the devices linked to their identity.

**Content:**
- List of linked devices, each showing:
  - Device name (user-editable label)
  - Device type (phone, YubiKey, browser, computer)
  - Public key fingerprint (truncated, expandable)
  - Last authenticated timestamp
- Add device action: presents a list of candidate devices owned by the user
  (filtered by some out-of-band association, e.g. a pairing code or QR scan)
  and links the selected candidate to this identity.
- Remove device action: unlinks a device from this identity. The device returns
  to the candidate pool or is deregistered entirely.
- Rename action: edit the human-readable device label.

**Access:** Any authenticated device on the identity. Adding or removing a
device is a unilateral action from any single authenticated device.

**Flows:**
- My Devices -> add -> candidate selection -> confirm -> device linked
- My Devices -> remove -> confirm -> device unlinked
- My Devices -> rename -> edit label -> save

---

#### Screen 2 - My Identity

A read-mostly overview of the user's DKG identity and its place in the system.

**Content:**
- DKG identity (BLS12-381 `did:key`)
- Compartments and rings this identity belongs to
- Roles held (e.g. admin, member) per compartment
- Count of linked devices (link to My Devices screen)

**Access:** Any authenticated device on the identity. This screen is
informational. Actions like leaving a compartment may be added later but are out
of scope for the initial build.

---

### Group 2: Admin (provisioning & permissions)

#### Screen 3 - Candidate Devices

Admin view of the pool of unlinked devices waiting to be assigned to identities.

**Content:**
- List of candidate devices, each showing:
  - Public key fingerprint
  - Device type (if self-reported during registration)
  - Registration timestamp
  - Pairing metadata (e.g. pairing code used during registration)
- Link action: assign a candidate device to an identity. Opens a picker to
  select an existing identity or create a new one inline.
- Reject action: remove a candidate from the pool (e.g. unrecognized device).

**Access:** Admin role only.

**Flows:**
- Candidate Devices -> select candidate -> link to existing identity -> confirm
  -> device linked, removed from candidate pool
- Candidate Devices -> select candidate -> create new identity -> provide
  identity details -> confirm -> identity created, device linked
- Candidate Devices -> reject -> confirm -> candidate removed

---

#### Screen 4 - Identity Directory

Admin view of all identities in the system.

**Content:**
- List of identities, each showing:
  - Human-readable name or label
  - DKG identity (`did:key`)
  - Number of linked devices
  - Roles and compartments
  - Created timestamp
- Create identity action: create a new DKG identity (can optionally link a
  candidate device in the same flow).
- View/edit action: drill into an identity to see its devices, roles, and
  permissions.

**Access:** Admin role only.

**Flows:**
- Identity Directory -> create -> provide details -> optionally link candidate
  device -> confirm -> identity created
- Identity Directory -> select identity -> view details -> edit roles /
  compartments

---

#### Screen 5 - Permission Management

Admin view for managing Zanzibar-style access control relations.

**Content:**
- Table of relation tuples: (identity, role, resource). Human-readable
  rendering of the Zanzibar relations, e.g. "Alice is an editor of Document X".
- Filterable by identity, role, or resource.
- Grant action: create a new relation tuple. Select identity, role, and
  resource.
- Revoke action: remove an existing relation tuple.

**Access:** Admin role only. Permissions are binary (on/off) with no scoping or
expiry in the initial build.

**Flows:**
- Permission Management -> grant -> select identity -> select role -> select
  resource -> confirm -> relation created
- Permission Management -> select relation -> revoke -> confirm -> relation
  removed

---

### Group 3: Approval Inbox (policy signing queue)

The approval inbox is a general-purpose policy signing queue. Any identity in
the system can submit a request to any other identity. Requests appear in the
target identity's inbox and require an explicit approve or reject action, which
produces a signed transaction.

#### Screen 6 - Inbox

The user's queue of pending requests.

**Content:**
- List of pending requests, each showing:
  - Requesting identity (name + `did:key` fingerprint)
  - Request type (access grant, delegation, policy change)
  - Target resource or scope
  - Submitted timestamp
  - Status badge (pending)
- Tapping a request navigates to the Request Detail screen.

**Access:** Any authenticated device on the identity that the request is
addressed to.

---

#### Screen 7 - Request Detail

Expanded view of a single request for review and decision.

**Content:**
- Full details of the requesting identity
- The policy or access being requested, rendered in human-readable form (e.g.
  "Agent X is requesting read access to Collection Y")
- The raw policy object (expandable, for power users)
- Approve action: signs the policy and submits the signed transaction
- Reject action: signs a rejection and submits

**Access:** Any authenticated device on the target identity.

**Flows:**
- Request Detail -> approve -> sign -> transaction submitted -> request moves
  to history
- Request Detail -> reject -> sign -> transaction submitted -> request moves to
  history

---

#### Screen 8 - Request History

Audit log of past request decisions.

**Content:**
- List of resolved requests, each showing:
  - Requesting identity
  - Request type and resource
  - Decision (approved / rejected)
  - Decided timestamp
  - Which device signed the decision
- Filterable by decision type, identity, and date range.

**Access:** Any authenticated device on the identity.

---

#### Screen 9 - Request Access

The "ask" side of the approval flow. Allows an identity to compose and submit a
request to another identity.

**Content:**
- Target identity picker (search/browse the identity directory)
- Request type selector (access grant, delegation, etc.)
- Resource selector (browse available resources)
- Role or permission level to request
- Optional message or justification field
- Submit action: creates the request, which appears in the target identity's
  inbox

**Access:** Any authenticated identity in the system.

**Flows:**
- Request Access -> select target identity -> select request type -> select
  resource -> select role -> submit -> request created in target's inbox

---

## Flow Diagrams

### Device Onboarding Flow

```
New Device                     Admin                        System
    |                            |                            |
    |-- register as candidate -->|                            |
    |                            |                            |
    |                            |-- view candidate pool ---->|
    |                            |                            |
    |                            |-- link to identity ------->|
    |                            |                            |
    |<------------ device is now linked, can authenticate --->|
```

### Bootstrapping Flow

```
First Operator Device          System (fresh)
    |                            |
    |-- register as candidate -->|  (candidate pool: 1 device)
    |                            |
    |-- admin-link self -------->|  (creates first identity
    |                            |   with admin role,
    |                            |   links this device)
    |                            |
    |<-- authenticated as admin -|
```

### Approval Request Flow

```
Requester                      System                       Target Identity
    |                            |                            |
    |-- compose request -------->|                            |
    |   (Screen 9)               |                            |
    |                            |-- request appears -------->|
    |                            |   in inbox (Screen 6)      |
    |                            |                            |
    |                            |          review (Screen 7) |
    |                            |                            |
    |                            |<-- signed approval/reject -|
    |                            |                            |
    |<-- outcome visible --------|-- recorded in history ---->|
    |                            |   (Screen 8)               |
```

### Agent Delegation Flow

```
User                Agent               System              User's Inbox
  |                   |                   |                     |
  |-- "do X, Y, Z" ->|                   |                     |
  |                   |                   |                     |
  |                   |-- compose policy  |                     |
  |                   |   for X, Y, Z --->|                     |
  |                   |                   |-- request --------->|
  |                   |                   |                     |
  |                   |                   |     user reviews    |
  |                   |                   |     policy details  |
  |                   |                   |                     |
  |                   |                   |<-- approve (sign) --|
  |                   |                   |                     |
  |                   |<-- delegation     |                     |
  |                   |   now active -----|                     |
  |                   |                   |                     |
  |                   |-- acts within     |                     |
  |                   |   granted scope ->|                     |
```

## Navigation Map

```
+------------------+     +------------------+
| My Devices    [1]|     | My Identity   [2]|
+------------------+     +------------------+

+------------------+     +------------------+     +------------------+
| Candidate     [3]|---->| Identity Dir  [4]|---->| Permissions   [5]|
| Devices          |     |                  |     |                  |
+------------------+     +------------------+     +------------------+

+------------------+     +------------------+     +------------------+
| Inbox         [6]|---->| Request       [7]|     | Request       [9]|
|                  |     | Detail           |     | Access           |
+------------------+     +------------------+     +------------------+
                          |
                          v
                         +------------------+
                         | Request       [8]|
                         | History          |
                         +------------------+
```

Screens 1-2 are available to all authenticated users.
Screens 3-5 are admin-only.
Screens 6-9 are available to all authenticated users.
