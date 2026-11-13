# ACP light client

The client verifies native Vera records and permission evidence against a consensus
key provisioned by the operator. It uses `vera_getCurrentRecordProof` for policy
and persisted access-decision records, `vera_getCurrentPolicyPrefixProof` for
ownership and relationship reads, and `vera_getCurrentPermissionProof` for
permission evaluation. Each response pairs the evidence with its certified revision.
Ownership and relationships require a live policy, matching relation generations and
current target-object incarnation at that same revision. Keys use
`relationship/v5/{policy}/{target:016x}/{subject:016x}/` followed by the canonical
`v3` suffix containing the incarnation. Specialized proofs require an `objects`
array of same-root object-state witnesses for non-owner rows; authenticated absence
means initial incarnation zero, while a missing witness is an error. Owner rows use
incarnation zero and need no object witness. Retained cleanup records cannot restore
a grant after relation recreation or object unarchiving. Older namespaces and proof
shapes are rejected; this fresh-state cutover has no backfill. HTTP responses and
header messages are bounded before deserialization.

The pinned verifier accepts up to 256 operations per revision while retaining
the shared encoded-byte limits. Applications pinned to the older 64-operation
verifier must update before connecting to nodes that produce larger revisions.

Each request requires at least the latest verified height. A newer certified response
can advance the client's tracked revision ahead of its header subscription. Delayed
headers cannot move that state backward; repeated certificates cannot renew its
monotonic freshness lifetime. A delayed response at a superseded root is rejected.
Cached records are usable only at the same module root and within the configured
height and revision-age bounds. Ownership, relationships and permission results are
evaluated from fetched evidence; physical record cache entries do not establish
policy, generation or incarnation liveness.

`read_relationship` and `cache::keys::relationship_key` require an explicit shared
`RelationPair`. Derive its identities from the current authenticated policy catalogue;
do not use `(0, 0)` for arbitrary relations. The owner helper selects the permanent
owner pair and incarnation zero. Non-owner suffixes require the authenticated current
object incarnation. A retained inactive exact key is an error, while certified absence is
returned as `None`; neither authorizes access.

`read_policy`, `read_relationship` and `read_access_decision` return authenticated
record data, not an authorization decision. `verify_access` evaluates the full
request with the shared ACP evaluator. `verify_access_decision` checks a persisted
successful decision against its exact submission and expiry; it does not establish
permission after subsequent revocation or authorize a payload by itself.

The default freshness policy permits revisions less than 30 seconds old and at most
15 seconds in the future. Transport operations have a ten-second deadline. A caller
may configure stricter age and clock-skew bounds. Arbitrary historical native record
reads are not provided.

Header synchronization uses `vera_subscribeHeaders` and accepts `vera_header`
notifications only for the acknowledged subscription ID. The acknowledgement
must arrive within ten seconds. Notifications still require independent finality
verification before they can advance cached state.

## Native dependency set

This workspace uses the published Vera 0.1.2 crates and the released Commonware
2026.10.0 crates. Tests that need Vera's unpublished node crates pin the Vera
0.1.2 release commit, `a9ce2e431d6f43786f94946dfc5c8a3405a9a8f6`; the root
manifest's patch section resolves that revision's published crates to the
crates.io packages, so each is built once. The selected Vera version must match
the node and proof-verifier deployment. The Defra and Orbis integration fixture
revisions are recorded separately in `backbone.toml`.
