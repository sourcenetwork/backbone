# ACP light client

The client verifies native Vera records and permission evidence against a consensus
key provisioned by the operator. It uses `vera_getCurrentRecordProof` for policy
and persisted access-decision records, `vera_getCurrentPolicyPrefixProof` for
ownership and relationship reads, and `vera_getCurrentPermissionProof` for
permission evaluation. Each response pairs the evidence with its certified revision.
Ownership and relationships require a live policy and matching relation generations
at that same revision. Keys use `relationship/v4/{policy}/{target:016x}/{subject:016x}/`
followed by the canonical relationship suffix. Retained cleanup records cannot restore
a grant after a target or userset relation is removed and recreated. Older relationship
namespaces are rejected; this is a fresh deployment cutover without backfill. HTTP
responses and header messages are bounded before deserialization.

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
policy or generation liveness.

`read_relationship` and `cache::keys::relationship_key` require an explicit shared
`RelationPair`. Derive its identities from the current authenticated policy catalogue;
do not use `(0, 0)` for arbitrary relations. The owner helper selects the permanent
owner pair. A retained inactive exact key is an error, while certified absence is
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

This workspace pins Vera to `fa832ea575fc22c21e235ce7d5f0fc300609e792`
and its Commonware fork to `d0cef38586581911ddbeb3060ea6b0d7e33d2a98`.
Both revisions must match the node and proof-verifier deployment. The Defra and
Orbis integration fixture revisions are recorded separately in `backbone.toml`.

Cargo does not inherit dependency patches from a dependency's workspace. A
consumer of this crate must carry this workspace's Commonware `[patch.crates-io]`
entries in its own root manifest. Keep all entries on the same revision, retain
the lockfile, and use `--frozen` for validation. Otherwise the released Commonware
API can be selected alongside Vera's fork-dependent code.

The Defra and Orbis fixture revisions in `backbone.toml` still await aligned consumer
branches. This crate update alone does not qualify the full native stack.
