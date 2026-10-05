# ACP light client

The client verifies native Vera records and permission evidence against a consensus
key provisioned by the operator. It uses `vera_getCurrentRecordProof` for policy
and persisted access-decision records, `vera_getCurrentPolicyPrefixProof` for
ownership and relationship reads, and `vera_getCurrentPermissionProof` for
permission evaluation. Each response pairs the evidence with its certified revision.
Ownership and relationships require policy liveness at that same revision; retained
cleanup records under `relationship/v3/` do not establish current ownership or a
current relationship after policy deletion. HTTP responses and header messages are
bounded before deserialization.

The pinned verifier accepts up to 256 operations per revision while retaining
the shared encoded-byte limits. Applications pinned to the older 64-operation
verifier must update before connecting to nodes that produce larger revisions.

Each request requires at least the latest verified height. A newer certified response
can advance the client's tracked revision ahead of its header subscription. Delayed
headers cannot move that state backward; repeated certificates cannot renew its
monotonic freshness lifetime. A delayed response at a superseded root is rejected.
Cached records are usable only at the same module root and within the configured
height and revision-age bounds. Ownership, relationships and permission results are
evaluated from fetched evidence; physical record cache entries do not establish policy liveness.

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

This workspace pins Vera to `2536670fa4a900f211295cd14ce1ad12c2758f13`
and its Commonware fork to `d0cef38586581911ddbeb3060ea6b0d7e33d2a98`.
Both revisions must match the node and proof-verifier deployment.

Cargo does not inherit dependency patches from a dependency's workspace. A
consumer of this crate must carry this workspace's Commonware `[patch.crates-io]`
entries in its own root manifest. Keep all entries on the same revision, retain
the lockfile, and use `--frozen` for validation. Otherwise the released Commonware
API can be selected alongside Vera's fork-dependent code.
