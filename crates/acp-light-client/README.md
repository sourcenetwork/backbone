# ACP light client

The client verifies native Vera records and permission evidence against a consensus
key provisioned by the operator. It uses `hub_getCurrentRecordProof` for policy,
relationship and persisted access-decision records, and
`hub_getCurrentPermissionProof` for permission evaluation. Both responses pair the
evidence with its certified revision. HTTP responses and header messages are bounded
before deserialization.

Each request requires at least the latest verified height. A newer certified response
can advance the client's tracked revision ahead of its header subscription. Delayed
headers cannot move that state backward; repeated certificates cannot renew its
monotonic freshness lifetime. A delayed response at a superseded root is rejected.
Cached records are usable only at the same module root and within the configured
height and revision-age bounds. Permission results are evaluated from fetched evidence.

`read_policy`, `read_relationship` and `read_access_decision` return authenticated
record data, not an authorization decision. `verify_access` evaluates the full
request with the shared ACP evaluator. `verify_access_decision` checks a persisted
successful decision against its exact submission and expiry; it does not establish
permission after subsequent revocation or authorize a payload by itself.

The default freshness policy permits revisions less than 30 seconds old and at most
15 seconds in the future. Transport operations have a ten-second deadline. A caller
may configure stricter age and clock-skew bounds. Arbitrary historical native record
reads are not provided.
