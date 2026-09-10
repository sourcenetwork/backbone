# 32-tenant Vera run, 2026-09-03 20:39 UTC

Copy-ready tables from `cargo test --test gents_cloud -- --ignored` with
`GENTS_CLOUD_TENANTS=32`. The rendered version with charts and findings is
`gents-cloud-run-32-tenants.html` in this directory.

13 of 13 scenarios passed in 376.5 s. 223 chain transactions committed, none
failed, over 352 blocks at a 1.06 s interval.

## Consensus timings

The devnet sets these in `crates/sourcehub-harness/src/genesis.rs`. Before, the
harness left CometBFT's shipped values in place, and a block cost 5.03 s.

| Setting | Shipped | Devnet |
|---|---|---|
| `timeout_propose` | 3s | 500ms |
| `timeout_prevote` | 1s | 500ms |
| `timeout_precommit` | 1s | 500ms |
| `timeout_commit` | 5s | 1s |

| Measure | Before | After | Change |
|---|---|---|---|
| Block interval (s) | 5.03 | 1.06 | 4.7x |
| Provision one tenant (ms) | 25167 | 6058 | 4.2x |
| Suite wall time (s) | 1212.5 | 376.5 | 3.2x |
| Signed write p50 (ms) | 4909 | 1483 | 3.3x |
| Stack bring-up (s) | 83.5 | 22.4 | 3.7x |

## Scenarios

| # | Scenario | Discharges | Wall time (s) |
|---|---|---|---|
| 1 | `h1_node_identity_no_privileged_read` | gents-cloud §1.2 row 2 [V], H1 §10.2, I-2, spike S6, readiness C4 | 8.3 |
| 2 | `i26_absence_denial_indistinguishable` | gents-cloud §11.6, I-26, Phase 2 gate | 0.0 |
| 3 | `grant_asymmetry` | gents-cloud §1.6 (asymmetric grant granularity), §11.4 revocation cost | 8.7 |
| 4 | `h5_two_clocks` | gents-cloud §10.5 (H5, two clocks), §1.6 rows 2 and 3, spike S5, Phase 2 gate I-16 | 15.6 |
| 5 | `h12_pre_on_vera` | gents-cloud §10.6 (H12), §1.6 PRE row, open [?] on the shipping backend | 3.3 |
| 6 | `h3_ring_gate_mechanism` | gents-cloud §12.2 (H3), §1.6 row 2, spike S7 [?] on what the ring checks | 0.9 |
| 7 | `l8_ring_below_threshold` | gents-cloud §24 rung L8, §22.4, decision 43 | 34.8 |
| 8 | `s7_signed_write_cost` | gents-cloud §12.3 cost, spike S7, §19.1 'ring round trip: to be measured' | 18.3 |
| 9 | `dry_account` | gents-cloud §1.6 (a cell that cannot write because its account is dry), §1.2 (unregistered means public), §24 | 3.3 |
| 10 | `s8_topic_collision_c1` | gents-cloud §11.7 (A-1, A-2), spike S8, readiness C1, I-30 | 46.9 |
| 11 | `i7_kill9_identity` | gents-cloud I-7, §5.3 'golden kill -9', §17.6 VolumeRestore, §1.2 peerstore row | 3.1 |
| 12 | `afterburner_sealed_packages` | gents-cloud §1.1 (the manifold is the whole permission surface), H4, H11, §26 ban list, I-3 | 0.2 |
| 13 | `scale_per_tenant_cost` | gents-cloud §19.1 density, §20.1 (the workspace is the shard key), §20.6 growth stages | 210.7 |

## Scaling curve

| Tenants | Cell RSS median (MiB) | All cells (MiB) | Read p50 (ms) | Provision p50 (ms) | Cell ignition p50 (ms) |
|---|---|---|---|---|---|
| 8 | 100 | 750 | 6 | 6282 | 311 |
| 16 | 100 | 1505 | 7 | 6101 | 303 |
| 24 | 70 | 1855 | 6 | 6261 | 303 |
| 32 | 71 | 2572 | 6 | 6058 | 300 |

## Provisioning breakdown

| Step | p50 (ms) | Waits on |
|---|---|---|
| Fund the tenant account | 974 | Vera block |
| Create the policy | 1083 | Vera block |
| Register the collection object | 846 | Vera block |
| Grant writer | 1361 | Vera block |
| Ignite the cell | 300 | the process starting |
| Add the schema | 19 | local |
| First ring-signed write | 1384 | ring round trip and a Vera registration |
| **Total** | **6058** | 70% is the four transactions alone |

Each step is the median across 32 tenants, so the parts sum to 5967 ms rather
than exactly to the median total.

## What the chain did

| Message | Count |
|---|---|
| `/vera.acp.MsgDirectPolicyCmd` | 73 |
| `/vera.acp.MsgBearerPolicyCmd` | 69 |
| `/cosmos.bank.v1beta1.MsgSend` | 41 |
| `/vera.acp.MsgCreatePolicy` | 34 |
| `/vera.bulletin.MsgAddCollaborator` | 3 |
| `/vera.bulletin.MsgCreatePost` | 2 |
| `/vera.bulletin.MsgRegisterNamespace` | 1 |
| **Total** | **223** |

| Chain measure | Value |
|---|---|
| Blocks produced | 352 |
| Block interval | 1.06 s |
| Transactions committed | 223 |
| Transactions failed | 0 |
| Gas used | 25,471,721 |
| Gas wanted | 368,516,753 |
| Policies registered | 35 |
| Chain data on disk | 8.8 MiB |

## Component footprint

| Component | Count | Peak resident (MiB) | Each (MiB) |
|---|---|---|---|
| DefraDB cells | 35 | 2846 | 81 |
| Vera (`verad`) | 1 | 218 | 218 |
| Orbis ring | 3 | 139 | 46 |

Maxima over 33 samples taken every 15 seconds.

## Projection to 100,000 tenants

Arithmetic over the measurements above. No 100,000-tenant run happened.

| Projection | Value | Assumption |
|---|---|---|
| Cells per 64 GiB node | 923 | 71 MiB per cell measured, no headroom for a supervisor or a guest |
| Nodes for 100,000 tenants | 109 | one cell per tenant, no replicas |
| Chain transactions to provision | 400,000 | four per tenant |
| Serial provisioning time | 168 h | at the measured p50; a real fleet provisions in parallel |
| Chain storage | 15 GiB | 8.8 MiB per 223 transactions, scaled |

## Every recorded measurement

| Measurement | Value |
|---|---|
| `stack_bring_up_secs` | 22.4 |
| `ring_signed_batch_create_3_docs_ms` | 3949 |
| `i26_forbidden_read_ms` | 15 |
| `i26_absent_read_ms` | 10 |
| `per_document_grant_3_docs_to_vera_visible_ms` | 3650 |
| `grant_read_gate_eager_cell_lag_after_vera_ms` | 0 |
| `revocation_vera_visible_after_submit_ms` | 124 |
| `revocation_read_gate_eager_cell_ms` | 9 |
| `revocation_read_gate_ttl_cell_ms` | 2131 (cache ttl 15s) |
| `revoked_update_response` | `{"data":{"update_Transcript":[]}}` |
| `create_after_collection_writer_revoked` | accepted (no create gate under Vera: DefraDB sends the ring no ACP tuple; G-4 and H3 remain open) |
| `pre_authorised_reader` | refused by the ring despite the Vera relation |
| `ring_sign_with_vera_acp_check_ms` | 54 |
| `ring_signs_without_acp_tuple` | yes (DefraDB's Vera write path sends none) |
| `l8_refusal_latency_ms` | 30022 |
| `l8_ring_recovery_to_first_signed_write_ms` | 4731 |
| `s7_create_p50_ring_signed_ms` | 1483 |
| `s7_create_p50_unsigned_ms` | 769 |
| `s7_ring_round_trip_p50_ms` | 714 (signed minus unsigned over 8 samples; both are dominated by the Vera registration, so a value at or below zero would mean the round trip is not separable at this sample size, not that it is free) |
| `dry_account_leaves_public_document` | yes: 1 document readable by an unrelated DID after the failed registration |
| `s8_shared_collection_topic` | `bafyreibk625p5tcsamse3hqa7nzxuuxyf4277akdwhqdvhzzzqt4x2e4gy` |
| `s8_block_crossed_on_shared_topic` | no: within 45 s, with a peer connection and a subscription but no replicator |
| `c1_registration_is_chain_side` | yes (a replicated document stays registered on Vera, so the receiving cell gates it) |
| `i7_kill9_to_ready_ms` | 1405 |
| `afterburner_sealed_packages` | 4 packages, all sealed; engine 1,476,654 bytes |
| `scale_tenants_provisioned` | 32 |
| `scale_policies_on_vera` | 35 |
| `scale_cell_rss_median_mib` | 71 |
| `scale_read_p50_ms_one_tenant` | 8 |
| `scale_read_p50_ms_all_tenants` | 6 |
| `scale_cross_tenant_reads_denied` | 32 ordered pairs |
| `scale_provision_p50_total_ms` | 6058 |
| `scale_provision_p50_fund_ms` | 974 |
| `scale_provision_p50_policy_ms` | 1083 |
| `scale_provision_p50_register_object_ms` | 846 |
| `scale_provision_p50_grant_writer_ms` | 1361 |
| `scale_provision_p50_cell_ignition_ms` | 300 |
| `scale_provision_p50_schema_ms` | 19 |
| `scale_provision_p50_first_write_ms` | 1384 |
| `scale_provision_p50_chain_share` | 70% of the total is the four Vera transactions waiting for a block |
| `scale_projected_cells_per_64gib_node` | 923 (projected) |
| `scale_projected_nodes_for_100k_tenants` | 109 (projected) |

## Reproduce

| Component | Source |
|---|---|
| Vera | `sourcenetwork/vera` main @ ddcb612, binary `verad` |
| DefraDB | defradb.rs `vclq/vera-compat` (PR 1681) |
| Orbis | orbis-rs `vclq/vera-compat` (PR 264) |
| Suite | backbone `vclq/gents-cloud-vera` (PR 30) |

```
GENTS_CLOUD_TENANTS=32 cargo test --test gents_cloud -- --ignored --nocapture
```

Binaries resolve from `VERA_BINARY`, `DEFRA_BINARY`, `ORBIS_BINARY` and
`ORBIS_CLI_BINARY`, or from the pins in `backbone.toml`.
