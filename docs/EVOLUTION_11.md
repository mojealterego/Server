# OMEGA-X — eleven implemented engineering increments and next evolution

Baseline: 9b732af3763416c3a02798b2e88d08f94559f8ba. Scope: compute v5.5b and STORAGE-07a. Local PASS is not GATE-09 for the entire server. Previous HA, STORAGE-06, deployment and physical gates remain open.

## E01-E11: implemented, local acceptance PASS

| ID | Scope | Evidence |
|---|---|---|
| E01 | Bounded offline workload candidate generation | test_better_candidate_is_certified_against_original_inputs; test_determinism_and_budget_and_coverage |
| E02 | Independent PHASESHIFT validation of original certificate and candidate | test_better_candidate_is_certified_against_original_inputs; seeded upstream properties |
| E03 | Pinned task/node profiles, freshness, nearest-rank p95 | test_model_and_input_binding; test_stale_baseline_profile_fails_closed; test_nearest_rank_tail_penalty |
| E04 | Improvement threshold, privacy, preserved N-1 coverage | test_threshold_and_no_improvement_keep_baseline; test_private_task_never_migrates |
| E05 | Filesystem and remote quota read-only probes | test_10_local_probe_reports_real_mount; RemoteQuotaTests |
| E06 | Shared quota deduplication and inventory validation | test_01_duplicate_account_pool_rejected; test_11_strict_types_and_oversize |
| E07 | Authorization, zero-cost policy, read/write/block budgets and freshness | test_02_conservative_capacity_and_budgets; test_03_no_paid_or_unauthorized_pool; test_04_stale_or_future_telemetry_excluded; test_08_logical_operation_budget_enforced |
| E08 | Failure-domain capacity bound and deterministic chunk placement | test_05_same_domain_cannot_claim_two_copies; test_06_planner_stripes_and_never_exceeds_budget; test_order_independent_placement |
| E09 | Independent placement feasibility and policy version verification | test_07_independent_verifier_rejects_tampering; test_09_stale_plan_not_reused |
| E10 | Local CAS write/readback, deduplication and live free-space checks | test_real_roundtrip_and_deduplicated_blocks; test_real_two_mounts_and_restore_when_one_missing; test_real_free_space_guard |
| E11 | Pinned offline restore, corruption fallback and no-overwrite publication | test_corrupt_replica_fails_over; test_corrupt_only_replica_never_publishes; test_wrong_pin_or_existing_destination; test_manifest_no_overwrite |

These are eleven tested scopes, not eleven fully qualified releases. See reports/evolution-11-verification.txt.

## E12-E22: OPEN — next eleven evolution stages

| ID | Milestone | Required acceptance evidence |
|---|---|---|
| E12 | Free-provider capability registry, official TeraBox OAuth and approved Rclone/S3 adapters | Real authorized quota and encrypted round trip for each eligible provider; zero unexpected charges; token rotation and terms review; no session-cookie scraping. |
| E13 | Distributed quota/operation reservations with atomic CAS and fencing | Parallel admission cannot overbook; idempotency, expiry, crash/recovery and provider reconciliation; alerts are not spend caps. |
| E14 | Encrypted cross-provider chunk fabric | Private encrypted chunks, pinned authenticated manifests, streaming multipart writes, failure rollback, verified independent-provider recovery. |
| E15 | Adaptive erasure coding 4+2/8+3 | Real Reed-Solomon encode/decode/repair, randomized loss up to parity limit; compare bytes/CPU/latency with two copies. |
| E16 | Global namespace and SMB2/3 gateway | Transactional metadata, locking/fsync/rename, ACL; Windows/Android/Linux, huge files, power-loss recovery and one writable authority. |
| E17 | Owned/volunteer edge storage federation | Explicit owner opt-in, quotas, authenticated private mesh, encryption, revocable access, offline resume, real devices and loss of a node. |
| E18 | Source-backed virtual model artifacts | License/revision/SHA pins, reproducible hydration, bounded cache, failure closed on missing upstream; measure saved physical bytes; no private unique data. |
| E19 | Compute/storage locality co-optimization | Signed real measurements, compare p95, energy, transfer and gates; canary promotion and rollback. |
| E20 | Distributed metadata and self-healing | Real etcd quorum, isolated keys, monotonic generation, physical fencing, anti-rollback and cross-host failover; no SQLite over SMB. |
| E21 | Security and ransomware recovery | Immutable generations, separate recovery authority, tenant ACL/quotas, key rotation, attack and restore drills; prove RPO/RTO. |
| E22 | Physical and market qualification | SMB multichannel/SMB3 encryption, independent fault domains, TB workloads and cost model; compare Samba+mergerfs/Rclone and distributed filesystem alternatives. |

Do not claim novelty or superiority without comparative evidence. E12-E15 secure the data plane; E16-E18 make a usable virtual drive; E19-E22 deliver adaptive production infrastructure. Previous unqualified requirements remain.
