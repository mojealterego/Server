# E14 — OMEGA HYPER CAS verification on pinned upstream main

**Baseline:** `7454e43bd085257824767d48c5c3dee6bb8f4b26`, only branch `main`.
**Platform:** Linux-6.18.57-x86_64-with-glibc2.41, Python 3.13.5, cryptography 46.0.4.
**Source subset:** exact released E12/E13 code (`provider_registry.py` Git blob `e5c971a9df9b068a5e25f748c7ed9bd4e2b7358b`; `quota_ledger.py` Git blob `0bdeb9ffd3bc6807811bec604f33a6b46197a3e3`) plus E14 code below.

## Commands

```bash
python -m unittest discover -s tests -v
python -m compileall -q atlas tests
python -m unittest tests.test_e14_cli_roundtrip -v
```

The last CLI test launches actual child processes for `ingest`/`restore` on two private local directories, checks SHA-256 and refuses overwrite. Rclone tests launch a **controlled fake Rclone executable**, not a real vendor API. E12 tests use config fixtures; E13 tests run true SQLite transaction/concurrency cases.

## TDD evidence

- **RED:** seven wrong-typed, authenticated manifest fields produced seven unexpected `TypeError` errors in `test_e14_manifest_hardening`.
- **GREEN:** rejected by controlled `SecureError`, valid manifest accepted.
- **RED:** a symlink to a valid signed manifest could be followed and restored without rejection.
- **GREEN:** manifest reader now refuses symlinks, FIFOs and files with overly broad permissions; no blocking on special files; final suite passing.

## Test runner output

```text
test_cli_ingest_restore_1mib_three_chunks_and_no_overwrite (test_e14_cli_roundtrip.CLIRoundtrip.test_cli_ingest_restore_1mib_three_chunks_and_no_overwrite) ... ok
test_reject_invalid_types_with_safely_verified_mac (test_e14_manifest_hardening.ManifestInputTypes.test_reject_invalid_types_with_safely_verified_mac) ... ok
test_special_and_world_readable_manifest_refused (test_e14_manifest_hardening.ManifestInputTypes.test_special_and_world_readable_manifest_refused) ... ok
test_valid_manifest_unaffected (test_e14_manifest_hardening.ManifestInputTypes.test_valid_manifest_unaffected) ... ok
test_valid_signed_manifest_via_symlink_is_refused (test_e14_manifest_hardening.ManifestInputTypes.test_valid_signed_manifest_via_symlink_is_refused) ... ok
test_alias_and_account_duplication_denied (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_alias_and_account_duplication_denied) ... ok
test_injected_environment_backend_denied (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_injected_environment_backend_denied) ... ok
test_no_attestation_stops_before_subprocess (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_no_attestation_stops_before_subprocess) ... ok
test_registry_pin_detects_tampering (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_registry_pin_detects_tampering) ... ok
test_terabox_is_not_automatically_admitted (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_terabox_is_not_automatically_admitted) ... ok
test_valid_enrollment_is_readonly (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_valid_enrollment_is_readonly) ... ok
test_wrong_backend_identity_denied (test_provider_enrollment_gate.ProviderEnrollmentGateTests.test_wrong_backend_identity_denied) ... ok
test_wrong_s3_endpoint_cannot_be_admitted_as_cloudflare (test_provider_registry.CloudflareBindingTests.test_wrong_s3_endpoint_cannot_be_admitted_as_cloudflare) ... ok
test_config_permission_and_env_overrides (test_provider_registry.ProviderRegistryTests.test_config_permission_and_env_overrides) ... ok
test_duplicate_json_keys_rejected (test_provider_registry.ProviderRegistryTests.test_duplicate_json_keys_rejected) ... ok
test_fake_rclone_deadline_and_output_limit (test_provider_registry.ProviderRegistryTests.test_fake_rclone_deadline_and_output_limit) ... ok
test_no_account_free_tier_attestation_means_no_probe (test_provider_registry.ProviderRegistryTests.test_no_account_free_tier_attestation_means_no_probe) ... ok
test_rejects_duplicate_account_and_alias (test_provider_registry.ProviderRegistryTests.test_rejects_duplicate_account_and_alias) ... ok
test_rejects_stale_attestation (test_provider_registry.ProviderRegistryTests.test_rejects_stale_attestation) ... ok
test_tampered_registry_refused (test_provider_registry.ProviderRegistryTests.test_tampered_registry_refused) ... ok
test_tbox_not_implicitly_admitted (test_provider_registry.ProviderRegistryTests.test_tbox_not_implicitly_admitted) ... ok
test_valid_read_only_enrollment (test_provider_registry.ProviderRegistryTests.test_valid_read_only_enrollment) ... ok
test_wrong_backend_fails_closed (test_provider_registry.ProviderRegistryTests.test_wrong_backend_fails_closed) ... ok
test_renewal_survives_restart_and_blocks_old_epoch (test_quota_ledger.LedgerRenewalTests.test_renewal_survives_restart_and_blocks_old_epoch) ... ok
test_clock_rollback_rejected (test_quota_ledger.LedgerTests.test_clock_rollback_rejected) ... ok
test_durable_restart_idempotency_and_reuse_guard (test_quota_ledger.LedgerTests.test_durable_restart_idempotency_and_reuse_guard) ... ok
test_expired_unknown_holds_quota_until_reconcile (test_quota_ledger.LedgerTests.test_expired_unknown_holds_quota_until_reconcile) ... ok
test_failed_reservation_is_atomic (test_quota_ledger.LedgerTests.test_failed_reservation_is_atomic) ... ok
test_fencing_rejects_old_owner (test_quota_ledger.LedgerTests.test_fencing_rejects_old_owner) ... ok
test_invalid_parent_permissions_rejected (test_quota_ledger.LedgerTests.test_invalid_parent_permissions_rejected) ... ok
test_parallel_reservation_does_not_overbook (test_quota_ledger.LedgerTests.test_parallel_reservation_does_not_overbook) ... ok
test_safe_release_only_before_write (test_quota_ledger.LedgerTests.test_safe_release_only_before_write) ... ok
test_uncertain_reconciliation_committed_debits_once (test_quota_ledger.LedgerTests.test_uncertain_reconciliation_committed_debits_once) ... ok
test_backend_drift_blocks_even_with_operator_flags (test_remote_fabric.RemoteFabricFixtureTests.test_backend_drift_blocks_even_with_operator_flags) ... ok
test_failed_remote_copy_quarantines_budget (test_remote_fabric.RemoteFabricFixtureTests.test_failed_remote_copy_quarantines_budget) ... ok
test_real_subprocess_encrypted_upload_readback_and_restore (test_remote_fabric.RemoteFabricFixtureTests.test_real_subprocess_encrypted_upload_readback_and_restore) ... ok
test_remote_write_requires_explicit_opt_in (test_remote_fabric.RemoteFabricFixtureTests.test_remote_write_requires_explicit_opt_in) ... ok
test_all_replicas_lost_refuses_publication (test_secure_fabric.EncryptedArchiveTests.test_all_replicas_lost_refuses_publication) ... ok
test_ciphertext_mutation_fails_over (test_secure_fabric.EncryptedArchiveTests.test_ciphertext_mutation_fails_over) ... ok
test_crash_after_first_put_keeps_conservative_holds (test_secure_fabric.EncryptedArchiveTests.test_crash_after_first_put_keeps_conservative_holds) ... ok
test_encrypted_readback_and_verified_restore (test_secure_fabric.EncryptedArchiveTests.test_encrypted_readback_and_verified_restore) ... ok
test_existing_destination_preserved (test_secure_fabric.EncryptedArchiveTests.test_existing_destination_preserved) ... ok
test_hmac_tamper_even_with_rehashed_manifest (test_secure_fabric.EncryptedArchiveTests.test_hmac_tamper_even_with_rehashed_manifest) ... ok
test_nonce_unique_and_wrong_aad (test_secure_fabric.EncryptedArchiveTests.test_nonce_unique_and_wrong_aad) ... ok
test_quota_insufficiency_prevents_any_write (test_secure_fabric.EncryptedArchiveTests.test_quota_insufficiency_prevents_any_write) ... ok
test_replay_reservation_does_not_publish_new_version (test_secure_fabric.EncryptedArchiveTests.test_replay_reservation_does_not_publish_new_version) ... ok
test_two_domains_enforced_and_quota_check (test_secure_fabric.EncryptedArchiveTests.test_two_domains_enforced_and_quota_check) ... ok
test_wrong_key_fails_closed (test_secure_fabric.EncryptedArchiveTests.test_wrong_key_fails_closed) ... ok
test_key_permissions_and_duplicate_manifest_rejected (test_secure_fabric.SecurityBoundaryTests.test_key_permissions_and_duplicate_manifest_rejected) ... ok
test_stores_require_distinct_operator_failure_domains (test_secure_fabric.SecurityBoundaryTests.test_stores_require_distinct_operator_failure_domains) ... ok
test_many_malformed_authentication_tamper_cases (test_security_invariants.SecurityInvariants.test_many_malformed_authentication_tamper_cases) ... ok
test_no_symlink_source_and_no_overwrite (test_security_invariants.SecurityInvariants.test_no_symlink_source_and_no_overwrite) ... ok
test_seeded_quota_history_never_overbooks (test_security_invariants.SecurityInvariants.test_seeded_quota_history_never_overbooks) ... ok

----------------------------------------------------------------------
Ran 53 tests in 22.497s

OK
```

## Source Git blob objects (checked locally with git hash-object)

```
c55c5c081c75b679aa88727d582dc4d9216a3507  atlas/secure_fabric.py
02089ca34159a9a05166af4e4732f42937e982eb  tests/test_secure_fabric.py
cb0815a65edd85d8b8618ea3ef9696ddf5e2b1b8  tests/test_remote_fabric.py
ff35bf4ef77cf062606b657a40cbfb680abd53ad  tests/test_security_invariants.py
5948b7308bd0609780eb16b77b9aa4273d2f326a  tests/test_e14_manifest_hardening.py
7aa1aec7321ccfe50a1b06eeadcdf30ee3446c2d  tests/test_e14_cli_roundtrip.py
c0c0e9a3c3c98878195c25671c44dde9bd7492f9  tests/test_provider_registry.py
4a2d3c55627ac27317db3ac4e751d72920ae66ee  docs/E14_STORAGE.md
```

## Release-gate decision

| Gate | Status | Evidence / blocker |
|---|---|---|
| GATE-01 | PASS_LOCAL | E14 encrypted archive requirements and source/test mapping |
| GATE-02 | PASS_LOCAL | E12/E13 contract reuse, independent manifest validation |
| GATE-03 | PASS_LOCAL | AES-GCM, HMAC, CAS, readback, restore and adapter implemented |
| GATE-04 | PASS_LOCAL | 53/53 recovered-subset unit/integration/seeded tests |
| GATE-05 | BLOCKED | No live independent provider accounts, SMB E2E or multi-host quorum |
| GATE-06 | PARTIAL | Local tamper, filesystem, budget and failure tests; no live hostile cloud drills |
| GATE-07 | BLOCKED | No physical cross-host failure and recovery evidence |
| GATE-08 | PASS_LOCAL | Code, docs, test transcript, blob SHA and Roadmap |
| GATE-09 | BLOCKED | Production qualification depends on external gates above |

**No real hardware, real cloud, cost-free billing guarantee or deployed service claim.** Clone of the full Server repo is blocked locally by GitHub DNS, so full-repository regression is NOT_RUN. GitHub Actions and YepCode were not used.
