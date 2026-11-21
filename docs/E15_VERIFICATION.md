# E15 — executable local verification report

**Base main:** `3ce3c4cb2778b4c347f0e8aa8ce096612dd6e8ea`.
**Environment:** Linux x86_64, Python 3.13.5, cryptography 46.0.4.
**RED:** new tests could not import `atlas.reed_solomon` or `atlas.erasure_archive`; benchmark contract similarly failed before implementation.
**GREEN:** coding matrix/inverse tests, all loss combinations for 4+2 and 8+3, seeded random data, source/manifest authentication, actual CAS writes/readback and no-overwrite restore, 11-store 8+3 recovery and repair, actual CLI child-process E2E, uncertain ledger holds after ambiguous write.
**Source upstream:** E14 `secure_fabric.py` Git blob c55c5c081c75b679aa88727d582dc4d9216a3507; E12 `provider_registry.py` e5c971a9df9b068a5e25f748c7ed9bd4e2b7358b; E13 `quota_ledger.py` 0bdeb9ffd3bc6807811bec604f33a6b46197a3e3. Exact recovered source subset, not a complete checkout.
**Commands executed:**

```bash
python -m unittest discover -s tests -v
python -m compileall -q atlas tools tests
python -m tools.bench_erasure --bytes 1048576 --repeats 3 --seed 20261121
```

**Test output:**

```text
test_cli_ingest_restore_1mib_three_chunks_and_no_overwrite (test_e14_cli_roundtrip.CLIRoundtrip.test_cli_ingest_restore_1mib_three_chunks_and_no_overwrite) ... ok
test_reject_invalid_types_with_safely_verified_mac (test_e14_manifest_hardening.ManifestInputTypes.test_reject_invalid_types_with_safely_verified_mac) ... ok
test_special_and_world_readable_manifest_refused (test_e14_manifest_hardening.ManifestInputTypes.test_special_and_world_readable_manifest_refused) ... ok
test_valid_manifest_unaffected (test_e14_manifest_hardening.ManifestInputTypes.test_valid_manifest_unaffected) ... ok
test_valid_signed_manifest_via_symlink_is_refused (test_e14_manifest_hardening.ManifestInputTypes.test_valid_signed_manifest_via_symlink_is_refused) ... ok
test_both_profiles_real_disk_recovery_at_parity_limit (test_erasure_archive.ErasureArchiveTests.test_both_profiles_real_disk_recovery_at_parity_limit) ... ok
test_corrupted_fragment_treated_as_erasure (test_erasure_archive.ErasureArchiveTests.test_corrupted_fragment_treated_as_erasure) ... ok
test_more_losses_than_parity_refused_and_no_output (test_erasure_archive.ErasureArchiveTests.test_more_losses_than_parity_refused_and_no_output) ... ok
test_no_double_registration_and_no_duplicate_domains (test_erasure_archive.ErasureArchiveTests.test_no_double_registration_and_no_duplicate_domains) ... ok
test_no_overwrite_and_ciphertext_shards (test_erasure_archive.ErasureArchiveTests.test_no_overwrite_and_ciphertext_shards) ... ok
test_quota_exhaustion_blocks_writes (test_erasure_archive.ErasureArchiveTests.test_quota_exhaustion_blocks_writes) ... ok
test_wrong_key_and_manifest_tamper_refused (test_erasure_archive.ErasureArchiveTests.test_wrong_key_and_manifest_tamper_refused) ... ok
test_real_encode_decode_bench_reports_bytes_and_validation (test_erasure_bench.BenchContractTests.test_real_encode_decode_bench_reports_bytes_and_validation) ... ok
test_actual_storage_overhead_less_than_two_copies (test_erasure_code.CauchyErasureProperties.test_actual_storage_overhead_less_than_two_copies) ... ok
test_adaptive_profile_only_when_domains_suffice (test_erasure_code.CauchyErasureProperties.test_adaptive_profile_only_when_domains_suffice) ... ok
test_all_erasure_patterns_at_limit (test_erasure_code.CauchyErasureProperties.test_all_erasure_patterns_at_limit) ... ok
test_corruption_in_surviving_shard_detected_with_redundancy (test_erasure_code.CauchyErasureProperties.test_corruption_in_surviving_shard_detected_with_redundancy) ... ok
test_invalid_profiles_and_shard_indices (test_erasure_code.CauchyErasureProperties.test_invalid_profiles_and_shard_indices) ... ok
test_missing_beyond_parity_fails_closed (test_erasure_code.CauchyErasureProperties.test_missing_beyond_parity_fails_closed) ... ok
test_seeded_random_erasures_and_byte_lengths (test_erasure_code.CauchyErasureProperties.test_seeded_random_erasures_and_byte_lengths) ... ok
test_cli_ingest_restore_repair_and_pinned_manifest (test_erasure_operational.ErasureOperations.test_cli_ingest_restore_repair_and_pinned_manifest) ... ok
test_uncertain_quota_after_ambiguous_partial_write (test_erasure_operational.ErasureOperations.test_uncertain_quota_after_ambiguous_partial_write) ... ok
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
Ran 70 tests in 31.152s

OK
```

**Measured benchmark output (not extrapolated to target hardware):**

```json
{
  "case_bytes": 1048576,
  "note": "Offline synthetic CPU codec only; not network, disk, Android or cloud.",
  "platform": "Linux-6.18.57-x86_64-with-glibc2.41",
  "profiles": [
    {
      "data_shards": 4,
      "encode_ms_median": 3.9113,
      "encode_ms_runs": [
        3.9113,
        7.5236,
        3.6431
      ],
      "encoded_bytes": 1572864,
      "parity_shards": 2,
      "profile": "4+2",
      "recover_ms_median": 10.1884,
      "recover_ms_runs": [
        10.1884,
        11.6328,
        7.9486
      ],
      "savings_relative_to_two_copies_fraction": 0.25,
      "sha256_verified": true,
      "two_copy_bytes": 2097152
    },
    {
      "data_shards": 8,
      "encode_ms_median": 5.9824,
      "encode_ms_runs": [
        8.171,
        5.5285,
        5.9824
      ],
      "encoded_bytes": 1441792,
      "parity_shards": 3,
      "profile": "8+3",
      "recover_ms_median": 12.1095,
      "recover_ms_runs": [
        13.1315,
        12.1095,
        11.7248
      ],
      "savings_relative_to_two_copies_fraction": 0.3125,
      "sha256_verified": true,
      "two_copy_bytes": 2097152
    }
  ],
  "python": "3.13.5",
  "repeat_count": 3,
  "schema": "omega.rs-bench.v1",
  "seed": 20261121
}
```

**Exact local Git blobs (`git hash-object`):**

```text
32545e652c5069d3281d8f481a2574eca64f74ef  atlas/reed_solomon.py
c9478ae656f4eed7f098a7e2cec960bc0fb91c91  atlas/erasure_archive.py
dd54bb6ad7cc83b3e5f660f80a0af9045aca61e9  tests/test_erasure_code.py
1dfeead7cd5d3a8867a6763a3f1ce8fb2a71470e  tests/test_erasure_archive.py
8fef670f79d38be6ed7667d551137b67bcf86cc8  tests/test_erasure_operational.py
609b97da42317e8f0930d132ba6ae7072dd819b5  tests/test_erasure_bench.py
1660dbdc67b272fc91b8845541bab49cd66c782e  tools/bench_erasure.py
8dd82b0f2e4fb7780e22eb1120e4439bb1f29e60  docs/E15_ERASURE.md
```

**Release gates:** GATE-01/02/03/04/08 PASS_LOCAL, GATE-06 PARTIAL,
GATE-05/07/09 BLOCKED. GATE-09 cannot pass without real cross-provider and
cross-host fault isolation, actual transfer limits/cost controls, live recovery
and SMB protocol qualification. `git clone` of full Server repository is
DNS-blocked in this environment, thus full-repository regression NOT_RUN.
No GitHub Actions, YepCode, S24 Ultra, production WAN or vendor account tests.
