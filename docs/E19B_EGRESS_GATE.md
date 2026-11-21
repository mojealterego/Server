# E19b — Zero-Billable-Egress Guard (advisory-only)

This increment complements `atlas.locality_advisor` (E19a) and does not alter E19a, PHASESHIFT, scheduler, SMB, E12 enrollment, or the E13 quota ledger. It filters **existing E19a rankings** against a second, externally pinned, time-bounded operator-declared egress policy. It does not start any transfer, reserve quota, accept cloud charges, or deploy a schedule.

## Input contract

`omega.egress.guard.v1` JSON has exactly `schema`, `profile_sha256`, `max_age_seconds` and `links`. A link has `source`, `target`, `free_bytes`, `billable`, `observed_at`.

Example (replace all numbers/identities after an authorized measurement and tariff review):

```json
{"schema":"omega.egress.guard.v1","profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_age_seconds":300,"links":[{"source":"phone","target":"vps","free_bytes":2097152,"billable":false,"observed_at":1800000000}]}
```

Profile `omega.locality.v1`, E19a advice, and this egress policy must be supplied together. SHA-256 pins must be acquired from a **separate trusted operator channel**, not simply computed from the attacker-controlled files being consumed. A SHA-256 pin is **not a signature or remote attestation**.

```bash
umask 077
python -m atlas.egress_gate \
  --advice /private/e19a-advice.json \
  --profile /private/e19a-profile.json \
  --profile-sha256 "$EXTERNALLY_TRUSTED_PROFILE_PIN" \
  --policy /private/free-egress.json \
  --policy-sha256 "$EXTERNALLY_TRUSTED_EGRESS_PIN" \
  --now 1800000000 > /private/zero-cost-advice.json
```

In production omit `--now` to use the host UTC clock. Input files must be regular, user-owned, 0600, absolute paths, no symlinks, and at most 2 MiB. Duplicate JSON keys and NaN are rejected.

The guard recomputes p95 from **fresh raw runtime samples** and recomputes the original E19a transfer estimate from measured link telemetry before considering a candidate. Absent/stale evidence fails closed. An already present, fresh local SHA-256 replica needs no transfer. A remote destination needs a matching live replica, directional measured link, `billable=false` policy observation, and enough **declared** free bytes to cover that task's input; ties resolve deterministically. Missing routes are excluded. This intentionally reduces candidate count when proof is incomplete.

## Limitations and gates

- **Advisory only**: per-task estimates can each reuse the same free-byte allowance. They are **not** distributed admission, an atomic budget reservation, provider billing guarantee, or a globally feasible workflow. E13 admission/fencing must be used before any physical write/transfer, alongside the existing certified scheduler.
- `billable=false` and `free_bytes` are **operator assertions**. They do not prove actual free-provider eligibility, billable API requests, egress quotas, network access authorization, or content rights. This module cannot make a paid provider free. Read costs, request costs, ingress, metadata and multipart overhead are outside scope.
- The module cross-checks E19a advice with the pinned profile, but does not independently revalidate node hardware trust, tenant identity, resource constraints or PHASESHIFT certificate. Never treat its rankings as access control or activation approval.
- No live S24 Ultra, Samba dialect negotiation, WAN throughput, independent failure-domain tests or provider billing evidence in this increment. **GATE-09: BLOCKED**.

## Evidence

`python -m unittest discover -s tests -v` in an isolated copy containing just `tests/test_egress_gate.py` and `atlas/egress_gate.py`: 15/15 PASS. The regression suite includes negative tampering, expiration, concurrent-looking multi-task budgeting and real Python CLI subprocess invocation. It does not substitute full-repository integration or physical E2E.
