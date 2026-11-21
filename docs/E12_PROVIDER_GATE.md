# E12 - operator-pinned free provider enrollment (local increment)

Source: `atlas/provider_registry.py`. Purpose: bounded, read-only Rclone backend and quota probe under an operator-pinned registry; no cloud credentials, writes or OAuth grants are provisioned.

Local verification on Python 3.13.5: `python3 -W error::ResourceWarning -m unittest -q tests.test_provider_enrollment_gate` ran **7 tests**, all passed. The isolated working set including the pending E13/E14 patch ran 48 tests; this does **not** establish the repository-wide suite. The Rclone binary was emulated locally; no real provider, SMB network, Android or payment entitlement was exercised.

Controls: stable provider/account ID; no shared-quota double counting; exact backend and Cloudflare R2 HTTPS endpoint; private `rclone.conf`; deny RCLONE_* overrides; fail closed on unknown quotas, stale operator attestations or missing opt-in. TeraBox is not enrolled and remains `BLOCKED_OFFICIAL_OAUTH`.

CLI (read-only):
```bash
python3 -m atlas.provider_registry --registry /private/providers.json --registry-sha256 "$TRUSTED_SHA256" --config /private/rclone.conf
```

No guarantee of free transfers or billing limits follows from a successful quota probe. The operator must separately verify provider terms, credentials and costs. E12 physical/external acceptance remains **BLOCKED**. E13 and E14 are prepared in a separate verified patch archive, but not merged. E15 remains OPEN.

Base `aacf69533553cd8a3e2a21556325372275fd0ec6`. The current local tests do not certify full GATE-09.
