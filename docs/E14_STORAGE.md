# OMEGA-X Server: E14 encrypted multi-provider archive (increment)

Base: `7454e43bd085257824767d48c5c3dee6bb8f4b26`; branch: `main`. E12 provider registry and E13 quota ledger were already committed on this branch; this increment adds the E14 encrypted archive only.

E14 connects the existing E12 provider inspection and E13 local quota ledger to an encrypted chunk archive. **They are not three completed production gates.** No cloud credentials are bundled or provisioned. Real cloud transfers, multi-host quota consensus and TeraBox OAuth are OPEN. They do not replace the existing Samba SMB2/SMB3 server or E11 capacity planner.

## Dependencies

- Python 3.13 is the tested host runtime; Python 3.11+ expected where the dependencies support it.
- `cryptography==46.0.4` was used in local testing. Provision the vetted wheel for your platform using your controlled dependency mirror. Do not download arbitrary wheels or put encryption keys in the repository.
- `rclone` is optional for read-only provider inspections and explicit remote object adapters. No arbitrary shell commands or session-cookie scraping.
- SQLite WAL must be hosted on a private LOCAL filesystem. Not SMB, NFS or a cross-host shared mount. Filesystem and parent should be owned by a dedicated service identity (0700 directory, 0600 files). Back up the WAL safely using SQLite backup API/checkpoint, not raw copy of a live DB.
- Preserve and protect a separate offline copy of the 32-byte encryption root key. Losing the key permanently prevents decryption.

## E12: operator-pinned provider enrollment

```
python -m atlas.provider_registry \
  --registry /private/providers.json \
  --registry-sha256 "$TRUSTED_REGISTRY_SHA256" \
  --config /private/rclone.conf
```

The registry schema is `omega.provider-registry.v1` with `max_age_seconds` (1..86400) and `providers` (1..64). Every record contains exactly: `id`, `provider`, `account`, `domain`, `alias`, `authorized`, `free_tier_attested`, `write_enabled`, `limit_bytes`, `reserve_bytes`, `monthly_write_bytes`, `monthly_read_bytes`, `monthly_operations`, `attested_at`. An account identifier must not appear twice, even behind multiple aliases. `account` and `domain` are operator-declared identities, not automatically verified physical isolation.

Supported inspected provider types: `google_drive` (Rclone drive), `onedrive`, `dropbox`, `backblaze_b2`, `cloudflare_r2` (S3 with Cloudflare provider and official HTTPS R2 endpoint), `generic_s3` and `webdav`. Cloudflare R2 endpoint is pinned to its official `https://<accountid>.r2.cloudflarestorage.com` form (including documented `.eu` variant); plain S3 type is insufficient. Both Rclone configuration and quotas must pass bounded read-only subprocess checks. Environment overrides are rejected. Missing/unknown quotas, stale attestations, unsupported adapters or absent authorization block enrollment.

`terabox` remains explicitly `BLOCKED_OFFICIAL_OAUTH`, with no write permission and no session/cookie workaround. The public 1 TB offer must not be treated as accessible API capacity without consent and official API qualification. No provider can be declared guaranteed zero-cost based on quota output alone. Billing tiers, account restrictions, egress, API calls and external operations must be checked independently. The registry may only return `ENROLLED_READ_ONLY`, not an unconditional transfer authorization.

## E13: conservative quota reservations

Register pools using independent verified budgets, including actual ciphertext overhead and possible provider API operations:

```
umask 077
mkdir -m 700 -p /private/omega-ledger
python -m atlas.quota_ledger \
  --database /private/omega-ledger/quota.sqlite enroll \
  --pool disk1 --limits /private/limits.json --epoch 1
python -m atlas.quota_ledger \
  --database /private/omega-ledger/quota.sqlite status --pool disk1
```

Limits JSON uses exactly six nonnegative integer counters: `storage_bytes`, `write_bytes`, `read_bytes`, `write_ops`, `read_ops`, `egress_bytes`. One exclusive SQLite `BEGIN IMMEDIATE` transaction reserves an idempotency key and all six counters. Concurrent callers never exceed the configured pool budgets in the tested local database. The caller must provide an owner epoch and TTL. Expired reservations transition to **UNCERTAIN** without freeing quota. A crash or unknown upload result must be operator-reconciled with proven absent/committed provider data. Old epochs cannot commit or renew after explicit fencing. The timestamp high-water mark rejects backward wall-clock jumps. No negative counters and no implicit cost alerts as spend caps.

This is a **single trusted local transaction coordinator**, not distributed consensus. An actual multi-host reservation gateway must use the existing etcd authority, cross-host fencing and an atomic provider reconciliation protocol. This production gate remains OPEN. Ledger limits cannot prevent third-party billable events or spending from other clients using the same account.

## E14: encrypted chunk archive

The local CLI intentionally accepts only explicitly enrolled private local object paths; remote writes require the Python `RcloneStore` adapter with a separately pinned and inspected E12 registry, E13 ledger and `permit_remote=True` operator opt-in.

```
umask 077
python -m atlas.secure_fabric \
  --manifest /private/archives/a.json --key /private/keys/storage.key \
  --ledger /private/omega-ledger/quota.sqlite --stores /private/stores.json \
  --epoch 1 ingest --source /private/source.bin \
  --policy-sha256 "$TRUSTED_POLICY_SHA256" \
  --archive-id "$PERSISTENT_UNIQUE_ARCHIVE_ID" \
  --chunk-bytes 4194304 --copies 2

python -m atlas.secure_fabric \
  --manifest /private/archives/a.json --key /private/keys/storage.key \
  --ledger /private/omega-ledger/quota.sqlite --stores /private/stores.json \
  --epoch 1 restore --pin "$RETURNED_MANIFEST_SHA256" \
  --destination /private/recovered.bin
```

A local stores JSON object maps pool ID to `{"path":"/private/disk/cas","domain":"operator-enrolled-domain"}`; at least two distinct declared domains. Physical failure-domain independence is **not** proven by strings. Real production placement must enforce separate hosts/devices/providers and bind the E11 certified capacity plan, which is still an open integration requirement. The crypto root key is exactly 32 random bytes, owned 0600; never log or place it on a remote. The application derives separate manifest and per-archive data keys using HMAC-SHA256, encrypts each bounded 64KiB..16MiB block with AES-256-GCM and a fresh random nonce, and authenticates associated context (archive, index, policy pin and plaintext length). An HMAC-SHA256 and separately pinned manifest SHA-256 protect metadata; both pins and keys are needed. Readback compares encrypted bytes, then restore checks AES-GCM tag, plaintext digest and the final whole-file SHA-256 before no-overwrite publication with fsync. A failed replica is skipped. Current copy count: 2 or 3; maximum 65536 chunks, 1 TiB theoretical at 16 MiB/chunk. Size is an addressable bound, **not** a TB throughput or resource qualification.

The external Rclone adapter builds fixed safe object names, verifies its configured backend and quota before admission, requires operator opt-in, uses the E13 active reservation before writes and an additional read reservation for remote recovery. Rclone transfer subprocesses have bounded time/output, no shell interpolation and no credentials in source. Tests used an isolated executable fixture (not real Rclone nor a live cloud). Chunk encryption is randomized and does not deduplicate identical plaintext across archives. The local CAS storage metadata does not implement GC, retention, tenant ACL, distributed leases, erasure coding or a writable POSIX/SMB namespace.

A staged remote write can leave orphans when a crash occurs. Quota is conservatively retained as UNCERTAIN or spent; no automatic deletion or refund. If any underlying pool already has a COMMITTED idempotency key for an archive ID, a second ingest is rejected. Operators must treat the manifest SHA pin as a durable, independently retained reference and preserve keys/backups. Out-of-band reconfiguration or cloud provider billing remains outside this guarantee.

## Verification evidence

See `docs/E14_VERIFICATION.md` and `reports/e14-verification.txt` for 53 recovered-subset tests (including existing E12/E13 regressions, malformed-manifest RED/GREEN and real CLI subprocess tests). E14 was tested with an emulated Rclone provider executable and local private stores, NOT real external accounts. Complete-repository tests, physical independent-fault-domain qualification, live SMB/Rclone and deployed service gates remain NOT_RUN. E14 integration is a code-level PASS only; production gate remains BLOCKED. The cryptography dependency is not vendored, and runtime must install the pinned package.

Primary vendor documentation:
- https://rclone.org/commands/rclone_about/
- https://rclone.org/crypt/
- https://developers.cloudflare.com/r2/examples/rclone/
- https://developers.cloudflare.com/r2/pricing/
- https://developers.cloudflare.com/r2/api/s3/api/
- https://www.terabox.com/integrations/docs?lang=en

## Verification gate amendment

Before claiming production availability, execute physically independent encrypted round trips on at least two authorized provider accounts with measured quotas, billing controls, vendor TOS review and live fault injection. The local E13 SQLite authority cannot coordinate several writers on different hosts. Reject unqualified mirrors and record live key rotation, restore, and WAN timing under a new evidence record. The manifest validator now rejects wrong JSON types (including unhashable replica IDs) with `SecureError`, after checking HMAC and external pin.

### E14 filesystem hardening

All authenticated manifests are now read from private 0600 regular files using
`O_NOFOLLOW|O_NONBLOCK`, a 16 MiB hard bound and before/after file identity checks.
Symlinks, named pipes and world-readable manifests are refused without waiting
for special-file producers. Malformed JSON fields with valid HMAC and a recomputed
external pin are rejected with `SecureError` rather than unexpected `TypeError`.
This protects the local host interface; remote-provider integrity and metadata
fencing remain separate open qualification gates.
