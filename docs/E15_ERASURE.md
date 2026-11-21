# OMEGA-X / E15 — authenticated Reed-Solomon local erasure archive

E15 is a **locally implemented** GF(256) Cauchy Reed-Solomon 4+2 / 8+3
codec, encrypted local CAS stripe archive and repair engine. It does not
provision cloud accounts, perform an SMB mount or certify independent hardware.
**Upstream branch:** `main`, pinned base `3ce3c4cb2778b4c347f0e8aa8ce096612dd6e8ea`.

## Erasure coding contract

- Field: GF(2^8), primitive polynomial `0x11D`. Generator is systematic
  `[I_k; C]`, `C[i,j] = inv((k+i) XOR j)`. Only `(4,2)` and `(8,3)` accepted.
- All fragments of a stripe have equal padded length. Any `k` verified fragments
  recover the original frame; up to `m` missing fragments are repairable.
- Every fragment is checked against a SHA-256 digest from an authenticated
  manifest before reconstruction. FEC alone does not detect silent corruption
  of precisely `k` unverified shards. The E14 AES-256-GCM frame is reconstructed
  and authenticated, then plaintext stripe and full-file SHA-256 are checked.
- **Auto selection is a simple declared failure-domain count policy**, not a
  measured performance or durability optimizer: 6..10 domains -> 4+2;
  11+ domains -> 8+3. Fewer than 6 declared independent domains blocks writes.
  Real physical/administrative independence is not established by text labels.
- 4+2 consumes about `1.5x` ciphertext space and 8+3 about `1.375x`, excluding
  metadata, padding and per-object/request overhead. Relative to 2 full copies,
  this is nominally 25% and 31.25% less raw stripe storage respectively.
- The implementation processes one bounded stripe at a time (64 KiB..16 MiB);
  input and manifest have hard limits, no arbitrary eval or shell interpolation,
  and publication is no-overwrite plus fsync. Manifest uses a separate
  E15-derived HMAC key and independently retained SHA-256 pin. Root key remains
  in a private 0600 file. Ciphertext fragments are stored using the existing
  E14 `LocalStore`, and E13 reserves all six resource counters before writes.

## CLI local file workflow

The JSON file `stores.json` maps pool names to
`{"path":"/private/store-root","domain":"operator-confirmed-fault-domain"}`.
Supply exactly six private local stores for 4+2 or eleven for 8+3, and enroll
all their quota budgets using `python -m atlas.quota_ledger`. Do not confuse
separate directories on one disk with physically independent failure domains.

```bash
umask 077
python -m atlas.erasure_archive --manifest /private/archives/a.json \
  --key /private/keys/storage.key --ledger /private/ledger/quota.sqlite \
  --stores /private/stores.json --epoch 1 \
  ingest --source /private/models/model.gguf \
  --policy-sha256 "$TRUSTED_POLICY_SHA256" --archive-id "$UNIQUE_ARCHIVE_ID" \
  --chunk-bytes 4194304 --profile auto

python -m atlas.erasure_archive --manifest /private/archives/a.json \
  --key /private/keys/storage.key --ledger /private/ledger/quota.sqlite \
  --stores /private/survivors.json --epoch 1 \
  restore --pin "$INDEPENDENT_MANIFEST_SHA256" \
  --destination /private/restored/model.gguf

python -m atlas.erasure_archive --manifest /private/archives/a.json \
  --key /private/keys/storage.key --ledger /private/ledger/quota.sqlite \
  --stores /private/all-enrolled-stores.json --epoch 1 \
  repair --pin "$INDEPENDENT_MANIFEST_SHA256" --repair-id "operator-incident-001"
```

Repair only repopulates **absent** shards; corrupt existing CAS objects must be
quarantined and reviewed by an operator before repair. Reserve operation IDs
must be unique and pinned. Failed or ambiguous writes never silently refund
budget: the E13 ledger marks reservations UNCERTAIN for reconciliation.
Data-plane encryption is authenticated, but availability is only verified on
private local filesystems with test fixtures. Independent cloud providers,
network retry/resume, distributed quota consensus, rollback-resistant metadata,
GC/retention/tenant isolation, billing guarantees, SMB3 gateway and physical
failure-recovery qualification remain OPEN. Production GATE-09 is BLOCKED.

## Reproducible CPU/byte comparison

Run:

```bash
python -m tools.bench_erasure --bytes 1048576 --repeats 3 --seed 20261121
```

Actual local measurement (Linux x86_64, Python 3.13.5) is recorded in
[E15_VERIFICATION.md](E15_VERIFICATION.md). The fixture uses 1 MiB seeded data,
three runs, and erases the full parity-count of original data fragments.
Milliseconds vary across runs. No GPU, Android, WAN, provider, power or market
performance claim is implied.

References for the MDS / systematic erasure-code model:
- https://datatracker.ietf.org/doc/html/rfc5510
- https://www.backblaze.com/blog/reed-solomon/
