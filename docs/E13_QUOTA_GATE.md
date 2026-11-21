# E13 - local quota ledger with conservative fencing

Integrated module: `atlas/quota_ledger.py`; test suite: `tests/test_quota_ledger.py`.

## Security and scope

- Six counters: storage, write bytes, read bytes, write operations, read operations, egress bytes. One SQLite `BEGIN IMMEDIATE` transaction checks and reserves all six atomically for one owner.
- Idempotency by `(pool, request)`, TTL, epoch fencing and clock rollback guard; stale or expired writes are **UNCERTAIN**, never implicitly refunded. Only an operator-confirmed reconciliation may release or debit them.
- The SQLite WAL is restricted to a private local filesystem, with private database and directory permissions. It is **not a distributed consensus system** and cannot fence side effects already in flight.
- The ledger does not prevent charges from other clients sharing the same provider account and is not a substitute for provider-enforced spending limits. Operator must initialize budgets from independently verified quotas and costs.
- Requires a single trusted writer authority and local backups. Never place live SQLite WAL on SMB/NFS or a mounted cloud drive.

Usage (one pool at a time):
```bash
umask 077
mkdir -m 700 -p /private/omega-ledger
python3 -m atlas.quota_ledger --database /private/omega-ledger/quota.sqlite enroll --pool disk1 --limits /private/limits.json --epoch 1
python3 -m atlas.quota_ledger --database /private/omega-ledger/quota.sqlite status --pool disk1
```

Expected limits JSON: `{"storage_bytes":1000,"write_bytes":1000,"read_bytes":1000,"write_ops":100,"read_ops":100,"egress_bytes":1000}`. These are example quotas, not a claim about any provider.

## Evidence

Ten focused ledger regression tests passed locally with real SQLite WAL, including 12 concurrent reservations, recovery/restart, idempotence, epoch changes, uncertain reconciliation, permissions and clock rollback. E12+E13 selected tests: **17/17 PASS**, Python compilation passed, using Python 3.13.5/SQLite 3.46.1 on Linux x86_64.

No cross-host quorum, external provider or live SMB was tested. E13 local implementation is accepted; global production acceptance and GATE-09 remain OPEN. E14 encryption module is still in a separate tested local patch, not yet merged.

Base: `bf620aae29b59a63ade67fa80823c5b92ba69e52`.
