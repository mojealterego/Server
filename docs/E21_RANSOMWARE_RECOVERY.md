# E21a — Offline SMB recovery authorization and anti-replay

**Status:** IMPLEMENTED / TESTED_LOCAL (13 focused tests). Full E21 ransomware recovery and GATE-09 are **BLOCKED** by the missing physical and independent-trust validation.

`atlas.ransomware_recovery` adds an opt-in, separate authorization layer to the existing E20a signed checkpoint history and `storage_recovery.restore_set` SMB restoration for exactly `omega-compat`, `omega-secure` and `omega-models`. It is an **offline restore into a new empty directory**, not an online Samba VFS, SMB write interceptor, immutable cloud store, distributed transaction, or live failover.

## Trust and authorization contract

1. Capture all three shares **with all SMB writers quiesced**, and export/retain E14/E15 snapshot objects on genuinely independent encrypted replicas. Retain the pinned SHA-256 recovery-set receipt separately.
2. Before the incident, store the E20a checkpoint chain, its Ed25519 public key and the *current external checkpoint tip* in a separately controlled location. Compromised metadata and an unsigned local `tip` are not trusted.
3. A separate offline recovery authority signs a canonical Ed25519 permit (`omega.ransomware-recovery-permit.v1`) over **tenant + exact three-share set SHA-256 + externally retained E20 tip + absolute destination + 128-bit random nonce + bounded validity interval** (at most 24 h). Use a **different key** from the E20 checkpoint signer; never place the recovery private key on a restore server.
4. The restore host validates pinned keys, signature, exact destination, two independently supplied hashes, E20 checkpoint history, protected files, target vacancy, and the original strict three-share recovery receipt. A durable `O_EXCL` + `fsync` claim of the `(public_key, tenant, nonce)` is made **before remote I/O**. Replay is denied even if the signed document has other changed fields.
5. Only after the claim does the existing E15/SMB restore stage fetch pinned replicas, verify each share identity, stage the three shares and publish them atomically without overwriting the destination. A failure leaves the authorization consumed and quarantined. A new operation requires a **new independently signed nonce**, with operator review of the existing staging and outcome.

The claim directory must be a private `0700` **durable independent journal**. It is not cryptographically immutable; a local root attacker can erase it. To claim ransomware survival, mirror it to append-only/WORM storage in an independent security domain and test actual retention/restore. Host clock rollback and signer compromise also require independent protection.

## Example (offline operator workflow)

First collect a previously verified `recovery-set.json`, real E20 chain and independently stored pin/public keys, and initialize the empty private claims directory (`mkdir -m 700 /private/claims`). Use a secure random 16-byte nonce and a short authorization window. The **signing command runs on an isolated authority**, not on the restore server:

```bash
python3 -m atlas.ransomware_recovery issue \
  --key /private/offline/recovery.seed --tenant omega \
  --set-sha256 "$PINNED_RECOVERY_SET_SHA256" \
  --checkpoint-tip "$EXTERNAL_E20_TIP" \
  --dest /private/offline-restored-shares \
  --nonce "$(openssl rand -hex 16)" \
  --issued-at "$NOW" --expires-at "$EXPIRES" > /private/offline/permit.json
chmod 600 /private/offline/permit.json
```

Transfer the canonical permit into a private directory on the offline restore host. The actual recovery command **must not use the signing key**:

```bash
python3 -m atlas.ransomware_recovery restore \
  --vault /private/restore-cas --set /private/receipts/recovery-set.json \
  --permit /private/receipts/permit.json \
  --tenant omega --set-sha256 "$PINNED_RECOVERY_SET_SHA256" \
  --checkpoint-dir /private/checkpoints --checkpoint-tip "$EXTERNAL_E20_TIP" \
  --recovery-public-key "$PINNED_RECOVERY_KEY_HEX" \
  --authority-public-key "$PINNED_E20_KEY_HEX" \
  --claims-dir /private/claims --dest /private/offline-restored-shares \
  --remote crypt1:snapshots --remote crypt2:snapshots
```

The private parent directories and receipt files must be owned by the runtime UID with restrictive permissions; the output path must be new. Rclone remote aliases must already be configured as `crypt` on actual independent providers. Permits and recovery-set files are canonical JSON without whitespace. Never pass a private key through command-line arguments.

## Verification boundary and remaining E21 requirements

- `PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_ransomware_recovery.py' -v`: **13/13 PASS** on a local Linux test subset; actual Ed25519 and CLI subprocess, private-file and symlink refusal, expiry, independent pins, used-nonce fencing, uncertain claim and no-overwrite checks. `python3 -m compileall -q atlas tests`: PASS.
- Tests use controlled E20/SMB adapters. **Full source checkout, full regression suite, real E20/SMB adapter end-to-end, Docker Samba negotiations, S24 Ultra, external WORM, actual independent cloud providers and ransomware recovery drill were NOT_RUN**. No RPO/RTO or multi-host fencing is proven.
- Remaining E21: immutable independently retained generations, authenticated tenant ACL and quota lifecycle, key rotation, anti-ransomware filesystem integration, failover and physical restore drill with measured RPO/RTO; independent verification of real E20 quorum. Do not mark E21 full PASS.

See `reports/e21a-verification.txt`, `docs/E20_AUTHORITY_CHECKPOINT.md`, `docs/STORAGE_FAILOVER.md`, and `docs/SMB_STORAGE.md`.
