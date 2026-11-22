# E22a — SMB2/SMB3 read-back and bounded transport qualification

**Status:** IMPLEMENTED / TESTED_LOCAL. This is **not** the completion of E22 or production GATE-09. Physical SMB handshake, negotiated dialect, independent server and fault-domain tests are still **NOT_RUN** in the project runner.

`tools.smb_qualification` is an **opt-in** measurement CLI for the existing Samba service. It does not implement Samba, alter `smb.conf`, mount a drive, create a new network share, authorize public TCP 445, change credentials, or assert HA. It checks the data plane by transferring newly generated random bytes over an installed `smbclient`, reading back the exact same named file, verifying complete SHA-256 and length, then deleting the disposable remote file. Any failed operation, hash mismatch or uncertain cleanup makes the invocation fail closed; unsuccessful cleanup includes the random name for operator inspection. Existing data are never intentionally deleted.

## Transport contract

- `omega-compat`: `-m SMB2_10` plus `client min protocol=SMB2_10` and `--client-protection=sign` (the exact SMB2.1 dialect is requested).
- `omega-secure`: `-m SMB3_11` plus `client min protocol=SMB3_11` and `--client-protection=encrypt` (SMB3.1.1 encryption requested).
- Uses only the corresponding existing private `vps/smb-secrets/{compat,secure}_password` files (0600, single hard link, owned by calling user). Passwords are written to temporary private `-A` credential files, never command arguments, outputs or reports. No model share writes.
- Accepts only literal loopback or an explicitly opted-in RFC1918/CGNAT/VPN IPv4 address. The network and firewall must *already* be authorized independently.
- Per share: 3–20 serial samples, 1–16 MiB each, 5–180 s process timeout per SMB command, no infinite retry or unconstrained transfer. Report includes per-direction end-to-end process time, MiB/s including authentication/session setup, p95 latency and median throughput. It is not raw link bandwidth, server IOPS, full-file-system throughput or network-wide p99.
- The JSON always says `OBSERVED_NOT_CERTIFIED` and `client_dialect_attestation=NOT_INDEPENDENTLY_VERIFIED`. Client command options alone do not prove server dialect or encryption without corresponding server/packet evidence.

## Execution on the real authorized VPS

Only run against owned and prepared shares, after completing `docs/SMB_STORAGE.md` provisioning and the existing signed/encrypted live acceptance probe. This benchmark **writes temporary files** and will consume some disk/network bandwidth. Default payload is 1 MiB, 3 runs per share.

```bash
sudo python3 tools/smbctl.py probe --bind 127.0.0.1 --port 445
sudo install -d -m 700 /root/omega-smb-evidence
sudo python3 -m tools.smb_qualification --root "$PWD/vps" \
  --bind 127.0.0.1 --port 445 --mib 4 --samples 5 --timeout 60 \
  --report /root/omega-smb-evidence/e22a-measurement.json
```

If using a bound private VPN interface, add `--allow-network` and your real private IPv4 address to both commands, after verifying VPN routing and firewall. Do not use public/exposed TCP 445.

Never reuse the same report filename: private reports are created atomically with `O_EXCL`, 0600 and `fsync`, without overwriting previous evidence. Staging files and authentication material live under an automatically removed private temporary directory. If a network operation has an ambiguous outcome and the cleanup fails, manually inspect only the printed `omega-e22-*` test file before retrying.

## Evidence and remaining requirements

Local qualification tests use a **controlled Bash `smbclient` executable** which implements only `put`, `get`, `del` against a sandbox directory, not a network SMB stack. They exercise an actual subprocess invocation, hashes, private credential files, CLI subprocess, corruption, replay of report path, failed delete, ambiguous writes, secret hard links, symlinks, unsafe address and bounded parameters. Their timing is **not an SMB performance measurement**. Exact command and test result are recorded in `reports/e22a-verification.txt`.

Real E22 qualification still requires a separate Linux/Windows/S24 Ultra SMB2/SMB3 matrix; server-side Samba dialect and encryption evidence; physical or VM-isolated fault domains, SMB multichannel and durable-handle failover; multi-TB datasets and cost comparison with Samba+mergerfs/Rclone and distributed alternatives; reproducible 30+ real trials and independent performance samples; actual RPO/RTO and tamper-proof archive retention. No throughput or production PASS is asserted until those tests really run.
