# E22b — deterministic SMB channel-fault model

**Scope:** application-level behavioral simulation for `omega-compat` (SMB2.10 signing requested), `omega-secure` and `omega-models` (SMB3.1.1 encryption requested). The model accepts operator-supplied identities as fixtures; it does **not** authenticate passwords, establish SMB sessions or perform SMB signing/AES encryption.

## Executable fault model

`atlas/smb_channel_sim.py` implements 2–8 separately switchable logical channels carrying operations to one in-memory server state. It models strict share/account/dialect/protection preconditions, a read-only models share, no-overwrite publication, SHA-256 readback against an **externally supplied pin**, transaction IDs for idempotent retries, competing client operations under a lock, lost acknowledgments **after** a logical commit, and injected pre-commit aborts. A one-shot corruption fault flips a byte and must be detected before data is returned. This is a logical application contract, **not SMB Multichannel semantics or proof that Samba has application-level exactly-once delivery**.

## Test commands and acceptance

```sh
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_smb_channel_sim.py' -v
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q atlas tools tests
```

15 focused cases, including 200 pseudorandom but fixed-seed fault sequences (seed 20261123), 32 concurrent attempts to replay one operation, strict read/write ACL, denial of SMB1, two-channel failover, lost-ACK after commit, simulated pre-commit crash, retry conflicts, SHA corruption, source-digest checks, no-overwrite, bad types/paths, namespace isolation and repeatable trace SHA-256. Three complete local-subset runs: **57/57 PASS** each (2.491, 2.652 and 2.568 seconds); `compileall` PASS. The sample event-trace digest is `aa0144e615a469d828bc12b30ad93988fdbfaaf3a7e80bf836c8501694972805`.

The local subset also contains 13 E20b quorum, 15 E21 signed-permit and 14 E22a bounded `smbclient` process-fixture tests. No physical SMB server, mTLS, actual network path, S24 Ultra, Etcd/Raft, cloud, WORM, production RPO/RTO or p95 throughput has been exercised by E22b.

**GATE-04:** PASS_SIMULATION (bounded application contract only). **GATE-05:** SIMULATION_VERIFIED_PARTIAL. **GATE-09:** OPEN globally. The model is not deployable as an SMB server or a replacement for real Samba/Rclone adapters.
