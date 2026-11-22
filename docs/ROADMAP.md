# E22a — Bounded SMB2/SMB3 read-back and throughput observation (2026-11-22)

- **IMPLEMENTED / TESTED_LOCAL:** opt-in native `smbclient` bounded read/write benchmark for existing signed SMB2.1 `omega-compat` and encrypted SMB3.1.1 `omega-secure`. Mandatory exact protocol request, SHA-256 read-back, unique disposable names, fail-closed cleanup, owner-private credential handling and no-overwrite 0600 evidence report. No other Samba shares or runtime configuration changes.
- **Local evidence:** 14/14 deterministic tests PASS (controlled Bash subprocess client, **not** real SMB network); Python compile and CLI help PASS. [Runbook](E22_SMB_QUALIFICATION.md) · [test proof](../reports/e22a-verification.txt).
- **GATE-05/07/09 BLOCKED:** live Samba packet/dialect/encryption proof, actual throughput, multichannel and durable handles, TB loads, real independent fault domains, physical S24/Windows/Linux and competitor cost comparison have **NOT_RUN**. Real E22 is not complete; local subprocess timings are not SMB throughput measurements. E21a and all previous E20a/HA gaps remain unchanged.

---

# E21a — Signed offline ransomware recovery authorization (2026-11-22)

- **IMPLEMENTED / TESTED_LOCAL (13/13):** separate Ed25519-signed, strictly bounded single-use restore permit binding tenant, three-share SMB2/SMB3 pinned recovery set, independent E20a checkpoint tip, absolute new destination, nonce and expiration. Durable no-replay claim before remote access; uncertain restore consumes permit. Works with existing E20 verification and `storage_recovery.restore_set` stage through an opt-in offline CLI.
- **Evidence:** source and test SHA-256 pinned in [E21a verification](../reports/e21a-verification.txt); read [E21a runbook](E21_RANSOMWARE_RECOVERY.md). Cryptographic, file-safety and controlled-adapter tests passed locally. Full repository checkout and physical SMB/E20/cloud E2E **NOT_RUN**.
- **BLOCKED:** WORM/independent immutable generations, real cross-host etcd fencing, hardware trust, tenant ACL/quota/key lifecycle, full ransomware drill and measured RPO/RTO. GATE-05/07/09 BLOCKED; do not advertise full E21 completion. Next E20 quorum-backed metadata and E21 physical restore qualification; E22 SMB3 performance and independent fault domain comparison remain OPEN.

---

# E20a — signed namespace checkpoint chain (2026-11-21)

- **IMPLEMENTED, LOCALLY TESTED:** Ed25519-signed, SHA-256-chained immutable checkpoint receipts of E16 single-host SQLite namespace; externally supplied hash pin; independent signature and monotonic generation verifier; optional exact-current-state gate. Private files, no-overwrite and fsync, serialized writers.
- **Evidence:** 17/17 new focused tests, actual sqlite3 transaction, concurrent append, subprocess CLI; red-green fixes for over-reading whole SQLite file, resource leaks, acceptance of empty chain. [E20a contract](E20_AUTHORITY_CHECKPOINT.md) · [proof](../reports/e20a-verification.txt).
- **BLOCKED:** no real etcd quorum or cross-host fencing, no automatic transactional checkpoint on every mutation, no independent external pin retention device, no real Samba/cloud end-to-end. GATE-09 stays OPEN. Base `82410a84ea6ccbf6b3c18f6a82c49126b8d77e70`.

---

# E19b — Verified locality egress gate (2026-11-21)

- **IMPLEMENTED + LOCALLY TESTED:** independently recompute p95 and network transfer from a pinned E19 source profile, reject stale/tampered rankings, forbid explicitly billable links, validate JSON/directory inputs and bounded CLI. Existing PHASESHIFT certification and E13 quota ledger remain mandatory for any execution.
- **Evidence:** 15/15 focused local tests, including separate CLI process, source tampering and path safety. See [E19b contract](E19B_EGRESS_GATE.md) and [verification](../reports/e19b-verification.txt).
- **NOT a billing guarantee or transport ACL:** zero-cost links are operator assertions; no real provider, actual paid-transfer reconciliation, telemetry signing, multi-task capacity reservation, or activation. GATE-09 remains BLOCKED. Base `afb6c5d5c395f09aee70e3b3d4f0ad2a4abc9578`.

---

# Evolution E19a — verified-data locality advisor (offline, read-only)

Added E19a: bounded pinned profile of data digest availability, directional measured bandwidth/RTT and stage-level p95; deterministic policy-constrained ranking. Missing/expired routes and measurements fail closed. Output is ADVISORY_ONLY and cannot authorize migration, create workloads or bypass existing PHASESHIFT certified schedules. 11 new local cases (10 unit + 1 subprocess CLI), combined E16–E19 scope 44/44 PASS in repeated runs, Python compileall PASS. No live WAN or provider measurements. See [E19 locality](E19_LOCALITY.md) and [verification](../reports/e19-verification.txt). Base 73e200d783d30c4dc7d331e7aeb2a5679028d225.

E19b real signed measurements and certified candidate integration OPEN. E20 etcd/quorum, E21 ransomware recovery and E22 physical SMB market qualification OPEN. GATE-09 remains BLOCKED.

---

# Evolution E16a-E18a — transactional metadata, signed edge admission, pinned model hydration

Local integration milestone on main. E16a: single-host SQLite transactional namespace for pinned E14/E15 archives; atomic rename/CAS/replay/tombstones, six-writer concurrency; no Samba VFS or distributed byte locks. E17a: Ed25519 operator grant and node proof, one-use challenge, persistent revocation; no actual device attestation or mesh data transfer. E18a: bounded HTTPS-only, pinned public model reference hydrator, full SHA-256 and immutable-style atomic private cache publication; no live Hugging Face download tested.

Evidence: 33/33 new local tests PASS on three repeated runs (12 E16 + 11 E17 + 8 E18 + 2 subprocess CLI); Python compileall PASS. See [E16](E16_NAMESPACE.md), [E17](E17_EDGE_ENROLLMENT.md), [E18](E18_VIRTUAL_MODELS.md), [verification](../reports/e16-e18-verification.txt). Base `3bc0a4ce86d6b994b97c430a44e651d5bfc83c15`.

Production E16, E17 and E18 remain OPEN/BLOCKED pending real SMB2/3 E2E, distributed authority, independent devices, authenticated network paths and source-provider evidence. Existing E12–E15 implementation and all GATE-09 requirements remain unchanged. Next E19: verified compute/storage locality; E20: real etcd authority; E21: immutable ransomware recovery; E22: physical market benchmark.

---

# Storage E15: encrypted Reed-Solomon erasure archive (2026-11-21)

- Base main: `3ce3c4cb2778b4c347f0e8aa8ce096612dd6e8ea`. E14 encrypted CAS, E13 local quota fencing and E12 provider enrollment are retained.
- Implemented offline systematic GF(256) Cauchy Reed-Solomon 4+2 and 8+3, exact k-of-(k+m) recovery, deterministic profile selection by declared failure-domain count, SHA-256 validation of every fragment, AES-256-GCM decryption and HMAC-pinned E15 manifests.
- Implemented streaming local archive ingest/restore/repair on E14 private CAS using E13 budget reservations and fail-closed no-overwrite publication. Supports recovery from 2 lost fragments in 4+2 or 3 in 8+3 (not corruption without authenticated per-fragment hashes).
- Evidence: 70/70 selected local unit/regression/CLI/process/fault tests passed; Python compileall PASS. Includes all 53 E12-E14 recovered-subset tests and 17 E15 tests. [E15 runbook](E15_ERASURE.md), [actual test and benchmark output](E15_VERIFICATION.md).
- Actual local 1 MiB seeded codec benchmark: raw stored 1.5x for 4+2, 1.375x for 8+3, compared to 2.0x mirrored data; 25% and 31.25% fewer shard bytes than two full copies before crypto/metadata/request overhead. CPU timings are not Android, storage or WAN benchmarks.
- Status: E15 IMPLEMENTED / TESTED_LOCAL / CODE_INTEGRATED, GATE-05 external integration BLOCKED, GATE-06 PARTIAL, GATE-07 real physical recovery BLOCKED, GATE-09 BLOCKED. No cloud deployment, actual separate fault domains, TB loads, SMB namespace or assured free provider API.
- Next: E16 transactional virtual namespace and SMB2/SMB3 adapter; separate E12-E15 real-provider cost, data-plane and physical-fault qualification. Do not alter these gates without evidence.

---

# Storage E14 / Omega Hyper CAS (2026-11-21)

- Base: `7454e43bd085257824767d48c5c3dee6bb8f4b26` (main only). E12 provider registry and E13 single-host quota ledger remain intact.
- Added AES-256-GCM chunk storage with authenticated HMAC/SHA-256 pinned manifests, private local CAS, opt-in Rclone adapter and quota reservations, bounded remote readback and replicated restore with failover.
- Hardened manifest type validation and no-follow/nonblocking private regular-file input. Actual RED failures for malformed fields and symlink manifest preceded the fix.
- Local acceptance: 53/53 selected tests (including 7 current E12 main regressions, E13 upstream suite, and E14 crypto, CLI, Rclone subprocess fixture and tamper tests); Python compileall PASS. Exact source blobs recorded in [E14 evidence](E14_VERIFICATION.md) and [E14 runbook](E14_STORAGE.md).
- Gate status: E14 IMPLEMENTED / TESTED_LOCAL / INTEGRATED_CODE. GATE-05 external cloud and multi-host E2E BLOCKED; GATE-06 PARTIAL (local attacks only), GATE-07 physical recovery BLOCKED; GATE-09 BLOCKED. No real vendor credentials, zero-charge guarantees, independent devices or production deployment.
- Next: E15 Reed-Solomon erasure code with bounded recovery tests, then E16 global namespace SMBv2/SMBv3; separately qualify E12-E14 against real authorized provider accounts and external gates.

---

# E13 / STORAGE-07c — durable local quota reservations (local increment)

- Added `atlas/quota_ledger.py` and `tests/test_quota_ledger.py`: ten focused E13 cases passed, including concurrent reservations; 17/17 selected E12+E13 tests passed on a local runner.
- Enforces private local SQLite WAL, atomic multi-counter budget checks, TTL, idempotency, monotonic time, epoch fencing and UNCERTAIN quarantine after ambiguous side effects. Explicit reconciliation is mandatory.
- E13 distributed authority, real provider billing reconciliation and cross-host fencing remain OPEN. E14 is still a separate patch, not merged. No real etcd/SMB/cloud claim; GATE-09 OPEN. See [E13 gate](E13_QUOTA_GATE.md).

---
# E12 / STORAGE-07b — read-only provider enrollment (local increment)

- Added `atlas/provider_registry.py` and `tests/test_provider_enrollment_gate.py`: 7/7 local test cases passed (real local Rclone subprocess fixture; no live cloud).
- Pin operator registry digest; check unique account/quota identity, expected backend, Cloudflare R2 HTTPS endpoint, bounded quota probe, no environment overrides, reject unsupported TeraBox writes. Outputs are advisory read-only.
- External E12 OAuth, live account, rates, cost guarantee and integration with E13/E14 remain OPEN. E13/E14 code remains in local patch and is not marked merged. See [E12 gate](E12_PROVIDER_GATE.md).
- No mobile, Docker, etcd or SMB qualification from these tests. GATE-09 remains OPEN. Base: `aacf69533553cd8a3e2a21556325372275fd0ec6`.

---
# Mobile evidence-gated preflight (2026-11-21)

- Source: `termux/device_model_probe.py` provides read-only first-page mmap evidence, optional full SHA-256, observed file count, model-header classification through the existing parser and current-process CPU affinity. It refuses symlinks, malformed input and detected concurrent mutation. Does not copy model weights or overwrite Rclone configurations.
- Verification: 13/13 isolated deterministic fixture tests PASS on x86_64 Linux, `compileall` PASS, CLI `--help` PASS; exact Git blobs match tested code. No full-repo regression, real S24 Ultra hardware check, inference, mmproj lineage, thermal/performance result or real cloud transfer. `reports/green-mobile.txt` remains NOT_RUN. See [report audit](MOBILE_REPORT_AUDIT.md).
- Previous E12–E14 implementation is still a standalone ZIP patch pending integration; this increment does not certify it. Existing production/HA/SMB GATE-09 remains OPEN. Parent: `aec4640b476fc097738639d2d5dba5fb019f2799`.

---

# Evolution batch E01-E11 (2026-11-20)

Compute v5.5b + STORAGE-07a: 11 engineering scopes implemented and locally accepted, not 11 full production releases. 47/47 selected tests (34 new, 13 upstream), 200 seeded schedule cases, CLI archive round trip 1,250,000 bytes. See [E01-E22](EVOLUTION_11.md), [zero-cost capacity](ZERO_COST_FABRIC.md), [workload optimizer](WORKLOAD_OPT.md), and [verification](../reports/evolution-11-verification.txt).

Next E12-E22: authorized free-provider registry, quota ledger, encrypted cross-provider chunks, erasure coding, SMB namespace, edge federation, virtual artifacts, locality optimization, real distributed quorum, ransomware recovery, physical/market qualification. All OPEN; prior gates remain unchanged. Base 9b732af3763416c3a02798b2e88d08f94559f8ba.

---

# Compute v5.5a + STORAGE-06 — adaptive polling and verified replica preference

- Compute: opt-in bounded adaptive idle polling (`--max-poll-interval`, base..30 s), reset on state progress and execution, preserve certified assignment order, privacy, retry budgets and existing RPC-error backoff. Fixed default retained. Deterministic one-task idle fixture: 21 status calls reduced to 6 in the same 20 simulated seconds; no energy/throughput or physical hardware claim. 5 new cases and 12 existing scheduler cases passed. Worker CLI compiles; its full remote execution path was not run.
- Storage: serial per-staging preference for the last SHA-256-verified replica, all enrolled alternatives remain available on failure; no integrity or version fallback relaxation. 3 new cache cases, 8 existing cache cases (one assertion updated for the new expected read count), and 2 real Fabric/cache/Merkle integration cases with controlled Rclone subprocess passed. Actual signed manifests, private file staging and atomic publication; no real Samba/SMB network negotiation or cloud replication.
- Evidence: 30/30 local focused tests passed (10 new and 20 existing), Python compilation and storage CLI help passed. Source subset verified against pinned Git blobs; dispatch error contract, capctl and artifact helper functions were extracted because full clone fails DNS. Full-repo regression, real HA/etcd quorum, live SMB, recovery-generation integration and final GATE-09 remain open. Base: `a12e2e29e544df7b3e37e18ec8a559fd50ed8fcc`. [Verification](../reports/adaptive-polling-storage-verification.txt).
- Next: v5.5b measured workload-policy optimization with independently verified plans; continue STORAGE-06 recovery/real transport qualification and all previously recorded HA gates. No automatic reallocation or production certification.

# Compute v5.4b + STORAGE-06 — admission and SMB routing hardening

- Compute: reject inconsistent etcd range responses; permanently revoke the current process after an observed missing or changed grant; concurrent stale observations cannot clear revocation. Transient transport failure remains fail-closed for that request and does not by itself revoke an unchanged grant.
- Storage: lazily validate each used SMB replica via bounded redacted Rclone config read; reject other backends, ambiguous config and remote type environment overrides; do not query Rclone on verified cache hit. A rejected alias stays excluded for the staging invocation. No hardware or dialect claim.
- Evidence: 34/34 recovered-subset tests passed (11 new; 23 previous), Python compilation and both CLI help commands passed. Six real local mTLS tests use an emulated etcd backend. Local subprocess tests use an emulated Rclone executable, not real SMB. Prior unresolved qualification gates retained; GATE-09 remains open. Base `b5b40dfdbf6f8aeac7254ed4e7e3a849e3bf2034`. [Verification](../reports/ha-storage-hardening-verification.txt).
- Next: full integration with real etcd quorum and upstream cache/recovery adapters; physical storage and failover qualification before production acceptance. Compute v5.5 remains pending.

# Compute v5.4b + STORAGE-06 — pinned authority and storage routing (increment)

- Compute: implemented a non-expiring etcd v3 CAS registry, explicit operator-fenced transfer with pinned checkpoint and monotonic modification revision, TLS gateway, cluster pin and optional dispatch admission guard. 15 focused tests passed (including six real local mTLS cases with an emulated etcd RPC contract). No automatic failover or physical fencing; full dispatch wiring integration, real etcd quorum, cross-host SQLite state continuity and zero-RPO remain open. See [DISTRIBUTED_AUTHORITY.md](DISTRIBUTED_AUTHORITY.md).
- Storage: implemented a SHA-256-pinned logical catalog routing model IDs to signed cache manifests and enrolled SMB replicas, and recovery to exactly one pinned three-share generation using existing snapshot/CAS crypt replicas. 8 local routing cases passed with controlled adapter doubles. Real upstream adapter end-to-end integration, Samba/SMB2/SMB3 negotiation, mounted drives, transparent failover, quotas/ACL/retention and physical qualification remain open. See [STORAGE_FABRIC.md](STORAGE_FABRIC.md).
- Verification: 23 new tests passed on the recovered source subset; Python compilation and both CLI help commands passed. Full checkout blocked by DNS. Exact tested new source and test blobs checked; dispatch CLI wiring is source-inspected only. Full-repo verification and final GATE-09 not claimed. Evidence: [verification log](../reports/compute-v5.4b-storage06-verification.txt). Base: `69f7797aabbe25b62af3528a6da457b8027d56e0`.
- Next: qualify these two increments with real etcd and upstream storage adapters; preserve all existing open physical gates before v5.5.

# Compute v5.4a + STORAGE-05 — standby authority and pinned SMB recovery

- Compute: same-host private authority lock with bounded standby wait in dispatch CLI, capture exclusion, quiesced SQLite WAL-aware checkpoint of lease and replay databases plus completed CAS outputs, explicit fencing/latest-state confirmation, atomic offline restore preserving retry and replay state. 12 focused cases passed. Full dispatch integration regression, cross-host quorum/physical fencing and zero-RPO HA remain open.
- Storage: coherent operator-quiesced recovery receipt for all three SMB shares, pinned snapshot identities, encrypted remote export using existing CAS, no silent fallback to an older generation, all-or-nothing local offline publication. 9 focused cases passed, including real upstream snapshot/CAS and subprocess emulated replicas. Automatic live share promotion, ACL metadata, transparent SMB failover and physical tests remain open.
- Verification: 21 focused tests passed on Linux (4.105 s), Python compilation for recovered sources, CLI help for both new modules. Full source checkout blocked by DNS; no full-repo regression or real multi-host deployment claimed. Next compute v5.4b distributed authority, then v5.5 self-optimization; next STORAGE-06 unified storage fabric, retaining outstanding STORAGE-05 qualification gates.

# Compute v5.3 + STORAGE-04 — parallel CAS and SMB access/capacity

- Compute: bounded 1..8 parallel block operations, verified Merkle resume, in-object duplicate suppression, manifest-last publication, compatible remote layout and replicactl --workers. 5 new and 12 existing replication tests passed. Actual throughput/RSS, global bandwidth arbitration and high-speed mTLS dispatch remain open.
- Storage: independent model-only SMB3 identity, native Samba full_audit/auth logging, opt-in dedicated ext4/XFS volume-capacity checks on host and container startup, persisted policy, expanded live probe. 6 new and 11 existing SMB cases passed. Per-user quota, arbitrary ACL/user lifecycle, audit retention and real SMB/mount/SMB3 multichannel qualification remain open.
- Snapshot/cache regression: 9 + 8 passed. 51 local cases in total, split runs, no physical or full-repository certification. Next compute: v5.4 HA authority preparation. Next storage: STORAGE-05 storage failover; outstanding qualification gates retained.

# Compute v5.2b + STORAGE-03 — retry ceilings, failover watch and versioned SMB snapshots

- Compute: persisted administrator attempt ceiling across workflow lineage, coordinator and direct claim enforcement, scheduler budget status, bounded expired-lease candidate detection, transactional expiry-gated cutover. 9 new cases passed. Physical fencing and automatic successor deployment remain open; v5.2 is not a transparent failover release.
- Storage: versioned quiesced share-content snapshots in separate CAS, empty directories, file deduplication, explicit export to configured crypt remotes, pinned snapshot/object manifests, replica recovery, atomic no-overwrite directory restore. 9 new cases passed. Metadata/ACL restoration, online snapshots, GC/retention and real provider/SMB tests remain open.
- Regression: 42 existing scheduler, dispatch, failover and recovery cases passed; source subset only. Next compute: bulk CAS transport and HA preparation alongside remaining physical failover gates. Next storage: ACL, quotas, audit and retention; no claim of live SMB snapshot semantics.

# Compute v5.2a + STORAGE-02 — fenced restart and verified SMB cache

- Compute: operator-confirmed adaptive full restart with fresh signed survivor telemetry, conservative replanning, verified successor certificate, atomic durable predecessor retirement, no live-lease takeover and explicit completed-job restart authorization. 9 new tests passed; automatic detection/migration and completed artifact reuse are still open.
- Storage: per-model Ed25519 manifests and independent SHA pin, 4 MiB verified range staging from up to eight named model-share replicas, resume, cache-hit revalidation, bounded subprocess and private cache disk admission. 8 new tests passed; actual SMB/Rclone/S24/Windows negotiation and device integration remain open. Existing SMB2/SMB3 service retained.
- Regression: 13 dispatch + 11 scheduler + 9 recovery cases passed; full repo regression and real hardware deployment not performed. Next: remaining adaptive failover automation/global retry policy and STORAGE-03 snapshots/verified replication.

# Compute v5.1 — autonomous node scheduler

- Implemented: node-local polling of admitted assigned stages, dependency readiness over mTLS, deterministic planned-slot ordering, privacy exclusion, bounded idle/RPC/preclaim failures, opt-in retry with coordinator-side requested epoch budget, recovery through persisted lease status and local duplicate scheduler exclusion.
- Verified: 11 new unit tests and 13 dispatch tests (2 new, 11 regression) including concurrent schedulers with real mTLS, CAS and process execution against synthetic LLM endpoints. CLI help and compilation passed. Full repository and device qualification remain open.
- Open: policy-owned global retry ceilings, adaptive priority/reassignment, service-wide job intake, high availability and physical inference. STORAGE-02 mobile verified cache and STORAGE-03 backup/replication are the next parallel storage increments.

# Parallel roadmap — OMEGA-X compute + OMEGA STORAGE

Storage is a permanent companion workstream, not a replacement for compute. STORAGE-01 implemented: native Samba SMB2/SMB3 service, separate signed compatibility and encrypted shares, read-only models, private IPv4 bind guard, idempotent credentials, acceptance probe. 11 focused local tests passed (SMB client simulated); Docker/Samba and physical client gate NOT_RUN. STORAGE-02 mobile network drives and verified cache; STORAGE-03 CAS/Rclone snapshots and replication; STORAGE-04 ACLs/quotas/audit/SMB3 performance; STORAGE-05 independent storage failover. See docs/SMB_STORAGE.md.

Compute v5.1 autonomous scheduler is still open; no compute completion claim in this storage increment.

# v5.0 development — AUTHENTICATED HYBRID EXECUTION

- Implemented: single central PHASESHIFT lease authority, pinned mutual TLS task dispatch, fresh signed CAPCTL telemetry per claim/renewal, effective privacy enforcement, bounded resumable dependency and result transfers, typed output verification before fenced completion, automatic execution of a named stage with guardian and renewal in a worker process.
- Verified: 11 new tests and 68 selected regression tests on Linux; real TLS, SQLite, CAS, managed subprocesses and controlled model endpoints/telemetry. Full repository regression and physical AI inference remain open.
- Open: autonomous polling/scheduling, cross-host hardware tests, coordinator HA/consensus, automatic failover reassignment, integrated privacy-aware bulk replication, quota/GC and model qualification. No final production v5.0 release claimed.

# v4.9 development — MULTIMODAL ORCHESTRATOR

- Implemented: typed recipe DAG, strict modality dependencies, operator-enrolled model bundle validation and streaming media weight SHA-256, local supervised engine execution, output signature/dimensions/frame count/FPS/decode verification, CAS checkpoint reuse and explicit failure retry, optional per-stage runtime gate.
- Verified: 24 new unit/integration cases in groups and 35 selected existing regression cases. Actual upstream planner/lease/guardian/CAS and FFmpeg, synthetic engine endpoints; no actual AI inference claim. Full regression and hardware test remain open.
- Open: physical model/backend qualification, Qwen loaded-weight attestation, audio validation, cross-node dispatch over mTLS, privacy-aware automatic replication, global fencing, automatic admission renewal. v5.0 is not closed.

# v4.8 development — SECURE mTLS CAPABILITY GATEWAY

- Implemented: bounded TLS 1.3 gateway and client; mutual certificate authentication, dual leaf certificate pinning, SAN verification, node-ID binding, CAPCTL signature/policy/replay reuse, strict bounded framed JSON, timeout/connection controls, and explicit private network opt-in.
- Verified: 16 new local mTLS tests + 10 CAPCTL tests in a single 26/26 passing run with real TLS and separate CLI processes. Full repository and physical-device regression remains open.
- Open: certificate lifecycle automation and revocation, discovery, independently signed receipts, distributed membership/lease, network telemetry, authenticated dispatch, durable audit and real mobile/VPS deployment. This is an admission transport, not a full peer-to-peer mesh.

# v4.7 development — REPLICATED CAS

- Implemented: explicit push/pull via Rclone, fixed 4 MiB deduplicated blocks, upload/read-back verification, manifest-last publication, pinned manifest and artifact SHA-256, replica failover, resumable Merkle staging and atomic local CAS publication without duplicating the artifact.
- Verified: 12 focused tests run in groups, plus explicit CLI authorization and round trip; real upstream ArtifactStore/Merkle code with controlled Rclone subprocess. Full repository regression, real Rclone/provider/VPS/mobile validation remain open.
- Open: signed receipts, automatic workflow privacy policy on exports, repair and GC, background replication, mTLS control plane and distributed fencing. Separate configured remotes do not prove independent failure domains.

# v4.6 development — LOCAL RECOVERY

- Implemented: mandatory per-node flock in SupervisedExecutor, guardian with parent-lifetime pipe, process-group kill on supervisor death, inherited lock for cooperative foreground child, recovery status CLI, bounded log drain before publication, and RUNTIME_GUARD failure persisted in the lease state machine.
- Verified: 35 focused local tests, including 8 new recovery/exclusion tests, one SQLite failure-state regression and 26 existing focused tests. Real processes and SIGKILL; controlled lease/CAS doubles in supervisor tests, extracted exact fail/transaction logic with an ownership double in SQLite regression. Full repository suite unavailable in test runner because Git clone fails DNS. Earlier reports are historical.
- Open: reconciling durable lease epochs on restart using the full stack, actual device tests, distributed lock and CAS, safe cancellation of remote llama-server, arbitrary daemon/descendant tracking and checkpoint-based process reattachment. Recovery is retry-oriented, not process memory restoration.

# v4.5 development — LIVE RUNTIME GATE

- Implemented: automatic signed collection of local memory, filesystem and configured thermal telemetry; optional cgroup-v2 ceiling; fresh CAPCTL admission at execution; runtime checks before claim, before process spawn, once per second and before result publication; ties gate to task and node.
- Verified: 26 focused host tests (10 CAPCTL, 12 runtime gate, 4 subprocess tests with controlled lease/CAS doubles). Full integration and hardware evidence remain open. Optional CLI flags wired into phaseexec and phasechat; not exercised end-to-end in the test container.
- Open: automatic attestation renewal, mandatory enforcement across every runtime entry point, cgroup ancestor discovery and kernel-level enforcement, authenticated physical telemetry, actual S24/VPS tests, remote server cancellation and process recovery.

# v4.4 development — CAPCTL

- Implemented: signed node declarations, operator trust and capacity policy, freshness and atomic persistent replay rejection. Optional verified-node JSON input for PHASESHIFT; 10 focused tests passed on Linux/OpenSSL 3.5.5.
- Open: full repository regression, automatic telemetry collection and runtime enforcement of attestation freshness, distributed replay registry, mTLS transport, key rotation procedure, device-backed attestation and actual hardware inference. Signature authenticates a declaration, not its physical truth.

## P0 — po v4.3: uruchomienie prawdziwych modeli

- PHASECHAT obsługuje uruchomienie **zapytania** na gotowym lokalnym llama-server, nie uruchamia automatycznie samych modeli. Wykonać prawdziwy test Qwen GGUF + mmproj na S24 Ultra: memory, temperatura, model_id, poprawność, opóźnienie oraz retry po awarii.
- Potwierdzić hash wag GGUF w Google Drive vs lokalny plik; weryfikacja lineage Qwen/mmproj bez założenia zgodności.
- FLUX/Wan/LTX to osobne rodziny o innych API; nie wolno stosować adaptera llama jako substytutu generowania wideo lub obrazów.
- Prawdziwa kontrola RAM/cgroups i przenoszenie checkpointów pomiędzy hostami pozostaje otwarte.

# v4.2 — stan i następne bramki

**Zaimplementowane i poddane testom hosta:** transakcyjne admission deklarowanego RAM pomiędzy zadaniami i planami w jednej bazie SQLite; fenced `fail`; nadzorowany lokalny subprocess z heartbeat, timeout, ograniczonym logiem i CAS. Nie jest to sprzętowe wymuszanie przydziału RAM ani rozproszony lease.

**Następne P0:** test S24 Ultra/Termux dla rzeczywistego `llama-cli` i `llama-server`, profilowanie temperatury i RAM; adaptery stdout dla faktycznych silników; test przerwania zasilania; stany reattach przy restarcie procesu; podpisane capabilities węzłów; ograniczenia procesów przez sandbox/cgroups tam, gdzie platforma wspiera; prywatne mTLS pomiędzy węzłami; test na prawdziwym VPS/GPU.

# OMEGA-X v4.1 checkpointy CAS — status

**Zaimplementowane lokalnie:** prywatny, adresowany SHA-256 magazyn artefaktów,
atomowa publikacja, weryfikacja przed restore, integracja z SQLite LeaseStore.
**Otwarte:** replika drugi host; niezawodne reattach po restarcie workerów;
zweryfikowana rzeczywista inferencja S24 Ultra/GPU; test przerwania zasilania,
retencja/GC; podpisane capabilities, bezpieczne klucze i zasady polityk.

# OMEGA-X v4 PHASESHIFT — stan potwierdzony

**Lokalnie zaimplementowane:** kompilator DAG z rezerwacją RAM per slot i trwałą rezerwacją dysku, N−1 kontrfaktyczne plany od początku, niezależny weryfikator wykonalności, polityka prywatności dziedziczona po zależnościach, SQLite lease z epoch fencing, hash rzeczywistego pliku, CLI, deterministyczny benchmark syntetyczny.

**P0 nadal otwarte:** rzeczywista inferencja na S24 i VPS GPU; integracja runtime z lease i telemetryką; podpisane aktualne capability; kompletność modeli; bezpieczny transfer danych między węzłami; centralny rozproszony magazyn fencing; testy awarii realnych hostów.

**P1 badawcze:** porównanie z MILP/CP-SAT i współczesnymi schedulerami, pomiar kosztu N−1, energii, opóźnienia i przewagi na realnym sprzęcie, analiza patentowa. Symulacja jest dowodem logiki, nie substytutem dowodu działania fizycznego GPU.

---

# Roadmap OMEGA-X — status dowodowy

## v3.0.0 ATLAS — zaimplementowane w kodzie

- Katalog metadanych Google Drive (44 pliki) i roboczy rejestr 13 modeli; bez weryfikacji ich wag.
- Merkle + Rclone range staging (lokalne i symulowane zdalne), automatyczna naprawa brakujących/uszkodzonych bloków.
- Deterministyczny placement DAG z politykami prywatności, RAM, temperatury i lokalności wag.
- HMAC łańcucha audytu i klient lokalnego OpenAI-compatible llama-server z kontrolą model ID.
- CLI `tools/atlasctl.py`, testy i reprodukowalny ZIP.

## P0 — wymagane do rzeczywistej usługi

- Zgodność i kompletność modeli Wan, FLUX, LTX, Qwen oraz ich encoderów/VAE.
- Połączenie planera z telemetrią runtime i faktycznym uruchamianiem całego pipeline (obecnie plan i wykonanie to osobne komponenty).
- Testy Rclone Google Drive na rzeczywistym koncie, w tym API rate limit, autoryzacja i koszt transferu.
- Prawdziwy S24 Ultra: Termux, inferencja GGUF, model mmproj, test temperatury i pamięci.
- Prawdziwy VPS GPU: ComfyUI/FLUX/LTX/Wan z kompletami modeli i pomiarem kosztów.
- Publiczne podpisy i C2PA: obecny HMAC jest tylko dowodem integralności lokalnej deklaracji.

## P1 — eksperymenty badawcze

- Porównanie transferu ATLAS vs `rclone copyto` w co najmniej 30 przebiegach, różne awarie.
- Adaptacyjny policy engine i kosztowa optymalizacja po pomiarach sprzętowych, nie arbitralnych liczbach.
- Kontrola i podpisanie capabilities, odporność na fałszywą telemetrię, zdalne anchoring głowy audytu.

---

# Roadmap OMEGA-X — stan rzeczywisty

## Wykonane lokalnie w kodzie v2

- Parser GGUF/Safetensors, macierz klasyfikacji z jawnie niezweryfikowanym lineage mmproj.
- SFTP i WebDAV Termux, procesy pod nadzorem i bezpieczną ekspozycją LAN.
- Katalog modeli `1.GGUF-UNCENSORED` używany bez automatycznego kopiowania/zmiany nazwy.
- VPS FTPS i SFTP z odseparowanymi procesami Docker Compose (bez dowodu uruchomienia).
- Worker `sd-cli` z walidacją, stagingiem, idempotencją i realnym wynikiem binarium przed COMPLETE.
- Offload JSON przez Rclone SFTP, auth pin requirement.
- Kopie Rclone Crypt do dwóch celów, HMAC/SHA256 i restore fail-closed.
- Testy lokalne, symulacyjne, negatywne i deterministyczny mechanizm pakowania.

## P0 — nadal otwarte (brak dowodów docelowej infrastruktury)

- Test Termux SFTP (logowanie kluczem), WebDAV, uruchomienie małego GGUF i test temperatury/RAM na rzeczywistym S24.
- Weryfikacja pełnych nagłówków sześciu konkretnych plików i pochodzenia projektora mmproj.
- Docker Compose `config` i rzeczywiste kontenery, FTPS TLS handshake, SFTP chroot, własny VPS.
- Worker `sd-cli` z *kompletnymi* modelami Wan/LTX oraz ffprobe realnego wyniku AVI.
- Prawdziwe 2 niezależne kryptowane chmury, upload, restore na drugim urządzeniu i utrzymanie klucza HMAC.

## P1 — możliwe rozszerzenia po testach sprzętowych

- Akceleracja CPU/GPU po profilowaniu i pinowaniu wersji źródeł, bez arbitralnych deklaracji o OpenCL/NPU.
- API offload z kontrolą uprawnień, mTLS/VPN, trwalszy workflow engine z lease i retry idempotency.
- Monitoring Prometheus i opt-in alerting, rotacja sekretów, regularny restore drill.
- Zaprojektowanie HA storage/skalowania L4 dopiero po wyborze łącza, zasobów i SLA.
