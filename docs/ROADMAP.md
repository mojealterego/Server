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
