# OMEGA-X v5.4a + STORAGE-05 development

Same-host authority lock and quiesced coordinator checkpoints with verified lease/replay and completed CAS recovery; pinned three-share SMB recovery sets with verified replica failover and atomic offline publication. See [HA recovery](docs/HA_CONTROL_PLANE.md) and [storage recovery](docs/STORAGE_FAILOVER.md). 21 focused cases passed. Cross-host HA, automatic SMB failover and full-repository/physical qualification remain open.

# OMEGA-X v5.3 + STORAGE-04 development

Bounded parallel CAS replication with compatible manifests, model-only SMB3 identity, Samba VFS audit configuration and persisted dedicated-filesystem capacity checks. See [parallel CAS](docs/BULK_CAS.md) and [SMB access and capacity](docs/SMB_ACCESS_CAPACITY.md). 11 new and 40 selected regression cases passed in split local runs. Physical throughput, live SMB and volume qualification remain open.

# OMEGA-X v5.2b + STORAGE-03 development

Persistent administrator retry ceilings across failover generations, bounded lease-expiry watcher, and content-addressed versioned SMB share snapshots with explicit encrypted-replica export and atomic restore. See [retry policy](docs/RETRY_POLICY.md) and [SMB snapshots](docs/SMB_SNAPSHOTS.md). 18 new and 42 selected regression tests passed; physical failover, actual SMB/Rclone/provider tests and full repository regression remain open.

# OMEGA-X v5.2a + STORAGE-02 development

Fenced operator-confirmed PHASESHIFT restart after node failure and signed per-model SMB cache with Merkle resume and verified replica failover. See [failover](docs/FAILOVER.md) and [storage cache](docs/STORAGE_CACHE.md). 17 new tests and 33 selected regression tests passed. Automatic migration, real SMB/mobile qualification and full repository validation remain open.

# OMEGA-X v5.1 development — autonomous node scheduler

Certified network stages can now run via `atlas.dispatch_worker --schedule`, with readiness polling, bounded retry, backoff and remote epoch budget checks. See [scheduler runbook](docs/SCHEDULER.md). 11 new unit tests plus 13 dispatch tests passed, including two new integration tests. The parallel SMB2/SMB3 storage track remains active.

# OMEGA-X / OMEGA STORAGE — dual-track development

SMB2/SMB3 native Samba service added as an opt-in VPS profile. Three isolated shares, separate credentials, encrypted SMB3 storage and read-only models. [SMB runbook](docs/SMB_STORAGE.md). 11 focused local tests passed; actual Samba/Docker and device qualification remain open. Autonomous scheduler v5.1 remains open.

# OMEGA-X v5.0 development — AUTHENTICATED HYBRID EXECUTION

Central fenced dispatcher, authenticated remote typed-stage worker, live lease renewal, and resumable mTLS dependency/output transfers into CAS. See [hybrid runbook](docs/HYBRID_DISPATCH.md). 11 new and 68 selected regression tests passed locally; a physical S24/VPS deployment, automatic scheduler polling and coordinator HA remain open.

# OMEGA-X v4.9 development — MULTIMODAL ORCHESTRATOR

Typed local DAG execution for Qwen text, FLUX.1 PNG, Wan T2V/I2V and LTX-2 AVI, with fenced execution, verified CAS dependencies and explicit retry. See [multimodal runbook](docs/MULTIMODAL.md). 24 new cases and 35 selected regressions passed locally with synthetic engines; physical inference and distributed dispatch remain open.

# OMEGA-X v4.8 development — mTLS CAPABILITY GATEWAY

Private TLS 1.3 admission transport with mutual certificate verification, certificate pinning tied to CAPCTL node identity, Ed25519 policy checks and durable anti-replay state. See [mTLS runbook](docs/MTLS_MESH.md). 26 focused tests passed, including real local TLS and separate CLI processes. Full peer-to-peer mesh and real Android/VPS deployment remain open.

# OMEGA-X v4.7 development — REPLICATED CAS

Resumable content-addressed block replication, pinned manifests, per-block failover and local atomic CAS restoration. See [replication runbook](docs/REPLICATION.md). 12 focused tests passed in groups plus a CLI smoke test using a controlled Rclone process double; actual cloud, device and whole-repository regression remain open.

# OMEGA-X v4.6 development — LOCAL RECOVERY

Mandatory local per-node execution exclusion for SupervisedExecutor, a guardian monitoring supervisor death, inherited kernel locks, and an immediate RUNTIME_GUARD lease failure fix. See [RECOVERY runbook](docs/RECOVERY.md). 35 focused tests passed with real crash injection; full repository and hardware regression remain pending.

# OMEGA-X v4.5 development — LIVE RUNTIME GATE

Optional signed live telemetry admission and continuous local supervision for phaseexec/phasechat. See [runtime gate runbook](docs/RUNTIME_GATE.md). 26 focused local tests passed (including v4.4 tests); no full regression or hardware inference claimed.

# OMEGA-X v4.4 development — CAPCTL

New optional admission gate for PHASESHIFT: Ed25519 signed node declarations, pinned per-node keys, operator capacity limits and durable SQLite replay rejection. See [CAPCTL runbook](docs/CAPCTL.md). Ten focused host tests passed; full repository regression and mobile hardware validation remain pending. Existing v4.3 reports are historical, not results for v4.4.

# OMEGA-X v4.3.0 — PHASESHIFT / ATLAS / FENCED EXECUTION


## v4.3: PHASECHAT — wykonanie zapytań lokalnego llama-server w obrębie planu

- `atlas/llama_job.py`: ograniczony do `http://127.0.0.1:PORT` klient health/model/chat, bez proxy, przekierowań i automatycznych powtórzeń POST.
- `tools/llama_job.py` i `tools/phasechat.py`: jedno uruchomienie modelu lokalnego (jeżeli server **już działa**) pod rzeczywistą dzierżawą `SupervisedExecutor`; wynik tekstowy jest sprawdzany, zatwierdzany w CAS SHA-256 i powiązany ze stanem SQLite.
- Jawna mapa `runtime_model_ids` w zadaniu, z certyfikatem planu; model ID serwera nie potwierdza kryptograficznie wag.
- Testy integracyjne uruchamiają rzeczywisty HTTP loopback + subprocess + CAS, ale **serwer odpowiada fikcyjnym tekstem**; nie jest to test prawdziwego modelu ani sprzętu.
- Szczegóły `docs/LLAMA_PHASECHAT.md`.

## v4.2: runtime RAM admission + supervised, fenced execution

- `atlas/phaselease.py`: transakcyjne, międzyworkflowowe przydziały deklarowanego RAM dla węzła w **jednym** pliku SQLite; wersjonowanie schematu z fail-closed dla starych, aktywnych wpisów bez rezerwacji; `fail()` zwalnia pamięć logiczną bez czekania na wygaśnięcie.
- `atlas/execution.py`: rzeczywisty proces lokalny z `shell=False`, kontrolą deadline, heartbeat w osobnym połączeniu SQLite, odcięciem niepowodzeń, ograniczeniem rozmiaru logu i publikacją SHA-256 do trwałego CAS **tylko po kodzie wyjścia 0 i weryfikacji wyniku**.
- `tools/phaseexec.py`: CLI operatora, łączący plan, rezerwację, proces i wynik. Szczegóły w `docs/EXECUTION.md`. Proponowane komendy są jawne i zaufane; **nie wykonuj poleceń generowanych przez modele**.
- Testy regresyjne obejmują równoczesne claim, blokadę przekroczenia RAM, dwa osobne plany, timeout, realny subprocess, CAS, wznowienie i heartbeat.

**Ważne:** jest to warstwa wykonania lokalnego na Linux/Termux, **nie** potwierdzona inferencja na Snapdragonie/GPU, rozproszony system lease ani bezpieczny sandbox. Przydział RAM dotyczy deklarowanych zasobów i nie wymusza limitu fizycznie (cgroups). Zmiennych możliwości urządzenia nie należy mylić z twardymi gwarancjami.

Zgodnie z bieżącym trybem projektu źródła trafiają też do repozytorium `mojealterego/Server` na gałęzi `main`; nie są przenoszone modele ani sekrety.

---

**Nowa warstwa v4:** kontrfaktyczne planowanie N−1, weryfikowalne certyfikaty ograniczeń, propagacja prywatności w DAG, transakcyjne lease SQLite z fencing i sprawdzaniem SHA-256 rzeczywistego pliku wynikowego. Wszystkie komponenty działają lokalnie na Python stdlib, bez API płatnych usług.

- `atlas/phaseshift.py`: ograniczony solver harmonogramu i planów N−1.
- `atlas/phaseverify.py`: niezależna weryfikacja RAM/dysk/DAG/prywatność/scenariusze.
- `atlas/phaselease.py`: lokalne, trwałe tokeny fencing (nie rozproszony lock).
- `tools/phasectl.py`: compile / verify / claim / renew / complete / status.
- `tools/phasebench.py`: powtarzalny benchmark **syntetyczny**, nie sprzętowy.
- `docs/PHASESHIFT_RESEARCH.md` oraz `docs/PHASESHIFT_RUNBOOK.md`: teoria, falsyfikacja i komendy.

```bash
python3 tools/phasectl.py --help
python3 tools/phasebench.py --cases 200
bash tools/verify.sh
```

**Status:** działająca, testowana lokalnie warstwa planowania i lokalnego admission; bez dowodu inferencji S24/VPS, bez automatycznej migracji GPU, bez sprzętowego testu modeli z Drive. Nie ma potwierdzenia pierwszeństwa światowego ani przełomu rynkowego. Starsze funkcje v3 pozostają w paczce.

---

# OMEGA-X v3.0.0 — ATLAS: Adaptive Tensor Logistics & Autonomous Scheduling

**Rozszerzenie v2.0.0 o rzeczywistą warstwę zarządzania modelami, zasobami i dowodami.** Archiwum package-only, bez modyfikacji GitHub i bez kopiowania wag z Google Drive.

## Nowe komponenty v3.0.0

- `atlas/merkle.py` + `atlas/remote.py` — strumieniowe hashowanie, blokowy staging, wznowienie pobierania brakujących fragmentów z Rclone oraz atomowa publikacja bez nadpisania.
- `atlas/planner.py` — deterministyczny placement z ochroną prywatności, RAM, temperaturą, lokalnością modeli i zależnościami DAG.
- `atlas/audit.py` — łańcuch rekordów HMAC-SHA256, integralność wyniku, haszowanie prywatnego promptu i kontrola zewnętrznego zakotwiczenia głowy logu.
- `atlas/runner.py` — rzeczywisty klient lokalnego llama-server: wyłącznie loopback, bez przekierowań i proxy, z audytem wyniku.
- `tools/atlasctl.py` — działające CLI; `catalog/` — 44 metadane Google Drive i 13 modeli priorytetowych.
- `docs/ATLAS_RUNBOOK.md` — konkretne komendy; `docs/ATLAS_RESEARCH.md` — hipoteza, kryteria falsyfikacji i ograniczenia.

**Uruchomienie i weryfikacja:**

```bash
python3 tools/atlasctl.py --help
python3 tools/atlasctl.py plan --tasks examples/pipeline.json --nodes examples/nodes.json
bash tools/verify.sh
python3 tools/package.py
```

**Ważne:** `READY` w plannerze nie oznacza wykonanej inferencji. Nie twierdzimy, że technologia jest pierwsza na świecie, że istnieje zdalne mmap ani że Snapdragon NPU został uruchomiony. Połączone funkcje to zweryfikowana lokalnie implementacja badawcza, nie gotowy produkt rynkowy.

## Dotychczasowy stos v2.0.0 (zachowany)

### Secure Mobile Storage & AI Fabric

**Wersja źródłowa, package-only.** Dwa serwery (Samsung Galaxy S24 Ultra / Linux VPS), dwa poziomy pamięci masowej (telefon i niezależne szyfrowane magazyny), lokalna inferencja GGUF i opcjonalny worker Wan/LTX. Wszystkie polecenia dotyczą **własnej** infrastruktury. Bez zmian w repozytoriach GitHub. W paczce nie ma modeli, kont chmurowych, sekretów, binariów GPU ani APK.

## Nowości v2.0.0 wobec v1.0.0

1. **Prawdziwa integralność backupów**: streaming SHA-256 każdego pliku, dwie niezależne kopie na rclone crypt (jeżeli skonfigurowane), HMAC-SHA256 manifestu z lokalnym kluczem, znacznik zatwierdzenia publikowany jako ostatni, odtwarzanie do nowego katalogu przez atomowe `renameat2(RENAME_NOREPLACE)` na Linuksie.
2. **Bezpieczny parser Safetensors**: walidacja dtype, kształtów, rozmiarów, nakładania się i dziur w zakresach tensorów; GGUF v2/v3 czytany bez ładowania wag; projektor `mmproj` nadal wymaga weryfikacji pochodzenia.
3. **Naprawiony worker wideo**: `sd-cli --mode vid_gen`, wynik `.avi` zamiast nieobsługiwanego z założenia `.mp4`, staging i publikacja dopiero po weryfikacji; stan `COMPLETED` w profilu `media` wymaga pozytywnego `ffprobe`. Idempotencja poprzez trwały plik rezerwujący ID oraz limit 64 oczekujących zadań.
4. **Bezpieczny transport zleceń**: `termux/offload.py` przesyła JSON do kolejek VPS przez Rclone SFTP z wymaganym przypiętym kluczem hosta. Nie przenosi automatycznie wag modeli.
5. **Audyt runtime**: `tools/doctor.py` raportuje brakujące binaria, katalog modeli, miejsce, CPU affinity, RAM i porty bez twierdzenia, że testuje połączenia E2E.
6. **Pakowanie allowlist**: tylko zatwierdzone ścieżki źródeł i raportów, bez kluczy i magazynów danych. `SHA256SUMS` i weryfikacja ZIP.

## I. Termux na Samsungu Galaxy S24 Ultra (bez roota)

1. Pobierz ZIP i skopiuj do systemowego Android `Download`.
2. W Termuksie:

```bash
pkg update && pkg upgrade -y
pkg install -y python unzip
termux-setup-storage
cp "$HOME/storage/downloads/OMEGA_STORAGE_AI_v2.0.0.zip" "$HOME/"
cd "$HOME"
unzip -o OMEGA_STORAGE_AI_v2.0.0.zip
cd OMEGA_STORAGE_AI_v2.0.0
bash termux/install-termux.sh
```

3. Uruchom **diagnostykę bez zmian systemowych** i inwentaryzację modeli:

```bash
export OMEGA_MODEL_DIR="$HOME/storage/shared/1.GGUF-UNCENSORED"
python3 tools/doctor.py --model-dir "$OMEGA_MODEL_DIR" --json-out "$HOME/.omega-x/doctor.json"
python3 termux/model_inventory.py --dir "$OMEGA_MODEL_DIR" --json-out "$HOME/.omega-x/models.json"
# UWAGA: następne polecenie odczyta wszystkie wagi, może trwać długo
python3 termux/model_inventory.py --dir "$OMEGA_MODEL_DIR" --sha256 --write-manifest "$HOME/omega-models.sha256"
```

4. Uruchom bezpieczne serwery plików na loopback:

```bash
python3 termux/omega_node.py run
```

W nowej sesji: `python3 termux/omega_node.py status`. Port SFTP `127.0.0.1:2022`, WebDAV `127.0.0.1:8081`. **Nawiązanie TCP nie jest testem uwierzytelnienia.** Opcjonalnie wystaw SFTP tylko na dokładny prywatny IPv4: `python3 termux/omega_node.py run --sftp-bind 192.168.1.50 --allow-lan` (zastąp własnym adresem, chroń firewallem/VPN). Bind `0.0.0.0` jest odrzucany.

5. Opcjonalny model językowy (nie LTX/Wan):

```bash
bash termux/build_llama.sh
# Po weryfikacji nagłówka i wersji konkretnego modelu:
MODEL='/pełna/ścieżka/do/Huihui-Qwen*.gguf'  # ZASTĄP dosłowną, poprawną ścieżką (bez gwiazdki)
python3 termux/omega_node.py run --model "$MODEL" --threads 4 --context 2048
```

Uruchamiaj **jednego** supervisora naraz. `--mmproj` tylko po potwierdzeniu zgodności pochodzenia. Mapowanie pamięci (`mmap`) przez Android Scoped Storage może różnić się od natywnego UFS; nie zakładaj gwarantowanego „zero-copy”.

Pełny przewodnik: `docs/ANDROID_RUNBOOK.md`.

## II. VPS (Linux / Docker Compose)

```bash
cd OMEGA_STORAGE_AI_v2.0.0
mkdir -p vps/secrets vps/data
cp ~/.ssh/id_ed25519.pub vps/secrets/authorized_keys
sudo chown -R 10001:10001 vps/data
bash vps/init.sh --self-signed-lab   # WYŁĄCZNIE lab lokalny
cd vps
docker compose config
docker compose up -d --build
docker compose ps
```

Domyślnie FTPS `127.0.0.1:2121`, SFTP `127.0.0.1:2222`, PASV `50000–50015`. Nie istnieje gotowy „darmowy VPS GPU” do LTX/Wan: potrzebna jest faktyczna zgodna maszyna, wagi i `sd-cli`. Worker profilu `media` pozostaje wyłączony do jawnego włączenia i konfiguracji. `docs/VPS_RUNBOOK.md`.

## III. Dwa zaszyfrowane magazyny, kopia, odtwarzanie

Skonfiguruj w `rclone config` **minimum dwa faktycznie niezależne** remotes `crypt` (np. `crypt1:` i `crypt2:`), gdzie każdy `crypt` ma osobny dostawcę lub niezależny obszar awarii. Następnie:

```bash
# Opcjonalny łączny widok (to nie jest proof backupu)
bash cloud/make_union.sh omega-mirror crypt1:models crypt2:models

# Migawki bez nadpisywania, weryfikacja pobranych bajtów i HMAC
bash cloud/backup.sh "$HOME/storage/shared/1.GGUF-UNCENSORED" crypt1:snapshots crypt2:snapshots

# Odtwarzanie wymaga klucza $HOME/.omega-x/manifest-hmac.key,
# nowej, NIEISTNIEJĄCEJ ścieżki i identyfikatora wypisanego przez backup.
bash cloud/restore.sh crypt1:snapshots/IDENTYFIKATOR_MIGAWKI "$HOME/omega-restore"
```

**Krytyczne**: `manifest-hmac.key` przechowuj w bezpiecznej kopii **poza magazynami**, które podpisuje, i nigdy nie umieszczaj go w repozytorium/ZIP. Bez niego odtworzenie z uwierzytelnieniem zostanie odrzucone. Nie traktuj dwóch nazw Rclone jako dowodu niezależności dostawców. `docs/CLOUD_RUNBOOK.md`.

## IV. Kolejka generacji wideo na VPS

Lokalny JSON zadania (patrz `docs/VPS_RUNBOOK.md`) wyślij z Termuksa do **przypiętego SSH**:

```bash
python3 termux/offload.py job.json --remote vps-sftp:queue/pending
```

`vps-sftp` to **Twoja** ręcznie skonfigurowana nazwa w `rclone config` z `host_keys` lub `known_hosts_file`. Serwer VPS musi już posiadać właściwe binaria i **zgodne z silnikiem** wagi w `vps/models`. Worker odrzuca zlecenia niezgodne ze schematem, utrwala historię identyfikatorów i zapisuje statusy w `data/queue/outputs/*.status.json`. Nie twierdzimy, że modele z fotografii są już kompletnym pakietem zgodnym z Wan/LTX.

## V. Dowody i status

```bash
bash tools/verify.sh
python3 tools/package.py
# po tym: archiwum obok katalogu projektu
```

`reports/verification.json` dokumentuje testy wykonane na hoście (w tym testy symulowanego Rclone i `sd-cli`) i osobne `NOT_RUN` dla S24 Ultra, Docker, GPU/NPU, rzeczywistego Wan/LTX i transferu do chmur. `reports/green-mobile.txt` pozostaje świadomie **NOT_RUN_ON_S24_ULTRA**. Brak fikcyjnego TTFT, GB/s, 8K lub gwarancji 24/7. Testy sprzętowe `termux/device_smoke.sh` wykonaj osobiście na telefonie, dopiero po uruchomieniu serwera i zaakceptowaniu odcisku SSH.

**Dokumenty:** `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/PERFORMANCE.md`, `docs/SECURITY.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`, `docs/VERIFICATION.md`.


## v4.1: checkpointy CAS

Nowy magazyn `atlas/artifacts.py` zapisuje wyniki pod SHA-256 i sprawdza
ich integralność przed uruchomieniem zależnych etapów.
`tools/casctl.py` zapewnia `put`, `verify`, `restore` bez nadpisania danych.
Szczegóły: `docs/RELIABLE_CHECKPOINTS.md`; nie jest to rozproszony CAS.
