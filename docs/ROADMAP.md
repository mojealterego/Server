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
