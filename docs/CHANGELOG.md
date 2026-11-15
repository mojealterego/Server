## v4.2.0 — deklaratywne rezerwacje RAM + nadzorowany wykonawca

- SQLite runtime admission sprawdza sumę aktywnych dzierżaw dla pojedynczego `node_id` w **wspólnym** DB. Wynik kompilacji slotów nie jest już traktowany jako autoryzacja do uruchomienia równoczesnego.
- Nowe pola `reserved_ram_mb`, `last_error`, tabela `node_registry`; automatyczna migracja bazy v4.1. Aktywne legacy lease bez kolumn rezerwacji blokują admission do wygaśnięcia. Zmiana statycznego kontraktu pojemności wymaga nowego pliku SQLite po wygaśnięciu aktywnych lease.
- `LeaseStore.fail()` sprawdza epoch/token i zapisuje trwały kod błędu, udostępniając zasób na retry.
- `SupervisedExecutor` uruchamia **rzeczywisty lokalny** proces bez powłoki, odnawia dzierżawę, ogranicza stdout do prywatnego logu, wymusza timeout i publikuje tylko zweryfikowany plik do CAS.
- CLI `tools/phaseexec.py` i test pełnego przebiegu. Brak automatycznej migracji węzłów, rzeczywistego cgroup, akceleracji GPU ani uruchamiania niezaufanych poleceń.
- Uporządkowany `tools/verify.py`: benchmark syntetyczny jest uruchamiany raz, a nie dwukrotnie.

## v4.1.0 — lokalne trwałe checkpointy
- Dodano SHA-256 CAS z atomową publikacją, fsync i odtwarzaniem bez nadpisywania.
- SQLite LeaseStore może wymuszać integralność zależnych wyników przed przydziałem.
- CLI i testy adversarial + współbieżność.
- Bez obietnicy HA, mobilnego E2E ani produkcyjnego GPU.

## v4.0.0 — PHASESHIFT (2026-11-15)

- Nowy solver counterfactual N−1 z bezpiecznym budżetem przeszukiwania, fail-closed i rezerwacjami.
- Weryfikator niezależny od algorytmu wyszukiwania i odporność na sfałszowane przypisania nawet po przeliczeniu SHA-256.
- Lokalny SQLite fencing lease, zależności, atomowy claim, renew, complete z SHA-256 pliku.
- CLI `phasectl.py`, benchmark syntetyczny, property-based style seeded 200 cases, testy współbieżności.
- Bez zmian w Google Drive i repozytoriach GitHub.

# Changelog

## v3.0.0 — ATLAS (eksperymentalna integracja technologiczna)

- Spis metadanych 44 plików z folderu Google Drive, 13 wybranych modeli w katalogu roboczym (wszystkie `lineage_verified=false`).
- Merkle model staging: strumieniowy manifest SHA-256, wznowienie po przerwaniu, naprawa uszkodzonych bloków, publikacja bez nadpisania.
- Rclone remote range staging: `rclone cat --offset --count`, tylko brakujące bloki; manifest z chmury bez lokalnego zapisu wag.
- Deterministyczny placement z DAG, prywatnością `local_only`, pamięcią, temperaturą, lokalnością modeli i jawnym `BLOCKED`.
- Lokalny łańcuch HMAC z kontrolą integralności wyników, haszowaniem promptów i opcjonalnym oczekiwanym hashem głowy.
- Klient lokalnego llama-server z walidacją model ID, blokadą SSRF/proxy/redirect, zapisem bez nadpisania i audytem.
- Badawcza specyfikacja hipotez, testy negatywne i dokumentacja CLI. Brak deklaracji pierwszeństwa światowego.

## v2.0.0 — poprawki bezpieczeństwa i odtwarzalności

- Safetensors: walidacja zakresów i dtype, w tym negatywnych wymiarów, overlap/hole, niezgodnych długości.
- `omega_node`: jawny `--allow-lan`, odmowa wildcard bind do sieci.
- Backup: snapshoty niezależnych kryptowanych miejsc, SHA-256, weryfikacja przez odczyt, lokalny HMAC-SHA256, commit-last.
- Restore: fail-closed przy braku HMAC, uszkodzonych wagach, podejrzanych ścieżkach, istniejącym katalogu docelowym; atomowy no-replace `renameat2` na Linuksie.
- Worker: wymóg `--mode vid_gen`, format AVI, staging wyjścia, `ffprobe` w profilu produkcyjnym, trwałe idempotency keys, limit kolejki, walidacja pól i wyłączenie silent completion.
- Offload: bezpieczna publikacja JSON w kolejce VPS przez Rclone SFTP z przypiętym host key; bez HTTP API publicznego.
- `doctor.py`: odczyt zasobów i braków z lokalnego systemu, bez roota ani fałszywych testów urządzenia.
- Bezpieczniejsze pakowanie: jawna allowlist plików, spis SHA-256, odrzucanie testów czerwonych/pominiętych.
- Nowe testy regresyjne, HMAC/corruption/path traversal/duplicate IDs/restore round-trip (symulacja granicy Rclone).

## v1.0.0 — baza

- Termux SFTP/WebDAV/LLM supervisor, parsy GGUF/Safetensors, kontroler RAM/temp, VPS FTPS/SFTP, podstawowa kolejka mediów, backup Rclone.

## Znane ograniczenia

- Brak niezależnej walidacji na rzeczywistym Galaxy S24 Ultra.
- Brak sprzętowej kompilacji/inferencji Snapdragon NPU i GPU.
- Brak kont chmurowych, hosta VPS, niezależnych nośników, wag dużych modeli i binariów `sd-cli`.
- `renameat2` dla bezpiecznej publikacji może być niedostępne w niektórych środowiskach, wtedy restore przerywa zamiast ryzykować overwrite.
- Współbieżna zmiana źródła po weryfikacji to ryzyko TOCTOU; dla spójnych backupów mutable danych wymagane migawki FS / zamrożenie zapisów.
