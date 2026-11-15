# OMEGA-X v4.2 — Fenced Execution & Runtime Admission

## Kontrakt implementacji

`atlas.phaselease.LeaseStore` to **lokalny** mechanizm dzierżaw SQLite. Każdy claim jest zapisywany w transakcji `BEGIN IMMEDIATE`. Przed przyznaniem prawa wykonania sprawdza sumę `reserved_ram_mb` aktywnych lease ze wszystkich workflow w tym samym pliku bazy i odmawia, gdy deklarowany przydział przekroczyłby zarejestrowaną pojemność logiczną węzła. Nie odczytuje rzeczywistego wykorzystania RAM, nie wykorzystuje cgroups i **nie** działa jako globalny distributed lock. Różne pliki SQLite nie współdzielą rezerwacji.

Przy inicjalizacji `node_registry` zapisuje deklarowaną pojemność RAM, wolny dysk i klasę zaufania dla identyfikatora węzła. Rozbieżne kontrakty tego samego węzła są odrzucane; dla zmian konfiguracji wymagane jest bezpieczne wygaszenie aktywnych zadań i inicjalizacja nowej bazy albo kontrolowana migracja kontraktu. Aktywne wiersze utworzone przez v4.1 bez informacji o RAM blokują nowe claim na tym węźle, dopóki nie wygasną. Wartości `now=` w testach są symulacyjne; produkcyjny czas jest pobierany z zegara ściennego systemu, więc duże skoki zegara są ryzykiem.

`atlas.execution.SupervisedExecutor` wykonuje tylko jawne argumenty operatora przez `Popen(..., shell=False)`; nic nie pobiera, nie kompiluje modeli i nie wybiera samodzielnie silnika. Wymaga `LeaseStore(..., artifacts=ArtifactStore(...))` ze spójnym magazynem CAS. Zastępuje pojedynczy token `{output}` prywatną ścieżką o losowym sufiksie; wymaga kodu zakończenia 0, obecności zwykłego pliku, dotrzymania deklarowanej wielkości wyniku i ważnej dzierżawy. Wynik jest atomowo wstawiany do CAS, a `COMPLETED` zapisywany dopiero po poprawnej weryfikacji SHA-256. Tymczasowy plik jest sprzątany po publikacji.

Osobny wątek odnawia lease we własnym połączeniu SQLite. Deadline zabija grupę procesów sygnałem TERM, a po 2 sekundach KILL. Stdout+stderr trafiają do prywatnego, ograniczonego rozmiarem logu (nadmiar jest odrzucany, ale pipe pozostaje opróżniany). Nie ma powłoki, ale operator może jawnie przekazać `/bin/sh`; dlatego **nie wolno** przekazywać argumentów z modeli, zdalnych wiadomości lub niezaufanych plików. Proces nadal ma uprawnienia lokalnego użytkownika i może wykonywać efekty uboczne poza ścieżką wyniku; fencing chroni publikację w CAS/SQLite, **nie** gwarantuje exactly-once efektów zewnętrznych.

## Uruchomienie (tryb laboratorium, bez GPU)

Do poniższego scenariusza przygotuj cztery pliki JSON: `tasks.json`, `nodes.json`, `catalog.json`, `plan.json`, tworząc plan przez `tools/phasectl.py compile`. Szczegółowe formaty znajdują się w `docs/PHASESHIFT_RUNBOOK.md`.

```bash
python3 tools/phasectl.py compile --tasks tasks.json --nodes nodes.json \
  --catalog catalog.json --out plan.json --horizon 4

python3 tools/phaseexec.py \
  --tasks tasks.json --nodes nodes.json --catalog catalog.json \
  --plan plan.json --db state/leases.sqlite --cas state/cas \
  --work state/work --task render --node phone --ttl 30 --timeout 600 \
  --suffix .bin -- python3 -c \
  'import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(b"test")' '{output}'
```

Katalog `state/` musi już istnieć i być prywatny (`chmod 700 state`). `--task` i `--node` muszą zgadzać się z zatwierdzonym planem. W komendzie użytkownika **dokładnie raz** musi wystąpić `{output}`, który CLI zastępuje ścieżką pliku. Wynik JSON wypisuje `sha256`, `epoch`, `log_path` i `status`. Drugi identyczny start skończy się odmową, jeżeli pierwsze wykonanie ma stan `COMPLETED`.

## Testy i dowody

```bash
PYTHONPATH=. python3 -m unittest -q tests.test_runtime_admission tests.test_supervised_execution tests.test_phaseexec_cli
bash tools/verify.sh
```

Powyższe testy używają **rzeczywistych procesów Pythona, SQLite i dysku** na hoście; nie uruchamiają modeli AI, GPU ani Androida. Funkcje `termux/omega_node.py`, `vps/media_worker.py` i generatory wideo pozostają odrębne; integracja z nimi wymaga jawnych, przetestowanych adapterów i faktycznych modeli.

## Granice bezpieczeństwa

- SQLite + CAS wymagają lokalnego zaufanego UID i niesymlinkowych katalogów; brak izolacji od innego procesu tego samego użytkownika.
- Nie ma dynamicznego odczytu wolnego RAM podczas claim ani wymuszenia limitów przez kernel; polityki `local_only` są weryfikowane na deklarowanym planie, nie w systemowym sandboxie.
- Wykonawca nie jest odporny na utratę całego dysku/telefonu i nie replikuje CAS.
- Po awarii hosta aktywne dzierżawy wygasają; nowe wykonanie dostaje nowe `epoch`. Zewnętrzne efekty uboczne poprzedniej próby mogą zostać wykonane więcej niż raz; komendy muszą być idempotentne lub mieć osobny mechanizm rozliczania.
- Nie przetestowano S24 Ultra, GPU VPS, faktycznych modeli z Google Drive ani produkcyjnych transferów Rclone w ramach tego wdrożenia.
