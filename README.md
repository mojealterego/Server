# OMEGA-X Server — PHASESHIFT / ATLAS

Repozytorium docelowe projektu **OMEGA-X v4.0.0 PHASESHIFT + ATLAS**.

## Źródło projektu

- Archiwum bazowe: `OMEGA_STORAGE_AI_v4.0.0.zip`
- SHA-256 archiwum: `c45d249ee11ca6103d970942f943634842779bd8e2bc81d3db9fb3e735be87d8`
- Zawartość archiwum: 90 plików projektu + manifest wejściowy.
- Sposób weryfikacji: CRC ZIP, kontrola SHA256SUMS oraz testy `python3 -m unittest discover -s tests -q`.

**Stan repozytorium:** etap inicjalizacji importu. Sam ten commit NIE oznacza pełnego przeniesienia źródeł ani potwierdzenia wykonania na Androidzie, VPS lub GPU.

## Zakres technologii

- `atlas/`: ATLAS (Merkle staging, placement, audit) i PHASESHIFT (harmonogramowanie N−1, weryfikacja, lokalne lease/fencing).
- `termux/`: serwery SFTP/WebDAV, inwentaryzacja GGUF/Safetensors, zabezpieczenie zasobów.
- `vps/`: kontenery SFTP/FTPS i opcjonalny worker generacji.
- `cloud/`: snapshot, backup i odtwarzanie.
- `tests/`, `tools/`, `docs/`: testy, narzędzia, dokumentacja.

## Zasady bezpieczeństwa

- Nie commituj modeli GGUF/Safetensors, danych użytkownika, kluczy, tokenów ani folderów `vps/secrets/` i `vps/data/`.
- Zapisuj na gałęzi `main`, bez wymuszania historii.
- `READY` w planerze nie oznacza potwierdzonej inferencji.
- Testy syntetyczne nie dowodzą wydajności ani zgodności sprzętowej Samsung Galaxy S24 Ultra.

## Przygotowanie kopii lokalnej

Pełna paczka źródłowa jest oddzielnym artefaktem wersji 4.0.0. Po pobraniu archiwum:

```bash
unzip -q OMEGA_STORAGE_AI_v4.0.0.zip
cd OMEGA_STORAGE_AI_v4.0.0
python3 -m unittest discover -s tests -q
```

Repozytorium jest **publiczne**. Nie przesyłaj prywatnej telemetrii, sekretów ani niezweryfikowanych plików z Google Drive.

## Import kompletnych źródeł (z lokalnej paczki v4)

Repozytorium zostało zainicjalizowane, a podstawowa dokumentacja i zweryfikowany skrypt importu są dostępne na `main`. **Pełne 91 plików źródłowych nie zostało jeszcze opublikowanych w GitHubie.** Do importu potrzebne jest źródłowe archiwum `OMEGA_STORAGE_AI_v4.0.0.zip`.

Na urządzeniu z Pythonem 3.10+ i Gitem (np. Termux), po pobraniu archiwum z rozmowy:

```bash
pkg install -y python git
git clone https://github.com/mojealterego/Server.git
cd Server
python3 scripts/import_bundle.py \
  --archive "$HOME/storage/downloads/OMEGA_STORAGE_AI_v4.0.0.zip" \
  --repo . --commit --push
```

Skrypt sprawdza SHA-256 archiwum, CRC, 90 sum źródeł, listę dozwolonych ścieżek, czystość drzewa Git oraz gałąź `main`. Nie usuwa istniejących plików, nie wykonuje `push --force` i nie publikuje modeli. Wymaga działających poświadczeń GitHub do `git push`.

**Uwaga dla audytu:** poprzedni raport `reports/verification.json` jest historycznym artefaktem testów v4, a nie dowodem wykonania testów na bieżącym sprzęcie.
