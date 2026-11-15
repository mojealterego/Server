# Dwa magazyny Rclone — kopie i odzyskiwanie

## Konfiguracja

`rclone config` → utwórz **dwa niezależne backendy crypt** opakowujące dostawców. Hasła Rclone i klucze nie mogą znajdować się w ZIP. `rclone.conf`: uprawnienia `0600`. Nazwy `crypt1`, `crypt2` są przykładami, nie istnieją automatycznie.

```bash
rclone config
rclone listremotes
rclone lsd crypt1:
rclone lsd crypt2:
```

## Kopia

```bash
cd OMEGA_STORAGE_AI_v2.0.0
bash cloud/backup.sh "$HOME/storage/shared/1.GGUF-UNCENSORED" crypt1:snapshots crypt2:snapshots
```

- Skrypt odrzuca symlinki i pliki specjalne, a nazwy z nowymi liniami oraz ukośniki wstecz są odrzucane przez manifest.
- Obliczany jest SHA-256 wszystkich plików. Każdy zdalny magazyn dostaje snapshot z unikalnym ID; `rclone check --download --one-way` potwierdza przesłane bajty poprzez ponowny odczyt.
- Po weryfikacji pierwotnych plików wysyłane są `SHA256SUMS`, następnie `COMPLETE.json` (HMAC SHA-256 oryginalnego manifestu). Brak znacznika oznacza nieweryfikowany snapshot.
- Błąd dowolnej chmury zwraca kod niezerowy, pozostałe udane kopie są oznaczone indywidualnie; nie ma transakcji ACID pomiędzy chmurami.
- HMAC key: `$HOME/.omega-x/manifest-hmac.key` (autogeneracja, binarne 32 bajty, `0600`). **Utwórz odrębną, offline kopię tego klucza**. Utrata klucza uniemożliwia uwierzytelnione odtwarzanie.

## Restore

```bash
bash cloud/restore.sh crypt1:snapshots/20261115T120000Z-0123456789ab "$HOME/omega-restore"
```

ID musi być dokładnie wypisane po zakończonym backupie. Folder docelowy **nie może istnieć**. Wszystkie pliki trafiają do odizolowanego katalogu staging (na tym samym systemie plików), potem sprawdzany jest HMAC, SHA256SUMS, pełna zgodność listy plików. Finalna publikacja używa `renameat2(RENAME_NOREPLACE)` — brak bezpiecznej implementacji kończy błędem, nie fallbackiem do destrukcyjnego nadpisania.

## Polityka prywatności i niezależności

Rclone Crypt zapewnia szyfrowanie danych w magazynie, nie gwarantuje geograficznej ani administracyjnej niezależności kopii. To operator musi zagwarantować niezależnych dostawców, limity transferów i miejsce. Union z `create_policy=all` jest użytecznym widokiem, lecz nie zastępuje tych kontroli.

**Ważne:** weryfikacja spójności snapshotu wymaga, by źródło nie zmieniało się podczas kopii. Przy źródłach aktywnie zapisywanych zastosuj filesystem snapshot albo wstrzymaj zapisy. `flock` koordynuje wyłącznie uczestniczące w nim procesy OMEGA.
