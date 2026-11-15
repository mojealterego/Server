# ATLAS — obsługa na Termux i VPS

## 1. Przegląd modeli z Google Drive (bez pobierania 8 GB wag)

Katalog `catalog/drive_inventory.json` zawiera **44 rekordy metadanych** odczytanych z udostępnionego folderu Google Drive; `catalog/model_roles.json` zawiera **13 wybranych pozycji** z przypisaną roboczą rolą. Dwa powtórzenia nazwy Qwen i mmproj w Drive nie dowodzą identyczności bajtów. Żaden model nie został pobrany do paczki. Wszystkie `lineage_verified=false` do czasu niezależnej kontroli.

```bash
cd OMEGA_STORAGE_AI_v3.0.0
python3 tools/atlasctl.py inventory --model-dir "$HOME/storage/shared/1.GGUF-UNCENSORED"
```

## 2. Staging z możliwością wznowienia

```bash
# Na urządzeniu z dostępem do źródła i docelowego katalogu ext4
python3 tools/atlasctl.py manifest /sciezka/model.gguf "$HOME/model.merkle.json"
python3 tools/atlasctl.py stage /sciezka/model.gguf "$HOME/staged-model.gguf" "$HOME/model.merkle.json"
python3 tools/atlasctl.py verify-model "$HOME/staged-model.gguf" "$HOME/model.merkle.json"
```

Operacja odczytuje **cały model** w celu wyliczenia sumy SHA-256. Jest strumieniowa, ale nie trwa 2 ms. Staging wymaga pliku źródłowego; nie pobiera automatycznie Google Drive. Przy przerwaniu ponów `stage` z tym samym manifestem. Weryfikowane bloki zostaną wykorzystane ponownie. Publikacja wymaga POSIX hardlink; na Android `~/storage/shared` może być niedostępny — wybierz prywatny katalog Termuksa lub VPS.

## 3. Placement z ochroną prywatności

```bash
python3 tools/atlasctl.py plan --tasks examples/pipeline.json --nodes examples/nodes.json
```

Przykładowe węzły mają **zerowe możliwości wykonawcze** i brak modeli; oczekiwane `BLOCKED`. Dopiero po sprawdzeniu rzeczywistego `llama-server` / `sd-cli`, wolnego RAM i modeli uzupełnij lokalną kopię `examples/nodes.json`. `lineage_verified` ustaw na `true` wyłącznie dla modeli rzeczywiście zweryfikowanych. Zadanie `local_only` nigdy nie zostanie skierowane na VPS.

## 4. Dowody integralności

```bash
mkdir -p "$HOME/.omega-x"
chmod 700 "$HOME/.omega-x"
python3 tools/atlasctl.py audit-keygen "$HOME/.omega-x/atlas-hmac.key"
# Utwórz osobny JSON z polami stage i status, np. {"stage":"llm","status":"completed","prompt":"prywatny tekst"}
python3 tools/atlasctl.py attest --key "$HOME/.omega-x/atlas-hmac.key" \
  --log "$HOME/.omega-x/atlas-audit.jsonl" --record /sciezka/record.json --output /sciezka/wynik.bin
python3 tools/atlasctl.py verify-audit --key "$HOME/.omega-x/atlas-hmac.key" \
  --log "$HOME/.omega-x/atlas-audit.jsonl" --outputs
```

Nie dołączaj klucza HMAC do ZIP, chmury ani repozytorium. Log zawiera **hash promptu**, nie pełny prompt. To dowód integralności deklaracji lokalnego procesu, a nie publiczny podpis wyniku.

## 5. Testy i raport

```bash
bash tools/verify.sh
python3 tools/package.py
```

`reports/verification.json` rozdziela testy hosta od brakujących testów Android, Docker, GPU/NPU, realnej chmury i rzeczywistej inferencji Wan/LTX.

## 6. Nowość: weryfikowane pobieranie brakujących bloków bez pełnego restartu transferu z Google Drive

To rozwiązanie działa z **samodzielnie skonfigurowanym Rclone** (np. `rclone config` i remote `drive:` z dostępem do folderu). Samo podanie URL folderu w ChatGPT nie konfiguruje konta Rclone na telefonie. Nie pobiera się automatycznie cudzych zasobów i nie umieszcza tokenów OAuth w paczce.

```bash
# Najpierw skonfiguruj Rclone i potwierdź dostęp do pliku
rclone lsf drive:MODELE --max-depth 1

# Jednorazowo odczytaj model strumieniowo i zbuduj manifest bloków
# UWAGA: to odczyta CAŁY plik z chmury, choć nie zapisze jego wag lokalnie.
python3 tools/atlasctl.py remote-manifest \
  'drive:MODELE/ltx-2.3-22b-distilled-Q2_K.gguf' "$HOME/ltx.merkle.json" \
  --expected-bytes 8275987488 --chunk-mib 16

# Pobieranie z możliwością wznowienia, każdy blok weryfikowany osobno.
# Wybierz docelowy katalog ext4 z wystarczającą przestrzenią.
python3 tools/atlasctl.py stage-remote \
  'drive:MODELE/ltx-2.3-22b-distilled-Q2_K.gguf' \
  /sciezka/ext4/ltx-2.3-22b-distilled-Q2_K.gguf "$HOME/ltx.merkle.json"
```

`MODELE` to nazwa rzeczywistego katalogu w Twoim Rclone. Google Drive nie musi zachowywać się jak natywny POSIX; `rclone cat --offset --count` odczytuje zakresy, ale rzeczywiste zużycie transferu zależy od backendu. Dokumentacja: https://rclone.org/commands/rclone_cat/.

**Model bezpieczeństwa:** manifest wygenerowany z tego samego niezaufanego źródła dowodzi jedynie spójności kolejnych odczytów, nie autentyczności wydawcy modelu. Gdy dysponujesz niezależną sumą SHA-256, dodaj `--expected-sha256 HEX` przy `remote-manifest`. Nie uruchamiaj pobranych `.ckpt` jako kodu. Nie stosuj tej procedury do modeli, które nie mieszczą się na dysku docelowym.

## 7. Rzeczywiste wywołanie lokalnego llama-server z audytem

Po uruchomieniu `llama-server` na `127.0.0.1:8082` i sprawdzeniu jego `GET /v1/models`:

```bash
curl -s http://127.0.0.1:8082/v1/models
# Zapisz prompt do prywatnego pliku, np. printf '%s' 'Opisz scenę.' > "$HOME/prompt.txt"
python3 tools/atlasctl.py run-local \
  --prompt-file "$HOME/prompt.txt" \
  --model-id 'DOKLADNY_ID_Z_V1_MODELS' \
  --output "$HOME/omega-response.txt" \
  --log "$HOME/.omega-x/atlas-audit.jsonl" \
  --key "$HOME/.omega-x/atlas-hmac.key"
```

Po zapisaniu wyniku zachowaj `head` zwrócony przez `verify-audit` poza urządzeniem (np. w niezależnym magazynie). W kolejnym audycie przekaż `--expected-head`, aby wykryć także obcięcie historii.

`run-local` korzysta wyłącznie z `http://127.0.0.1:PORT`, blokuje przekierowania i proxy, sprawdza identyfikator modelu zadeklarowany przez serwer, zapisuje odpowiedź bez nadpisania oraz dopisuje jej SHA-256 do łańcucha HMAC. Identyfikator modelu pochodzi z serwera i **nie stanowi dowodu**, że konkretne wagi zostały załadowane. Test integracyjny uruchamia rzeczywisty serwer HTTP imitujący protokół, nie prawdziwy model.
