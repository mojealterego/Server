# OMEGA-X v4.3.0 — PHASECHAT: faktyczne wywołanie lokalnego llama-server

## Co działa

`tools/phasechat.py` łączy cztery wcześniej niezależne granice: zatwierdzony plan PHASESHIFT, pojedynczą dzierżawę i rezerwację deklarowanego RAM SQLite, wywołanie HTTP do **lokalnego** `llama-server` oraz zapis wyniku do CAS SHA-256. Proces modelu musi już działać na tej samej maszynie (lub przez uwierzytelniony lokalny tunel przygotowany przez operatora). Uruchomienie, pobieranie i zgodność wag nie jest automatyczne.

`llama-server` obsługuje `/health`, `/v1/models` i `/v1/chat/completions`; adapter oczekuje `GET /health` → `200` z `{"status":"ok"}` i może czekać na `503` podczas ładowania modelu. Wymaga jednoznacznego identyfikatora z `/v1/models`, wykonuje dokładnie jeden POST bez retry i tylko wtedy przyjmuje odpowiedź tekstową. POST nie jest idempotentny z punktu widzenia modelu: po awarii może być konieczne ponowne obliczenie odpowiedzi. Retry POST nie jest wykonywany samoczynnie.

## Uruchomienie (Termux albo host Linux)

1. Uruchom na danym hoście **zaufanego**, dostępnego tylko przez loopback `llama-server`, np. `llama-server --model /bezpieczna/sciezka/model.gguf --host 127.0.0.1 --port 8082 --parallel 1`. Zobacz `termux/omega_node.py` dla obsługi GGUF, mmproj, RAM i temperatury. **Nie wystawiaj nieautoryzowanego endpointu na sieć.**
2. Uruchom `curl http://127.0.0.1:8082/health` i `curl http://127.0.0.1:8082/v1/models`. Odczytaj dokładny `data[].id`, ponieważ nie można go bezpiecznie zgadnąć z nazwy GGUF.
3. Przygotuj w katalogu prywatnym `tasks.json`, `nodes.json`, `catalog.json` i wyliczony plan `plan.json`. Zadanie z `engine=llama` powinno zawierać `"models":["qwen"]` (alias katalogowy) i **jawne** `"runtime_model_ids":{"ID_Z_V1_MODELS":"qwen"}`. Klucz to ID serwera, wartość to alias modelu z katalogu. Wiązanie musi znajdować się w JSON przed kompilacją planu, aby certyfikat dokumentował tę decyzję operatora. Nie stanowi atestacji kryptograficznej rzeczywistych wag.
4. Zapewnij prywatny katalog stanu, np. `mkdir -m 700 state`. Zapisz prompt w zwykłym, niesymlinkowym pliku UTF-8 (maks. 32 KiB i 8192 znaków). Narzędzie nie przyjmuje promptu w argv.

```bash
python3 tools/phasectl.py compile \
  --tasks tasks.json --nodes nodes.json --catalog catalog.json \
  --out plan.json --horizon 8

python3 tools/phasechat.py \
  --tasks tasks.json --nodes nodes.json --catalog catalog.json \
  --plan plan.json --db state/leases.sqlite --cas state/cas \
  --work state/work --task describe --node s24 \
  --endpoint http://127.0.0.1:8082 --model 'ID_Z_V1_MODELS' \
  --prompt-file prompt.txt --ready-timeout 30 --request-timeout 90 \
  --timeout 180 --ttl 30 --max-tokens 256
```

`phasechat.py` wypisuje dowód wykonania jako JSON zawierający m.in. `status=COMPLETED`, `sha256`, `epoch`, `log_path`. Wyświetlenie wyniku wymaga `python3 tools/casctl.py ...` (patrz `--help`) albo bezpośredniego odczytania zweryfikowanego pliku w `state/cas/objects/<sha256>`. Dzierżawa pozostaje `FAILED`, jeżeli wywołanie HTTP zakończyło się błędem, proces przekroczył limit, odpowiedź ma niewłaściwą strukturę lub plik nie został opublikowany.

## Zabezpieczenia i ograniczenia

- Adresy HTTP ograniczone do **dosłownego** `127.0.0.1:PORT`, bez przekierowań i proxy; brak zdalnego rozpoznawania DNS i publicznego API. VPS wymaga osobnego wykonania polecenia na VPS, nie wolno go zastąpić publicznym URL.
- `POST /v1/chat/completions` wykonuje się najwyżej jeden raz podczas próby; `GET /health` (kod 503) może być ponawiane przez ograniczony czas. Maksymalny rozmiar odpowiedzi JSON: 2 MiB; wynik w CAS to zwykły tekst odpowiedzi (bez obrazu/audio).
- Polecenie subprocess jest budowane wewnętrznie, bez `shell=True`, z kodu `tools/llama_job.py` i wyłączonym `PYTHONPATH` (`-I`); polecenia nie są pobierane z odpowiedzi LLM.
- Katalog CAS oraz baza SQLite pozostają lokalnymi komponentami. Nie ma rozproszonego locka, HA, atestacji backendu, GPU quota ani weryfikacji rzeczywistego GGUF SHA-256 z chmurą. Przez `/v1/models` kontrolowana jest deklaracja **serwera**, a nie autentyczność modelu.
- Operacje zewnętrzne i sam POST nie gwarantują `exactly once`; fencing chroni zatwierdzenie CAS/SQLite. Używaj jednego lokalnego użytkownika i prywatnych katalogów, bez niezaufanych procesów o tym samym UID.
- Tożsamość wag i kompatybilność mmproj muszą być sprawdzone osobno; nie zbadano fizycznie Samsung S24 Ultra ani VPS w tym teście.

## Dowody

`PYTHONPATH=. python3 -m unittest -v tests.test_phasechat` uruchamia faktyczny lokalny serwer HTTP, proces adaptera, SQLite LeaseStore i CAS na hoście, w tym odmowy dla symlinków, zewnętrznego hosta, niezarejestrowanego modelu, błędnej odpowiedzi i duplikatów. **HTTP jest implementacją testową, nie prawdziwym modelem.**

Dokumentacja API źródłowego: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
