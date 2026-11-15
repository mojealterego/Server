## Testy nowego adaptera PHASECHAT

`PYTHONPATH=. python3 -m unittest -v tests.test_phasechat` sprawdza lokalną granicę HTTP, proces potomny oraz CAS. Odpowiedź HTTP pochodzi z `ThreadingHTTPServer` uruchomionego w teście, a nie z wag GGUF. Status `COMPLETED` dowodzi tylko poprawnego wykonania procesu i zatwierdzenia tekstu, nie jakości modelu czy wydajności urządzenia. Kontrakt: `docs/LLAMA_PHASECHAT.md`.

## PHASESHIFT v4 — nowe dowody

Testy `test_phaseshift.py`, `test_phase_properties.py`, `test_phaselease.py`, `test_phase_cli.py`, `test_phasebench.py` sprawdzają harmonogramy, kontrfaktyczne N−1, 200 losowych deterministycznych instancji, zasady prywatności, modyfikacje certyfikatów, lokalne SQLite fencing i prawdziwe hashowanie plików. Benchmark syntetyczny nie potwierdza przewagi wydajnościowej na urządzeniach. `reports/phaseshift_benchmark.json` powstaje podczas `verify.sh` i raportuje liczby z rzeczywistego uruchomienia symulacji.

# Zasady weryfikacji i status dowodowy

Po rozpakowaniu:

```bash
bash tools/verify.sh
python3 tools/package.py
```

Raport `reports/verification.json` zawiera REALNE wyniki lokalnych testów i kompilacji składniowej. `test_restore_integration.py` symuluje granicę `rclone` lokalnie, nie jest integracją prawdziwych dostawców. Testy workera używają atrap procesów `sd-cli`; `ffprobe` sprzętowo nie był testowany. `green-mobile.txt` **musi** pozostać `NOT_RUN_ON_S24_ULTRA` aż do niezależnego testu na telefonie, którego nie zastępują symulacje.

| Rodzaj dowodu | Stan po uruchomieniu verify.sh na hoście |
|---|---|
| Python unit / integration simulation | `PASS` tylko jeżeli faktyczny test runner zakończy z exit=0 i bez failures, errors i skipped |
| `bash -n`, Python compileall | `PASS` albo `FAIL` na hoście |
| Docker Compose config | `NOT_RUN` jeśli brak Dockera |
| Docker kontenery VPS | `NOT_RUN` bez prawdziwego runtime Docker |
| Galaxy S24 Ultra SFTP E2E | `NOT_RUN` do wykonania `termux/device_smoke.sh` |
| Lokalny GGUF i `mmproj` | `NOT_RUN` bez rzeczywistych modeli |
| GPU/NPU, Wan/LTX | `NOT_RUN` bez binariów, wag i sprzętu |
| Rclone w prawdziwej chmurze | `NOT_RUN` bez kont i uwierzytelnienia |

Nie uruchamiaj `tools/package.py --skip-verify` po zmianach kodu. Opcja służy wyłącznie do sprawdzania powtarzalności paczki z niezmienionego, zweryfikowanego drzewa. Ciąg SHA-256 artefaktu musi być publikowany razem z ZIP. Nie deklaruj wydajności bez pomiarów.
