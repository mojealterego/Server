# PHASESHIFT v4 — uruchomienie offline (Termux / Linux)

Wymaga Python 3.10+ i standardowej biblioteki. Nie pobiera modeli i nie uruchamia GPU.

## 1. Syntetyczny test kompilatora i weryfikatora

```bash
cd OMEGA_STORAGE_AI_v4.0.0
python3 tools/phasectl.py compile \
  --tasks examples/phase_tasks.json --nodes examples/phase_nodes.json \
  --catalog examples/phase_catalog.json --out "$HOME/phase-plan.json" \
  --horizon 4 --require-n-minus-one
python3 tools/phasectl.py verify \
  --tasks examples/phase_tasks.json --nodes examples/phase_nodes.json \
  --catalog examples/phase_catalog.json --plan "$HOME/phase-plan.json"
```

Przykłady mają `synthetic-model` i fikcyjne pojemności. `RESILIENT` oznacza **tylko wynik symulacji**. Zanim zastąpisz je rzeczywistymi modelami, zmierz RAM/temperaturę/dysk, zweryfikuj SHA-256 wag i sprawdź silniki. Nie ustawiaj `lineage_verified=true` na podstawie nazwy pliku lub rozmiaru.

## 2. Trwały lease z tokenem fencing

```bash
mkdir -p "$HOME/.omega-x" && chmod 700 "$HOME/.omega-x"
python3 tools/phasectl.py claim \
  --tasks examples/phase_tasks.json --nodes examples/phase_nodes.json \
  --catalog examples/phase_catalog.json --plan "$HOME/phase-plan.json" \
  --db "$HOME/.omega-x/phase.db" --task analyze --node vps-a \
  --token-file "$HOME/.omega-x/analyze.token.json" --ttl 300
# Osobny, kontrolowany proces wykonawczy wytwarza plik wynikowy.
# Nie publikuj tokenu ani nie dodawaj go do ZIP.
python3 tools/phasectl.py complete \
  --tasks examples/phase_tasks.json --nodes examples/phase_nodes.json \
  --catalog examples/phase_catalog.json --plan "$HOME/phase-plan.json" \
  --db "$HOME/.omega-x/phase.db" --task analyze --node vps-a \
  --token-file "$HOME/.omega-x/analyze.token.json" --output /sciezka/do/istniejacego-wyniku
```

Jeśli kompilator wybierze inny węzeł niż `vps-a`, odczytaj przypisanie z planu i podaj rzeczywisty `--node`. `claim` odmawia niewłaściwemu węzłowi. Wygasły token można odzyskać wyłącznie przez nowy `claim`, który zwiększa `epoch`. Dla długich zadań wykonawca powinien regularnie wywoływać `renew` z tym samym plikiem tokenu; TTL maksymalnie 3600 sekund.

## 3. Benchmark wyłącznie syntetyczny

```bash
python3 tools/phasebench.py --cases 200 --seed 20261115
bash tools/verify.sh
```

`naive_overcommit_cases` odnosi się do celowo naiwnego uruchomienia wszystkich zadań na pierwszym węźle w slocie 0, **nie** do faktycznego działania ATLAS v3. Nie jest to benchmark token/s ani porównanie z badaniami naukowymi.

## 4. Zasady produkcyjne

- Przed uruchomieniem zadania sprawdź `admitted=true`, `verify.valid=true`, aktualność telemetrii i obecność wag.
- Nie traktuj planu N−1 jako automatycznego przełączania procesu GPU; to pełny alternatywny harmonogram od początku.
- SQLite działa tylko na jednym zaufanym hoście. Dla dwóch hostów wymagany będzie autorytatywny magazyn lease (np. PostgreSQL z fencing i idempotencją), transport z mTLS/VPN i transakcyjny outbox.
- Przestrzegaj `local_only` w całym DAG. Dla prywatnego etapu na pojedynczym S24 `--require-n-minus-one` słusznie odmówi przyjęcia planu, jeśli brak drugiego lokalnego węzła.
- `complete` hashuje wskazany istniejący plik; nie wykonuje inferencji i nie gwarantuje, że wynik powstał z danego modelu.