# OMEGA-X v4.1 — weryfikowane checkpointy (lokalny CAS)

## Rozwiązany problem

PHASESHIFT v4 potwierdzał zakończenie etapu, zapisując SHA-256 wyniku,
nie zapewniając przechowania wyniku po usunięciu pliku roboczego. W v4.1
`atlas.artifacts.ArtifactStore` publikuje zweryfikowane bajty pod nazwą SHA-256
we własnym magazynie, zanim `LeaseStore.complete()` ustawi stan COMPLETED.
`LeaseStore.claim()` odrzuca kolejne zadanie, gdy wymagany wynik jest uszkodzony
lub niedostępny. Bez magazynu CAS zachowane jest stare API, ale nie wolno
interpretować starego trybu jako odpornego na utratę pliku wejściowego.

## Granice gwarancji

- **Integralność:** SHA-256 wszystkich bajtów, także po odtworzeniu; brak
  kryptograficznego uwierzytelnienia właściciela i brak sygnatury.
- **Trwałość:** `fsync()` danych i katalogu przed zwróceniem potwierdzenia.
  Zakłada poprawną implementację `fsync()` przez lokalny filesystem.
- **Atomowość:** publikacja przez `os.link()` w tym samym systemie plików,
  tylko do nowej ścieżki. Nie ma cichego zastępowania plików.
- **Izolacja:** właściciel i uprawnienia 0700 katalogu CAS, obiekty 0600;
  symlinki są odrzucane, pliki specjalne nie są akceptowane.
- **Ograniczenia:** pojedynczy host, jeden zaufany użytkownik OS;
  nie chroni przed administratorem/root, złośliwym procesem tego samego UID,
  fizycznym uszkodzeniem dysku, ani wspólną awarią telefonu i serwera.
- **Lease:** fencing jest lokalne (SQLite), nie globalne i nie zapewnia
  exactly-once pomiędzy hostami. Publikacja do CAS przed zatwierdzeniem DB
  może pozostawić bezpieczny osierocony obiekt po awarii; GC wymaga odrębnej,
  świadomie autoryzowanej polityki retencji.

## Użycie Termux/Linux

```bash
python3 tools/casctl.py --vault "$HOME/.omega-x/artifacts" put ./answer.avi
python3 tools/casctl.py --vault "$HOME/.omega-x/artifacts" verify <sha256>
python3 tools/casctl.py --vault "$HOME/.omega-x/artifacts" restore <sha256> ./recovered.avi
```

Integracja Python:

```python
from pathlib import Path
from atlas.artifacts import ArtifactStore
from atlas.phaselease import LeaseStore

store = ArtifactStore(Path.home()/'.omega-x/artifacts')
with LeaseStore(database_path, certificate, tasks, nodes, catalog,
                artifacts=store) as leases:
    claim = leases.claim(task_id, node_id, ttl=60)
    # Zewnętrzny runner musi najpierw naprawdę wykonać zadanie i zapisać wynik.
    receipt = leases.complete(task_id, node_id, claim['token'],
                              claim['epoch'], output_path)
```

## Weryfikacja

`python3 -m unittest discover -s tests -p test_artifacts.py -v` sprawdza
odtwarzanie, integralność, konflikt, symlinki, limity, współbieżność i
ciągłość zależności workflow. Zaliczenie nie zastępuje testu z nagłym zanikiem
zasilania, trwałością nośnika UFS ani replikacją poza urządzenie.
