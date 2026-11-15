# OMEGA-X PHASESHIFT — proof-carrying counterfactual execution (v4.0.0)

## Definicja i status nowości

**Wdrożony prototyp badawczy**, nie dowiedziony wynalazek bez precedensu i nie gotowa usługa produkcyjna. PHASESHIFT to kompilator DAG, który dla zadeklarowanych zasobów tworzy plan bazowy i alternatywne pełne harmonogramy po awarii dowolnego pojedynczego węzła (N−1). Dołącza maszynowo sprawdzalny certyfikat wykonalności oraz lokalne, transakcyjne tokeny fencing dla wykonawców. Algorytm planowania, replikacja, N−1, SHA-256 i SQLite mają znane odpowiedniki w literaturze. **Hipotezą nowości produktu** jest ich spójne połączenie z Merkle/Rclone staging, propagacją polityki prywatności po zależnościach i możliwością niezależnej weryfikacji planu przed wydaniem lokalnego lease.

### Uzasadnienie zmiany względem ATLAS v3

W `atlas/planner.py` wybór `READY` odbywa się dla każdego zadania niezależnie. Dwa zadania po 600 MiB RAM mogą zostać wskazane na jeden węzeł o 1000 MiB dostępnego RAM, bez harmonogramu czasu. PHASESHIFT wprowadza **rezerwację deklarowanego RAM per slot**, **skumulowaną rezerwację przestrzeni wynikowej** oraz zależności. Zamiast błędnej deklaracji wykonania zwraca `BLOCKED` lub `INDETERMINATE`, jeśli nie potrafi wykazać poprawnego harmonogramu.

## Model obliczeniowy

- Wejście: DAG zadań `T`, węzły `N`, katalog modeli, horyzont `H` (1–64 dyskretnych slotów), budżet przeszukiwania i opcjonalne wymaganie `N−1`.
- Zmienne: przypisanie węzła `n_i`, start `s_i`, koniec `e_i = s_i + d_i`.
- Zależności: dla każdej krawędzi `i -> j` zachodzi `e_i <= s_j`.
- RAM węzła: dla każdego slotu `t`, `sum(r_i : n_i=n and s_i <= t < e_i) <= available_ram_n - headroom_n`.
- Dysk: `sum(output_bytes_i : n_i=n) <= disk_free_bytes_n`; wyniki pozostają zarezerwowane do końca planu.
- Prywatność: `local_only > trusted_only > any`; restrykcja propaguje się do wszystkich potomków DAG. `local_only` dopuszcza tylko `trust=local`, `trusted_only` wyklucza `untrusted`.
- Kompatybilność: silnik i wszystkie wymagane modele muszą być zadeklarowane na wybranym węźle. Jeśli `requires_verified_lineage=true`, każdy model musi mieć `lineage_verified=true`. **Deklaracja nie jest weryfikacją wag**.
- Temperatura: węzeł dopuszczalny tylko dla zadeklarowanego `0 <= thermal_c < 43`. To polityka ochronna, nie fizyczny model chłodzenia.
- Minimalizacja: deterministyczne DFS z backtrackingiem po rosnącym makespan; w obrębie horyzontu priorytet i ID węzła. Ograniczenie do 24 zadań i 8 węzłów. Przekroczenie budżetu przeszukiwania daje `INDETERMINATE`, **nie** dowód niewykonalności.

## Plan kontrfaktyczny i certyfikat

Dla bazowego planu `READY` kompilator ponownie planuje **cały workflow od początku** dla każdego scenariusza `node_down`. Nie twierdzi, że stan inferencji GPU jest migrowany w locie. Status `RESILIENT` oznacza wykonalność wszystkich takich scenariuszy przy niezmienionych, zadeklarowanych parametrach i horyzoncie. `DEGRADED` dopuszcza wykonanie podstawowe bez pełnego N−1; `BLOCKED_RESILIENCE` oznacza brak dopuszczenia przy wymaganym N−1.

`atlas/phaseverify.py` niezależnie od wyszukiwarki sprawdza: kompletność etapów, zależności, rezerwacje RAM i dysku, temperaturę, lokalność modeli, lineage, prywatność, scenariusze N−1 i zgodność haszów. Weryfikator **nie dowodzi**, że scenariusz `BLOCKED` jest matematycznie niewykonalny. SHA-256 certyfikatu chroni przed przypadkową modyfikacją, ale nie jest podpisem tożsamości: osoba mająca dostęp do dokumentu może przeliczyć hash. Niezależna weryfikacja ograniczeń nadal odrzuca fałszywe przypisania nawet po przeliczeniu SHA-256.

## Fencing lokalny

`atlas/phaselease.py` używa SQLite `BEGIN IMMEDIATE`, WAL, `synchronous=FULL`, monotonnie rosnącego `epoch` dla ponownego przejęcia zadania, losowego tokenu i weryfikacji SHA-256 rzeczywiście odczytanego pliku wyniku. Wykonawca ze starym `epoch` nie może zatwierdzić ukończenia po ponownym przejęciu zadania. Zależności wymagają statusu `COMPLETED`. SQLite jest **lokalnym źródłem prawdy**: nie wolno kopiować bazy na osobne urządzenia i traktować jej jako rozproszonej blokady. Brak exactly-once side effects, TEE attestation, bezpiecznego zegara rozproszonego, automatycznego recovery procesu GPU i atomowej publikacji wyniku na zewnętrznym magazynie.

## Badania porównawcze i konkurencja

Podobne, ale nie tożsame dziedziny badań:

- Habibi & Erçetin (2025), *Edge-LLM inference with cost-aware layer allocation and adaptive scheduling*, IEEE Access. https://research.sabanciuniv.edu/id/eprint/52136/
- Li et al. (2025), *NUDIF: A Non-Uniform Deployment Framework for Distributed Inference in Heterogeneous Edge Clusters*. https://www.mdpi.com/1999-5903/17/4/168
- Devaraj et al. (2026), *DARCS: Deadline- and reliability-constrained scheduling for LLM-based agentic workflows on heterogeneous edge infrastructure*. https://www.sciencedirect.com/science/article/pii/S1383762126003371
- Jenhani et al. (2026), *Replica-Aware Split Inference for Edge IoT Systems*. https://arxiv.org/abs/2611.04779

Te źródła uniemożliwiają rzetelne twierdzenie, że odporne harmonogramowanie AI zostało wynalezione tu po raz pierwszy. **Nie przeprowadzono przeglądu patentowego ani dowodu globalnej pierwszości.**

## Falsyfikacja hipotezy przewagi

Porównać z uczciwymi baseline'ami: (1) ATLAS v3 + jawny harmonogram i poprawne limity; (2) MILP/CP-SAT na małych instancjach jako optimum; (3) znany scheduler N−1. Mierzyć czas planowania, odsetek przyjętych wykonalnych zadań, false admission, N−1 coverage, realny czas i koszt recovery, transfer danych, energię na S24, realny GPU VPS. Uruchomić 30+ powtórzeń na tych samych śladach; testy awarii sieci, wymuszonych restartów, ENOSPC, zmian zegara i awarii hosta. Jeśli PHASESHIFT nie uzyska istotnej, powtarzalnej przewagi lub nie będzie oferował wartości użytkowej, hipoteza przełomu zostaje odrzucona.

### Dowody obecne i brakujące

**Obecne:** lokalne testy jednostkowe, testy CLI, 200 losowych deterministycznych instancji, wielowątkowy test wyścigu SQLite, symulacja N−1, sprawdzanie podmienionych certyfikatów i naruszeń prywatności. Raport w `reports/verification.json` i `reports/phaseshift_benchmark.json`.

**Brakujące:** rzeczywisty telefon S24 Ultra, GPU VPS, pomiar energii, sprzętowa inferencja FLUX/LTX/Wan, porównanie z MILP/CP-SAT, niezależny audyt kryptograficzny, distributed lease, transfer chmurowy, benchmark wydajności produkcyjnej, kompletna walidacja wag z Google Drive.

## Ograniczenia bezpieczeństwa

- `phase_nodes.json` i `lineage_verified` są deklaracjami; wymagają wiarygodnej telemetrii i manifestów SHA-256 modelu.
- Zadania mogą być planowane na różne węzły, lecz PHASESHIFT **nie implementuje bezpiecznego transferu wyników między węzłami**. Bez zaufanego transportu i autoryzacji nie uruchamiać wielowęzłowych workflow produkcyjnych.
- Certyfikat planu nie jest podpisem C2PA ani dowodem faktycznego uruchomienia modelu.
- Lease nie wstrzymuje procesu po wygaśnięciu; worker musi sprawdzać token i epoch przed publikacją wyników.
- Staging modeli i wykonanie pozostają oddzielnymi modułami; integracja runtime wymaga osobnego testu E2E.
