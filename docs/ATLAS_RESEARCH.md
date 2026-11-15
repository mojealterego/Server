# OMEGA-X ATLAS — hipoteza badawcza i protokół falsyfikacji

## Status: nowa integracja inżynierska, nie udowodniony wynalazek światowy

ATLAS łączy **integralność modeli opartą na Merkle**, **deterministyczny placement z polityką prywatności**, **uwierzytelniony łańcuch pochodzenia wyników** i istniejące usługi S24 Ultra / VPS. Wszystkie trzy moduły są rzeczywistym kodem i mogą działać bez usług zewnętrznych. Nie twierdzimy, że pierwszy na świecie wynaleziono Merkle, scheduling, mmap ani model streaming.

## Hipoteza technologiczna

> Przy częstych zmianach dużych modeli i awariach transmisji, system z blokową weryfikacją, wznowieniem i policy-aware schedulingiem może ograniczyć liczbę ponownie przesłanych bajtów, zmniejszyć błędy uruchomienia i poprawić identyfikowalność wyników względem bezwarunkowego `copy` i ręcznego wyboru modelu.

**Testowalne kryteria:**

1. `make_manifest` wylicza pełny SHA-256 oraz korzeń Merkle z bloków 4 MiB. `stage_file` sprawdza bloki istniejącego `.omega-part`, kopiuje tylko brakujące/uszkodzone, publikuje atomowo bez nadpisania istniejącego celu.
2. `planner.plan` wybiera wyłącznie węzły deklarujące wymagane silniki, lokalne modele, wystarczający RAM, przestrzeń na wynik, temperaturę poniżej limitu oraz dopuszczalny poziom zaufania. Niespełnione warunki kończą się `BLOCKED`, nigdy cichym offloadem prywatnego zadania.
3. `audit.append_record` wiąże parametry zadania, hash promptu, hash wyniku i poprzedni rekord przez HMAC-SHA256; wykrywa późniejszą podmianę danych przy użyciu tego samego sekretu.
4. Wynik `READY` jest **planem**, a nie uruchomioną inferencją. `SIZE_MATCH_METADATA_ONLY` nie jest potwierdzeniem zgodności wag, modelu, licencji ani binarium.

## Granice rozwiązania

- `stage_file` działa na **plikach lokalnych albo zdalnych zamontowanych jako system plików**. Nie wykonuje Google Drive API Range, zdalnego mmap, inferencji z niepełnego modelu ani transferu bez źródła. Na Androidzie Scoped Storage hardlink może być niedostępny; staging powinien odbywać się na ext4 prywatnego Termuksa lub na VPS. Brak wsparcia hardlink => fail closed.
- HMAC jest uwierzytelnieniem lokalnym, **nie** publicznym podpisem C2PA, attestation TEE ani dowodem faktycznego wywołania modelu.
- Planner przyjmuje deklarowane RAM/temperaturę i nie mierzy ich w tle. W produkcji dane powinny pochodzić z `tools/doctor.py` i sprawdzonego agenta telemetrycznego, z TTL i podpisem źródła.
- Po stronie modeli brakuje potwierdzenia kompletności zestawów Wan i LTX. Nazwa `ltx-2.3-22b-distilled-Q2_K.gguf` nie dowodzi, że zestaw jest kompatybilny z konkretnym `sd-cli`. Nie uruchamiać nieznanych `.ckpt` jako programów.
- Obecne rozwiązanie nie jest skalowalnym multi-tenant schedulerem, nie zapewnia HA ani rozliczeń, nie ma pomiarów energii czy token/s na S24 Ultra.

## Metodyka testu przewagi

Porównać na tych samych plikach: (A) pełne kopiowanie `rclone copyto` po przerwaniu transferu; (B) blokowy staging ATLAS z 10% i 50% już zweryfikowanych bloków. Zmierzyć **rzeczywiste bajty źródłowe, czas, energię, I/O, błędy i liczbę poprawnie odtworzonych plików**; wykonać minimum 30 prób z losowaną kolejnością. Osobno sprawdzić 20 awarii wymuszonych (SIGKILL, ENOSPC, uszkodzenie 1 bloku, symlink, zmiana źródła) i zero niezweryfikowanych publikacji. Dla planera mierzyć liczbę naruszeń polityki prywatności, odrzuceń, zadań wykonanych na odpowiednim sprzęcie i koszty danych.

**Warunek potencjalnej przewagi rynkowej:** zmierzona oszczędność transferu przy zachowaniu zerowej liczby naruszeń integralności i polityk. Bez tego technologia pozostaje hipotezą, nie przełomem.

## Integracja ze standardami

- C2PA 2.5: docelowa, osobna implementacja eksportu podpisanych Content Credentials dla zdjęć i wideo. HMAC z ATLAS nie zastępuje tego standardu.
- llama.cpp RPC: istnieje, ale upstream określa backend jako eksperymentalny i niezabezpieczony; nie uruchamiać na publicznym IP.
- Safetensors: wspiera zero-copy/lazy loading, ale to nie jest nowy wynalazek ATLAS.

## ATLAS Ranged Tensor Staging — implementacja z Rclone

`atlas/remote.py` implementuje rzeczywiste strumieniowe wyliczanie manifestu bez zapisu wag (`rclone cat`) oraz odczytywanie wyłącznie brakujących/uszkodzonych bloków (`rclone cat --offset --count`). W przypadku prawidłowego częściowego pobrania z 16 bloków i dwóch już zweryfikowanych lokalnie test wymaga dokładnie **14** zdalnych odczytów zakresowych. Testy używają kontrolowanego symulatora Rclone uruchamianego jako osobny proces. Nie potwierdzają ograniczenia opłat/transferu w Google Drive — wymaga to pomiaru na prawdziwym koncie i backendzie.