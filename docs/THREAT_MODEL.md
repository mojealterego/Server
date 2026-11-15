# Threat model v2.0.0

| Granica | Zagrożenie | Mechanizm | Pozostałe ryzyko |
|---|---|---|---|
| Android → lokalna usługa | niezaufana sieć, przypadkowa ekspozycja | loopback domyślnie, `--allow-lan` i tylko prywatny IPv4 | VPN/firewall wymagane poza LAN |
| Android → VPS | MITM / podmiana klucza hosta | Rclone SFTP `known_hosts_file`/`host_keys` obowiązkowe dla offloadu | bezpieczeństwo prywatnego klucza operatora |
| Model files | uszkodzone złośliwe nagłówki | ograniczony parser GGUF i Safetensors, walidacja offsetów, symlink odmowa | parser nie wykonuje weryfikacji semantyki tensorów ani pełnej walidacji runtime |
| Jobs JSON | polecenia powłoki/path traversal, kolizje ID | allowlist pól, lista nazw modeli, brak shell, trwałe idempotency keys, staging | user posiadający zapis do współdzielonego wolumenu może manipulować kolejką; jeden tenant |
| Worker → media file | pozorny sukces, fałszywy plik wideo | `sd-cli` exit 0, rozmiar >0, `ffprobe` w profilu media, SHA-256 wyniku | ffprobe nie dowodzi jakości/semantyki wygenerowanego klipu |
| Sync → cloud | niepełny zapis, utrata części kopii | osobna weryfikacja każdego crypt, commit-last, kod częściowej awarii | brak transakcji pomiędzy niezależnymi dostawcami |
| Cloud → restore | podmieniony manifest lub skasowane pliki | HMAC z lokalnym kluczem, SHA-256 każdego pliku, zakaz overwrite | przejęty klucz HMAC może sfałszować potwierdzenie |
| Packaging → użytkownik | przypadkowy wyciek danych w ZIP | sztywna allowlist ścieżek, odrzucenie `.key`, brak wag, sumy SHA-256 | log testowy może zawierać dane operacyjne, przed udostępnieniem zewnętrznym przeglądaj raporty |
| RAM/termika | OOM, throttle, ubijanie procesów Androida | supervisor, współdzielony `flock`, arbitraż RAM i histereza temperatury | brak uprawnień do kernel tuning i brak gwarancji 24/7 |

Nie wykorzystuj identycznego klucza HMAC do długowiecznego publicznego udostępniania. Klucze powinny mieć osobne kopie offline i rotację z zachowaniem poprzednich kluczy wymaganych przez stare backupy. Rclone `obscure` nie jest równoważne kryptograficznemu magazynowi sekretów; chroń `rclone.conf`.


## PHASESHIFT v4 — dodatkowe zagrożenia

- Złośliwy node może zawyżyć RAM, temperaturę lub zadeklarować model, którego nie ma. Rozwiązanie produkcyjne wymaga podpisanej telemetrii z TTL, manifestów Merkle i preflight przed lease.
- Hash certyfikatu SHA-256 nie uwierzytelnia autora. Niezależny weryfikator sprawdza ograniczenia, ale nie potwierdza źródła danych wejściowych.
- SQLite lease na dwóch niezależnych urządzeniach nie zapewnia wzajemnego wykluczenia. Nie replikować pliku SQLite jako mechanizmu HA.
- Expired lease nie zatrzymuje procesu. Stary worker może mieć side effect poza ledgerem. Publikacja wymaga fencing w magazynie wynikowym.
- Zmiana zegara systemowego może zmienić TTL. W produkcji wymagana synchronizacja i kontrola źródła czasu.
- Przejście danych między węzłami nie jest zaimplementowane w v4. Samo przypisanie planu nie autoryzuje transferu.
