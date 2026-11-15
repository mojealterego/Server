# Bezpieczeństwo OMEGA-X v2.0.0

- **Zasada najmniejszych uprawnień**: Termux uruchamia serwery na portach powyżej 1024. Domyślnie tylko loopback, LAN wyłącznie po jawnej zgodzie. Nie używaj `chmod 777`, root oraz nie publikuj hasła w kodzie.
- **Transfer**: rekomendowany SFTP z kluczem publicznym i przypiętym kluczem hosta. WebDAV tylko przez `127.0.0.1` lub zewnętrzny zaufany tunel HTTPS/VPN. FTPS na VPS wymaga zaufanego X.509, nie tymczasowego certyfikatu z `--self-signed-lab`.
- **Dane**: modele mogą być objęte licencjami osobnymi od kodu. `rclone.conf` i `$HOME/.omega-x/manifest-hmac.key` są sekretami. HMAC jest 256-bitowy, używany do potwierdzania pochodzenia manifestu; nie zastępuje szyfrowania magazynu ani kontroli dostępu dostawcy.
- **Worker**: only allowlisted job fields; pliki wag tylko z wydzielonego katalogu modeli; operator uruchamia prawdziwy `sd-cli`. Nie stosuj poleceń shell pochodzących z JSON, nie akceptuj symlinków w modelach i kolejce.
- **Backup/restore**: kod odrzuca symlinki źródłowe i niebezpieczne nazwy, powtarza weryfikację bajtów, oznacza częściowe błędy. Restore używa `renameat2(RENAME_NOREPLACE)` dla publikacji bez nadpisania. Po odtworzeniu wykonaj niezależny sanity-check modeli i aplikacji.
- **Zachowanie danych/kluczy**: trzymaj co najmniej jedną kopię klucza HMAC poza urządzeniem. Utrata klucza nie niszczy szyfrowanych bajtów, ale uniemożliwia pozytywne uwierzytelnienie snapshotów w tym narzędziu. Zmiana klucza wymaga utrzymania historycznych kluczy dla starych backupów.
- **Brak domniemanej odporności przemysłowej**: jeden telefon lub pojedynczy VPS nie tworzą HA. Failover, rbac per tenant, audit sink i mTLS nie są zaimplementowane. `docs/THREAT_MODEL.md` opisuje ryzyka szczątkowe.
