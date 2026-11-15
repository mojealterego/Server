# Architektura OMEGA-X v2.0.0

```text
┌──────────────── Samsung S24 Ultra / Termux ────────────────┐
│ SFTP:2022  WebDAV:8081  llama-server:8082 (loopback)       │
│   model_inventory (GGUF/Safetensors)                       │
│        │                                                     │
│  1.GGUF-UNCENSORED (niekopiowane modele)                 │
│        ├──── backup.sh (flock + sha256/HMAC) ────────────┐ │
│        └──── offload.py (pinned SFTP key) ─────────────┐ │ │
└───────────────────────────────────────────────────────│─│─┘
                                                        │ │
┌──────────────────── Linux VPS ────────────────────────│─│─┐
│ ProFTPD FTPS:2121 / OpenSSH SFTP:2222                │ │ │
│    └────────────── data/queue/pending <───────────────┘ │ │
│          media_worker (wan/ltx2)                         │ │
│         [pending → running → completed / failed]        │ │
│         output: AVI + sha256 + optional ffprobe         │ │
│                                                         │ │
│    data/  ←────────────────────────────────────────────┘ │
│      │                                                     │
│      └── Rclone Crypt A / Rclone Crypt B (kopie)           │
└───────────────────────────────────────────────────────────┘
```

## Główne kontrakty

- **Płaszczyzna sterowania**: lokalna w Termuksie; brak publicznego API arbitra. Zdalne zlecenia przez przypięty SFTP.
- **Płaszczyzna danych**: prywatne foldery Termuksa, katalog współdzielony Androida, wolumen `vps/data`, dwa osobne, szyfrowane cele Rclone.
- **LLM**: tylko poprawny GGUF obsługiwany przez `llama-server`. Nie uruchamiaj Wan ani LTX przez LLM. `mmproj` wymaga weryfikacji linii modelowej.
- **Wideo**: worker typu *fail-closed*. Sekwencja pending → running → staging output → ffprobe (włączone w Docker) → completed. Po restarcie przerwane zadanie otrzymuje `FAILED_INTERRUPTED`. Nie ma automatycznego retry z nieznanym stanem GPU.
- **Idempotencja**: pliki `ids/<job-id>` blokują ponowne użycie identyfikatora. Reset wyłącznie po ręcznej inspekcji.
- **Backup**: każdy remote weryfikowany osobno, HMAC potwierdza manifest, zakończone zlecenie ma `COMPLETE.json` ostatnie. Restore bez `COMPLETE.json` jest odrzucane.
- **Skalowanie**: SFTP/FTPS w konfiguracji repozytorium to pojedynczy serwer; HA wymaga oddzielnego planu storage i load balancera FTP-aware. Nie ma „nieskończonej” skali.

## Granice bezpieczeństwa

Uprawnienia Termuksa ≠ root. `sysctl`, maski affinity, OpenCL/NPU i Android Phantom Process Killer nie są modyfikowane w kodzie. `flock` zapewnia lokalny mutex między *zarządzanym* LLM a backupem; procesy uruchomione poza OMEGA mogą zajmować zasoby bez jego wiedzy. Rzeczywisty stan GPU, RAM i temperatury zależy od urządzenia.
