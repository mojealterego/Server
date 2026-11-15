# Wydajność — plan pomiarowy, nie fikcyjne benchmarki

Nie istnieje „absolutnie nielimitowany” serwer na jednym S24 Ultra: wpływ mają RAM, termika, throttling, CGNAT, UFS/Scoped Storage, sieć i koszty dostawców. **Żaden z poniższych parametrów nie jest tu poświadczonym wynikiem sprzętowym.**

| Pomiar | Sposób | Wymagane dowody |
|---|---|---|
| LLM prefill / decode | `llama-bench`/`llama-server` na rzeczywistym S24 | dokładny SHA modelu, git SHA llama.cpp, kontekst, n_threads, tok/s, TTFT, P50/P95, bateria/temperatura |
| CPU affinity | `taskset` tylko po weryfikacji faktycznego topology/allowed affinity | `os.sched_getaffinity()`, `lscpu`/sysfs, porównanie 2/4/6 wątków, TTFT & tok/s |
| GPU / OpenCL | osobna kompilacja i test backendu Adreno, Vulkan jeśli dostępne | log CMake, lista urządzeń, wyniki 1:1 dla tego samego modelu |
| NPU | dedykowany zgodny backend i rzeczywista delegacja | log runtime, model/operator support, wynik prefill i decode oddzielnie |
| SFTP/WebDAV | test strumienia 1/4/8 połączeń, pliki 1MB/1GB | RTT, MiB/s, RSS, CPU, retransmisje, identyczność SHA-256 |
| Rclone backup | 2 dostawcy + test awarii jednego remote | `rclone check --download`, sumy, ID snapshot, koszty egress, RTO i RPO |
| Wideo Wan/LTX | `sd-cli --mode vid_gen` na VPS ze wspieranym GPU | nazwane dokładne pliki, sha, binarium/commit, `ffprobe`, czas klipu, peak RAM/VRAM |
| Termika S24 | min. 30–60 min w scenariuszu realnym | próbki baterii/SoC z **opisanym źródłem**, throughput w czasie, thermal guards |

Progi 43.0/39.5°C to polityka aplikacyjna, a nie certyfikowane granice bezpieczeństwa SoC. Androidowe API termometru baterii nie raportuje temperatury rdzenia CPU. Wartości specyficzne dla telefonu muszą być skalibrowane empirycznie.

Porównuj warianty: CPU 2 vs 4 vs 6 threads; OpenCL vs CPU po zbudowaniu; WebDAV vs SFTP; rclone `transfers=1/2/4`, `checkers=2/4`; ciśnienie RAM przy różnych kontekstach. Wynik wybieraj po stabilnym P95 i temperaturze, nie po pojedynczym peak tok/s.
