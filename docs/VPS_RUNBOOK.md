# VPS — uruchomienie FTPS/SFTP i workera

Wymaga zaufanego Linux VPS/dedykowanego serwera z Docker Compose V2. Brak usługi VPS w samym ZIP. Przed uruchomieniem przeczytaj `docs/SECURITY.md`.

1. Przygotuj własny klucz publiczny klienta SFTP w `vps/secrets/authorized_keys`. Nie przenoś klucza prywatnego telefonu.
2. `sudo chown -R 10001:10001 vps/data` po stworzeniu katalogu `data`.
3. `bash vps/init.sh --self-signed-lab` generuje krótkotrwały testowy certyfikat FTPS **wyłącznie dla laboratorium**; wymień go na zaufany certyfikat produkcyjny i sprawdź hostname.
4. `cd vps && docker compose config && docker compose up -d --build && docker compose ps && docker compose logs --tail=100 sftp ftps`.
5. Ustawienie domyślne: `127.0.0.1`, FTPS:2121 i PASV:50000–50015, SFTP:2222. Dostęp z telefonu bez tunelu/VPN nie jest dostarczony automatycznie. Nie otwieraj publicznie portów na ślepo.

## Worker wideo

W katalogu `vps/engine/sd-cli` musi istnieć faktycznie wykonujące się binarium ze zgodnymi bibliotekami runtime. Modelom z `vps/models` trzeba zapewnić **potwierdzony zestaw wag** i odpowiednią ilość RAM/VRAM. Profil:

```bash
cd vps
docker compose --profile media up -d --build
docker compose logs --tail=100 media-worker
```

Worker wykonuje `sd-cli --mode vid_gen` z domyślnym wyjściem `AVI` (wymienione w dokumentacji stable-diffusion.cpp; nie zakładamy obsługi MP4). `ffprobe` w profilu `media` wymaga dekodowalnego strumienia wideo. W przypadku braku wyjścia, złego kodu zakończenia, niekompletnego formatu lub przerwanego procesu zadanie ma stan `FAILED`, nie `COMPLETED`.

Zadania można przekazać lokalnie przez `python3 vps/media_worker.py enqueue job.json --queue vps/data/queue` lub SFTP `python3 termux/offload.py job.json --remote vps-sftp:queue/pending` (rclone remote z przypiętym kluczem serwera). Modele na telefonie **nie są** automatycznie przesyłane do VPS.

Przykładowa specyfikacja JSON po zaktualizowaniu nazw na zgodne binaria i modele:

```json
{
  "id": "video001",
  "engine": "wan",
  "diffusion_model": "wan_1.3B_exp_e14.safetensors",
  "t5xxl": "umt5_xxl_fp8.safetensors",
  "vae": "wan_2.1_vae.safetensors",
  "prompt": "Cinematic mountain panorama",
  "width": 512, "height": 512, "frames": 17, "fps": 16, "steps": 20
}
```

**Uwaga:** podane komponenty nie są zweryfikowane jako pełny zgodny zestaw — nazwa pliku na zdjęciu nie wystarcza. `ltx2` wymaga ponadto `llm`, `embeddings_connectors` oraz `vae`.

Worker używa trwałych plików ID w `queue/ids/` — po przerwanym wykonaniu nie resetuje ich bez decyzji operatora. Limitem jest 64 oczekujące zadania w `pending/`. Katalogi `outputs/` i `staging/` przechowują wyniki i diagnostykę. Nie udostępniaj tych katalogów innym tenantom.
