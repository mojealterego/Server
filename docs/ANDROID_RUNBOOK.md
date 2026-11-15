# Android — Samsung Galaxy S24 Ultra / Termux

## Instalacja

```bash
pkg update && pkg upgrade -y
pkg install -y python unzip
termux-setup-storage
cp "$HOME/storage/downloads/OMEGA_STORAGE_AI_v2.0.0.zip" "$HOME/"
cd "$HOME" && unzip -o OMEGA_STORAGE_AI_v2.0.0.zip
cd OMEGA_STORAGE_AI_v2.0.0
bash termux/install-termux.sh
```

Instalator wymaga hasła WebDAV na loopback (minimum 16 znaków) i generuje klucze Ed25519. Wszystkie sekrety pozostają w `$HOME/omega-node` z uprawnieniami 0600/0700. Jeśli nie chcesz WebDAV, zainicjalizuj węzeł osobno: `python3 termux/omega_node.py init --without-webdav` po zainstalowaniu pakietów.

## Bezpieczny start

```bash
export OMEGA_MODEL_DIR="$HOME/storage/shared/1.GGUF-UNCENSORED"
python3 tools/doctor.py --model-dir "$OMEGA_MODEL_DIR"
python3 termux/model_inventory.py --dir "$OMEGA_MODEL_DIR"
python3 termux/omega_node.py run
```

Druga sesja: `python3 termux/omega_node.py status` (nasłuch portów 2022/8081/8082), `bash termux/device_smoke.sh` (test SFTP wymaga ręcznie potwierdzonego host fingerprint/known_hosts).

**Dostęp przez LAN:** proces bez `--allow-lan` nie będzie wiązał innego adresu niż loopback. Z urządzenia Samsung odczytaj prywatny IPv4, następnie: `python3 termux/omega_node.py run --sftp-bind 192.168.1.50 --allow-lan`. Wymagany firewall/router i VPN do dostępu z internetu.

## LLM

`bash termux/build_llama.sh` (może wymagać internetu i kompilatora), następnie `python3 termux/omega_node.py run --model /pełna/ścieżka/model.gguf --context 2048 --threads 4`. Nie uruchamiaj kolejnej instancji, gdy `run` już działa; zatrzymaj wcześniejszą `Ctrl+C`. Architektura nie używa automatycznie NPU. OpenCL może wymagać dodatkowych sterowników, flag i przetestowanego buildu.

## Modele wideo → VPS

`python3 termux/offload.py job.json --remote vps-sftp:queue/pending` publikuje plik JSON bez uruchamiania wideo na telefonie. Nazwa `vps-sftp` musi odnosić się do prawdziwego serwera OpenSSH z wpisem host key/known_hosts. Worker ma być niezależnie uruchomiony na VPS, a odpowiednie modele dostarczone na maszynę VPS.

## Android 12+ i zasilanie

Zezwól Termux na działanie w tle, wyłącz agresywne oszczędzanie baterii, rozważ `termux-wake-lock`. Bez roota Termux nie może gwarantować odporności na Phantom Process Killer. Nie zmieniaj na ślepo `sysctl`, ADB device_config i częstotliwości CPU. S24 Ultra pod obciążeniem się nagrzewa; używaj monitoringu i kontroli temperaturowej. `taskset -c 2-7` **nie jest** domyślnie ustawiany, bo mapa CPU może zależeć od urządzenia/kernelu.
