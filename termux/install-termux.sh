#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
if [[ ! -d /data/data/com.termux/files/usr ]]; then
  echo 'Run in Termux app on Android' >&2; exit 1
fi
pkg update
pkg install -y python rclone openssh apache2 coreutils findutils util-linux git cmake ninja clang
if [[ ! -d "$HOME/storage/shared" ]]; then
  termux-setup-storage
  echo 'Grant Android storage permission; re-run if not immediately available.'
fi
MODEL_DIR="${OMEGA_MODEL_DIR:-$HOME/storage/shared/1.GGUF-UNCENSORED}"
if [[ ! -d "$MODEL_DIR" ]]; then
  echo "Model directory not found: $MODEL_DIR" >&2
  echo 'Existing model files are not moved, renamed, or copied automatically.' >&2
fi
mkdir -p "$HOME/.omega-x"
chmod 700 "$HOME/.omega-x"
command -v ssh-keygen >/dev/null
command -v rclone >/dev/null
command -v htpasswd >/dev/null
python "$(dirname "$0")/omega_node.py" init
python "$(dirname "$0")/model_inventory.py" --dir "$MODEL_DIR" --json-out "$HOME/.omega-x/models.json" || true
printf '\nOMEGA Termux installed. Start: python termux/omega_node.py run\n'
