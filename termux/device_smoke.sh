#!/data/data/com.termux/files/usr/bin/bash
# Real on-device smoke test. Not run by host-side tools/verify.py.
set -Eeuo pipefail
command -v getprop >/dev/null || { echo 'Not running on Android' >&2; exit 2; }
node_model="$(getprop ro.product.model)"
[[ -n "$node_model" ]] || { echo 'Missing Android model identifier' >&2; exit 1; }
root="$HOME/omega-node"
[[ -s "$root/client_ed25519" && -s "$root/host_ed25519.pub" ]] || { echo 'Node identity not initialized' >&2; exit 1; }
command -v sftp >/dev/null || { echo 'openssh/sftp missing' >&2; exit 1; }
# First establish host authenticity manually with printed host public key fingerprint.
# StrictHostKeyChecking prevents silent trust-on-first-use during automated tests.
printf 'pwd\nls\nbye\n' | sftp -b - -q \
  -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -i "$root/client_ed25519" -P 2022 omega@127.0.0.1
if [[ "${OMEGA_TEST_LLM:-0}" == 1 ]]; then
  command -v curl >/dev/null || { echo 'curl missing' >&2; exit 1; }
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8082/health >/dev/null
fi
report="$HOME/.omega-x/mobile-smoke.txt"
mkdir -p "$(dirname "$report")"
{
  echo 'OMEGA-X ACTUAL DEVICE SMOKE'
  printf 'Device=%s\n' "$node_model"
  printf 'Executed_UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo 'SFTP_AUTHENTICATION_AND_DIRECTORY_LISTING=PASS'
  echo "LLM_HEALTH=$([[ "${OMEGA_TEST_LLM:-0}" == 1 ]] && echo PASS || echo NOT_RUN)"
  echo 'CLOUD_REPLICATION=NOT_RUN'
  echo 'PERFORMANCE_BENCHMARK=NOT_RUN'
} > "$report"
cat "$report"
