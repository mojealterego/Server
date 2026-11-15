#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")"
mkdir -p secrets data
chmod 700 secrets
if [[ ! -s secrets/ssh_host_ed25519_key ]]; then
  command -v ssh-keygen >/dev/null || { echo 'Install openssh-client' >&2; exit 1; }
  ssh-keygen -q -t ed25519 -N '' -f secrets/ssh_host_ed25519_key
fi
if [[ ! -s secrets/ftps_password ]]; then
  command -v openssl >/dev/null || { echo 'Install openssl' >&2; exit 1; }
  openssl rand -hex 32 > secrets/ftps_password
fi
if [[ ! -s secrets/authorized_keys ]]; then
  echo 'Place trusted client public key into vps/secrets/authorized_keys' >&2
  echo 'For example: cat ~/.ssh/id_ed25519.pub > vps/secrets/authorized_keys' >&2
  exit 1
fi
chmod 600 secrets/authorized_keys secrets/ssh_host_ed25519_key secrets/ftps_password
if [[ ! -s secrets/tls.crt || ! -s secrets/tls.key ]]; then
  if [[ "${1:-}" == '--self-signed-lab' ]]; then
    openssl req -newkey rsa:3072 -nodes -x509 -days 7 \
      -keyout secrets/tls.key -out secrets/tls.crt \
      -subj '/CN=localhost' >/dev/null 2>&1
    echo 'WARNING: self-signed lab certificate only, NOT for production' >&2
  else
    echo 'Provide valid secrets/tls.crt and secrets/tls.key; or --self-signed-lab for localhost lab' >&2
    exit 1
  fi
fi
chmod 600 secrets/tls.key
# Shared bind volume must be writable by the unprivileged UID in both containers.
if [[ "$(stat -c %u data)" != '10001' ]]; then
  echo 'Data volume requires UID/GID 10001. Run: sudo chown -R 10001:10001 vps/data' >&2
  exit 1
fi
chmod 750 data
if [[ ! -e .env ]]; then
  cat > .env <<'ENV'
FTPS_BIND_ADDRESS=127.0.0.1
SFTP_BIND_ADDRESS=127.0.0.1
FTPS_PUBLIC_HOST=127.0.0.1
ENV
  chmod 600 .env
fi
echo 'VPS secrets and permissions validated. Check .env before docker compose up -d --build.'
