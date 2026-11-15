#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" != 0 ]; then
  echo 'This container needs UID 0 to initialize the unprivileged FTP account' >&2
  exit 1
fi
for path in /run/omega/ftps_password /run/omega/tls.crt /run/omega/tls.key; do
  if [ ! -s "$path" ]; then
    echo "Missing nonempty secret: $path" >&2
    exit 1
  fi
done
case "${FTPS_PUBLIC_HOST:-}" in
  ''|*[!a-zA-Z0-9.-]*)
    echo 'FTPS_PUBLIC_HOST must be a safe DNS name or IPv4 address' >&2
    exit 1;;
esac
if [ "${#FTPS_PUBLIC_HOST}" -gt 253 ]; then
  echo 'FTPS_PUBLIC_HOST is too long' >&2
  exit 1
fi
PASS=$(cat /run/omega/ftps_password)
if [ "${#PASS}" -lt 16 ]; then
  echo 'FTPS password is too short' >&2
  exit 1
fi
printf 'omega:%s\n' "$PASS" | chpasswd
unset PASS
# Refuse silent downgrade if Debian's TLS module is unavailable.
if ! grep -Eq '^[[:space:]]*LoadModule[[:space:]]+mod_tls\.c' /etc/proftpd/modules.conf; then
  echo 'ProFTPD TLS module is not loaded: refusing to start' >&2
  exit 1
fi
if ! openssl x509 -in /run/omega/tls.crt -noout >/dev/null 2>&1; then
  echo 'Invalid TLS certificate' >&2
  exit 1
fi
if ! openssl pkey -in /run/omega/tls.key -noout >/dev/null 2>&1; then
  echo 'Invalid TLS private key' >&2
  exit 1
fi
# Certificate and private key must match; refuse mismatched credentials.
CERT_PUB=$(openssl x509 -in /run/omega/tls.crt -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | cut -d ' ' -f1)
PRIV_PUB=$(openssl pkey -in /run/omega/tls.key -pubout -outform der | sha256sum | cut -d ' ' -f1)
if [ "$CERT_PUB" != "$PRIV_PUB" ]; then
  echo 'TLS certificate/private key mismatch' >&2
  exit 1
fi
envsubst '${FTPS_PUBLIC_HOST}'  </etc/proftpd/omega.conf.template >/etc/proftpd/omega.conf
proftpd -t -c /etc/proftpd/omega.conf
exec proftpd -n -c /etc/proftpd/omega.conf
