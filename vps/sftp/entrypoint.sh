#!/bin/sh
set -eu
umask 077
for src in /run/omega-input/authorized_keys /run/omega-input/ssh_host_ed25519_key; do
  if [ ! -s "$src" ]; then echo "Missing key: $src" >&2; exit 1; fi
done
install -o root -g root -m 0600 /run/omega-input/authorized_keys /etc/ssh/authorized_keys/omega
install -o root -g root -m 0600 /run/omega-input/ssh_host_ed25519_key /etc/ssh/hostkeys/ssh_host_ed25519_key
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
