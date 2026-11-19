#!/bin/sh
set -eu
umask 077
for spec in 'omega-compat:compat:10002' 'omega-secure:secure:10003' 'omega-model-reader:models:10003'; do
    account=${spec%%:*}
    tail=${spec#*:}; share=${tail%%:*}; uid=${tail#*:}
    secret="/run/omega/${share}_password"
    [ -f "$secret" ] && [ ! -L "$secret" ] && [ "$(stat -c '%u:%a:%h' "$secret")" = '0:600:1' ] || exit 1
    [ "$(stat -c '%u:%g:%a' "/srv/omega-smb/$share")" = "$uid:$uid:700" ] || exit 1
    [ "$(wc -c < "$secret")" -eq 65 ] || exit 1
    LC_ALL=C grep -Eq '^[a-f0-9]{64}$' "$secret" || exit 1
    password=$(cat "$secret")
    printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a "$account" >/dev/null 2>&1 || exit 1
    unset password
done
[ "$(stat -c '%u:%g:%a' /srv/omega-smb/models)" = '10003:10003:700' ] || exit 1
if [ -n "${OMEGA_SMB_VOLUME_LIMITS:-}" ]; then
    python3 /usr/local/bin/omega-smb-limits.py --limits "$OMEGA_SMB_VOLUME_LIMITS" --paths /srv/omega-smb/compat /srv/omega-smb/secure /srv/omega-smb/models
fi
testparm -s /etc/samba/smb.conf >/dev/null
exec smbd --foreground --no-process-group --configfile=/etc/samba/smb.conf
