FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends samba samba-common-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 omega-compat && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin omega-compat \
    && groupadd -g 10003 omega-secure && useradd -u 10003 -g 10003 -M -s /usr/sbin/nologin omega-secure \
    && mkdir -p /srv/omega-smb/compat /srv/omega-smb/secure /srv/omega-smb/models /run/samba /run/omega
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/omega-smb-entrypoint
RUN chmod 0755 /usr/local/bin/omega-smb-entrypoint && testparm -s /etc/samba/smb.conf >/dev/null
EXPOSE 1445/tcp
ENTRYPOINT ["/usr/local/bin/omega-smb-entrypoint"]
