FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends proftpd-basic proftpd-mod-crypto gettext-base ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/omega /srv/omega && \
    (grep -Eq '^[[:space:]]*LoadModule[[:space:]]+mod_tls\.c' /etc/proftpd/modules.conf || printf '\nLoadModule mod_tls.c\n' >> /etc/proftpd/modules.conf) && \
    useradd --uid 10001 --home-dir /srv/omega --no-create-home --shell /usr/sbin/nologin omega
COPY proftpd.conf.template /etc/proftpd/omega.conf.template
COPY entrypoint.sh /usr/local/sbin/omega-entrypoint
RUN chmod 0755 /usr/local/sbin/omega-entrypoint
EXPOSE 2121 50000-50015
ENTRYPOINT ["/usr/local/sbin/omega-entrypoint"]
