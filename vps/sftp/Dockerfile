FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd /run/omega-input /etc/ssh/hostkeys /etc/ssh/authorized_keys /srv/omega-jail/files && \
    chmod 0755 /srv/omega-jail && \
    useradd --uid 10001 --home-dir /files --no-create-home --shell /usr/sbin/nologin --password x omega
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/omega-sshd-entrypoint
RUN chmod 0755 /usr/local/sbin/omega-sshd-entrypoint
EXPOSE 2222
ENTRYPOINT ["/usr/local/sbin/omega-sshd-entrypoint"]
