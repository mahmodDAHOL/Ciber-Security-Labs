FROM debian:bookworm-slim

# Tools the box offers a logged-in user, plus what the lab vectors need.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo cron libcap2-bin \
        python3 procps iproute2 iputils-ping \
        nano less findutils coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /root/flags /opt/maintenance /opt/scripts

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
