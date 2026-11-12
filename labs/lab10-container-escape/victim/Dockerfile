FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libcap2-bin procps jq iproute2 \
    && rm -rf /var/lib/apt/lists/*

# lean Docker CLI only (no daemon) — the container talks to the mounted host socket
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz \
        -o /tmp/d.tgz \
    && tar -xzf /tmp/d.tgz -C /tmp \
    && cp /tmp/docker/docker /usr/local/bin/docker \
    && chmod +x /usr/local/bin/docker \
    && rm -rf /tmp/d.tgz /tmp/docker

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
