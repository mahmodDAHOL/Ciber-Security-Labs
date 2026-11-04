FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap curl ftp netcat-openbsd iputils-ping iproute2 dnsutils tcpdump ca-certificates less netbase \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /root
CMD ["sleep", "infinity"]
