FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl sqlmap python3 nmap netcat-openbsd netbase ca-certificates less nano jq \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /root
CMD ["sleep", "infinity"]
