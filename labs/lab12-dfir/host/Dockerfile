FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# forensic analyst toolkit: strings/file (binutils+file), hashing, timeline (find/stat),
# text search, python for decoding. No live services — you investigate a "seized" host.
RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils file coreutils findutils grep less procps \
        python3 xxd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY host/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /evidence
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
