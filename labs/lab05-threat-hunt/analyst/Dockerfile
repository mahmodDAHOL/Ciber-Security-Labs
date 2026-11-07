FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ripgrep jq gawk grep coreutils less nano ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /cases
CMD ["sleep", "infinity"]
