FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl john curl nmap netcat-openbsd iputils-ping netbase ca-certificates coreutils less nano \
    && rm -rf /var/lib/apt/lists/*
COPY common-passwords.txt /root/wordlists/common-passwords.txt
COPY attacker/motd.sh /etc/profile.d/motd.sh
WORKDIR /root
CMD ["sleep", "infinity"]
