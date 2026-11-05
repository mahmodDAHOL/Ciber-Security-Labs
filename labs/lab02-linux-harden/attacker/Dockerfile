FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap hydra openssh-client sshpass curl netcat-openbsd iputils-ping iproute2 netbase ca-certificates less nano \
    && rm -rf /var/lib/apt/lists/*
COPY common-passwords.txt /root/wordlists/common-passwords.txt
WORKDIR /root
CMD ["sleep", "infinity"]
