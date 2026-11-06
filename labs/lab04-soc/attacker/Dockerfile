FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      hydra openssh-client sshpass nmap curl netcat-openbsd netbase iputils-ping less nano \
    && rm -rf /var/lib/apt/lists/*
COPY common-passwords.txt /root/wordlists/common-passwords.txt
COPY attacker/attack.sh /root/attack.sh
RUN sed -i 's/\r$//' /root/attack.sh && chmod +x /root/attack.sh
WORKDIR /root
CMD ["sh", "-c", "sleep 8; /root/attack.sh; sleep infinity"]
