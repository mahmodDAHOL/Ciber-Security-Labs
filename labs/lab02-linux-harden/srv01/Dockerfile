FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server sudo procps nano vim-tiny less \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
    && useradd -m -s /bin/bash deploy
COPY srv01/sshd_config /etc/ssh/sshd_config
COPY common-passwords.txt /root/.lab/list.txt
COPY srv01/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /etc/ssh/sshd_config /root/.lab/list.txt && chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
