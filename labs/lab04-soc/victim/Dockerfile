FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server sudo rsyslog procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash webadmin \
    && echo 'webadmin:Summer2024!' | chpasswd \
    && echo 'webadmin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/webadmin \
    && chmod 440 /etc/sudoers.d/webadmin
COPY victim/rsyslog.conf /etc/rsyslog.conf
COPY victim/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /etc/rsyslog.conf && chmod +x /entrypoint.sh \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
