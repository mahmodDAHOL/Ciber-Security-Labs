FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends vsftpd \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /var/ftp/pub /var/empty
COPY vsftpd.conf /etc/vsftpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /etc/vsftpd.conf && chmod +x /entrypoint.sh
EXPOSE 21
ENTRYPOINT ["/entrypoint.sh"]
