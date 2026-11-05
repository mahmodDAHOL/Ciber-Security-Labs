FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl python3 whois \
    && rm -rf /var/lib/apt/lists/*
COPY common-passwords.txt /root/.lab/list.txt
COPY intranet/entrypoint.sh /entrypoint.sh
COPY intranet/server.py /app/server.py
RUN sed -i 's/\r$//' /entrypoint.sh /root/.lab/list.txt && chmod +x /entrypoint.sh
EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
