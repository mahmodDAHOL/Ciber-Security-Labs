FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY secure-api/entrypoint.sh /entrypoint.sh
COPY secure-api/server.py /app/server.py
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
