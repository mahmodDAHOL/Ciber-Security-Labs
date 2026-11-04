FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl tcpdump && rm -rf /var/lib/apt/lists/*
COPY bot.sh /usr/local/bin/bot.sh
RUN sed -i 's/\r$//' /usr/local/bin/bot.sh && chmod +x /usr/local/bin/bot.sh
CMD ["/usr/local/bin/bot.sh"]
