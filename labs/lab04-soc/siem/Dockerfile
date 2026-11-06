FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-yaml less nano \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/soc
COPY siem/engine.py /opt/soc/engine.py
COPY siem/soc /usr/local/bin/soc
COPY siem/rules /opt/soc/rules
COPY siem/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /usr/local/bin/soc /opt/soc/engine.py \
    && chmod +x /entrypoint.sh /usr/local/bin/soc
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
