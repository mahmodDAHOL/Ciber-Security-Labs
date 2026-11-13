FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv git curl ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# SAST + SCA + secret-scanning tooling
RUN pip3 install --break-system-packages --no-cache-dir \
        bandit pip-audit detect-secrets

# gitleaks (secret scanning across git history) from GitHub release
RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
        -o /tmp/gl.tgz \
    && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gl.tgz

COPY vulnapp /opt/vulnapp-src
COPY scanner/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt/vulnapp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
