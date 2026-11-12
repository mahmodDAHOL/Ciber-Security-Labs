#!/bin/bash
# Lab 10 victim container. A deliberately over-privileged "web app" container:
#  - the host Docker socket is bind-mounted in (the critical misconfiguration)
#  - it runs --privileged
#  - a cloud API key is exposed in the environment
# On start it seeds the flags, using its own Docker-socket access to plant a flag on the HOST.
set -e

rand() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
HOST_FLAG="FLAG{esc_host_$(rand)}"
CONFIG_FLAG="FLAG{esc_config_$(rand)}"
# the env flag is injected statically by compose as APP_CLOUD_KEY
ENV_FLAG="${APP_CLOUD_KEY:-UNSET}"

# a secret config file inside the container (represents app secrets on disk)
mkdir -p /etc/app
cat > /etc/app/database.conf <<EOF
[database]
host = db.internal
user = appsvc
# TODO: move this out of the image
backup_token = $CONFIG_FLAG
EOF
chmod 600 /etc/app/database.conf

# Use the mounted Docker socket to plant a flag on the HOST filesystem (proves socket = host root).
if docker info >/dev/null 2>&1; then
    docker run --rm -v /:/host debian:bookworm-slim \
        sh -c "mkdir -p /host/opt/lab10 && echo '$HOST_FLAG' > /host/opt/lab10/host_flag && chmod 644 /host/opt/lab10/host_flag" \
        >/dev/null 2>&1 && echo "[*] host flag planted via docker socket" || echo "[!] could not plant host flag"
else
    echo "[!] docker socket not reachable from entrypoint"
fi

# record canonical answers for the grader (root-only)
cat > /root/.lab10_answers.json <<EOF
{
  "host_flag": "$HOST_FLAG",
  "config_flag": "$CONFIG_FLAG",
  "env_flag": "$ENV_FLAG"
}
EOF
chmod 600 /root/.lab10_answers.json

echo "[*] Lab 10 victim ready."
exec sleep infinity
