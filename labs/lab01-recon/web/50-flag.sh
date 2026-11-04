#!/bin/sh
# Generate a fresh flag on every container start
FLAG="FLAG{web_$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
mkdir -p /usr/share/nginx/html/backup-2024
cat > /usr/share/nginx/html/backup-2024/notes.txt <<EOF
Backup notes - DO NOT PUBLISH
------------------------------
- Old site files moved to the FTP server. Anonymous login is still enabled (TODO: disable).
- $FLAG
EOF
