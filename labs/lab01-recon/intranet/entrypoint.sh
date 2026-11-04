#!/bin/sh
rand() { head -c"$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
echo "FLAG{intranet_$(rand 6)}" > /flag
# Shared with ws01 once; ws01 reads it into memory and deletes it
echo "Winter-$(rand 3)!" > /secrets/password
exec python3 -u /app/server.py
