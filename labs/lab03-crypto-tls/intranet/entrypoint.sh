#!/bin/sh
set -e
rand() { head -c"$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# --- One-time setup: certificate authority, leaked hashes, self-signed TLS cert ---
if [ ! -f /root/.lab/init ]; then

  # 1) Northwind Root CA, published to the shared pki volume (the admin, on the attacker box, holds it)
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /pki/ca.key -out /pki/ca.crt \
    -days 3650 -subj "/C=US/O=Northwind/CN=Northwind Root CA" 2>/dev/null
  chmod 644 /pki/ca.key /pki/ca.crt

  # 2) "Leaked" password database: two users, sha512crypt hashes, plaintext from the wordlist
  ADMIN_PW=$(shuf -n1 /root/.lab/list.txt)
  SVC_PW=$(shuf -n1 /root/.lab/list.txt)
  echo "$ADMIN_PW" > /root/.lab/admin_pw
  echo "$SVC_PW"   > /root/.lab/svc_pw
  {
    printf 'admin:%s\n'       "$(openssl passwd -6 "$ADMIN_PW")"
    printf 'svc-backup:%s\n'  "$(openssl passwd -6 "$SVC_PW")"
  } > /loot/hashes.txt
  chmod 644 /loot/hashes.txt

  # 3) Intranet's own TLS certificate: SELF-SIGNED, with a flag hidden in the OU field
  echo "FLAG{tls_$(rand 6)}" > /flag
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /app/srv.key -out /app/srv.crt \
    -days 3650 -subj "/C=US/O=Northwind/OU=$(cat /flag)/CN=intranet.northwind.local" 2>/dev/null

  touch /root/.lab/init
fi

exec python3 -u /app/server.py
