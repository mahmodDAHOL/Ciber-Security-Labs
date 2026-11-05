#!/bin/sh
set -e
rand() { head -c"$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Wait for the Root CA to be published by the intranet container
while [ ! -s /pki/ca.key ]; do sleep 1; done

if [ ! -f /app/init ]; then
  # Server certificate signed by the Northwind Root CA (SAN = our IP)
  openssl req -newkey rsa:2048 -nodes -keyout /app/server.key -out /app/server.csr \
    -subj "/C=US/O=Northwind/CN=secure-api" 2>/dev/null
  printf 'subjectAltName=IP:10.10.30.40\n' > /app/san.cnf
  # Serial file must live on a writable path (/pki is mounted read-only here)
  openssl x509 -req -in /app/server.csr -CA /pki/ca.crt -CAkey /pki/ca.key \
    -CAserial /app/ca.srl -CAcreateserial \
    -out /app/server.crt -days 3650 -extfile /app/san.cnf 2>/dev/null
  echo "FLAG{mtls_$(rand 6)}" > /flag
  touch /app/init
fi

exec python3 -u /app/server.py
