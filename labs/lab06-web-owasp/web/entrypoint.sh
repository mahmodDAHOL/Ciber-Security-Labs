#!/bin/sh
set -e
rand() { head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
mkdir -p /srv/flags /srv/files
if [ ! -f /srv/flags/.init ]; then
  echo "FLAG{sqli_login_$(rand)}"  > /srv/flags/sqli_login.txt
  echo "FLAG{sqli_union_$(rand)}"  > /srv/flags/sqli_union.txt
  echo "FLAG{idor_$(rand)}"        > /srv/flags/idor.txt
  echo "FLAG{cmdinj_$(rand)}"      > /srv/flags/cmdinj.txt
  echo "FLAG{lfi_$(rand)}"         > /srv/flags/lfi.txt
  echo "Northwind product catalogue. Public file."   > /srv/files/catalogue.txt
  echo "Return policy: 30 days."                      > /srv/files/returns.txt
  touch /srv/flags/.init
fi
exec python3 -u /opt/app.py
