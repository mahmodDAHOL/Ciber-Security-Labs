#!/bin/sh
# Simulated user: alice's workstation polls the intranet with Basic auth over plain HTTP
while [ ! -s /secrets/password ]; do sleep 1; done
PW=$(cat /secrets/password)
rm -f /secrets/password
while true; do
  curl -s -o /dev/null -u "alice:$PW" http://10.10.10.50:8080/status
  sleep 5
done
