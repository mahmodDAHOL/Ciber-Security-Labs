#!/bin/sh
mkdir -p /cases
if [ ! -f /root/.answers.json ]; then
  python3 /opt/gen.py /cases /root/.answers.json
  echo "evidence generated in /cases"
fi
sleep infinity
