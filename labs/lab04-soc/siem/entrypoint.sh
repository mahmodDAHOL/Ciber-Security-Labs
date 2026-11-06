#!/bin/sh
mkdir -p /opt/soc/rules/custom
: > /opt/soc/alerts.jsonl
: > /opt/soc/events.jsonl
echo "SIEM engine starting. Dashboard on :8080"
exec python3 -u /opt/soc/engine.py
