#!/usr/bin/env python3
"""Minimal SIEM: tail the shared auth log, parse events, evaluate detection rules,
raise alerts, and serve a dashboard. Teaches log parsing + detection-as-code."""
import glob
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

LOG = "/logs/auth.log"
RULES_DIRS = ["/opt/soc/rules/builtin", "/opt/soc/rules/custom"]
ALERTS = "/opt/soc/alerts.jsonl"
EVENTS = "/opt/soc/events.jsonl"

PATTERNS = [
    ("failed_login", re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")),
    ("accepted_login", re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")),
    ("sudo", re.compile(r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$")),
]

alerts_lock = threading.Lock()
recent_alerts = deque(maxlen=500)
windows = defaultdict(deque)       # (rule_id, groupkey) -> deque[timestamps]
cooldown = {}                      # (rule_id, dedupkey) -> last_fire_epoch


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(line):
    for etype, rx in PATTERNS:
        m = rx.search(line)
        if m:
            d = m.groupdict()
            return {"event_type": etype, "source_ip": d.get("ip"),
                    "user": d.get("user"), "command": (d.get("cmd") or "").strip(),
                    "time": now_iso(), "raw": line.strip()}
    return None


def load_rules():
    rules = []
    for d in RULES_DIRS:
        source = "builtin" if d.endswith("builtin") else "custom"
        for path in sorted(glob.glob(os.path.join(d, "*.yml")) + glob.glob(os.path.join(d, "*.yaml"))):
            try:
                r = yaml.safe_load(open(path))
                if isinstance(r, dict) and r.get("match"):
                    r["_source"] = source
                    rules.append(r)
            except Exception as e:
                print(f"[rule error] {path}: {e}")
    return rules


def matches(rule, ev):
    for k, v in rule["match"].items():
        if str(ev.get(k)) != str(v):
            return False
    return True


def fire(rule, ev, count=None):
    key = (rule.get("id"), ev.get("source_ip"), ev.get("user"), ev.get("command"))
    t = time.time()
    if t - cooldown.get(key, 0) < 15:      # suppress duplicate spam
        return
    cooldown[key] = t
    alert = {"detected_at": now_iso(), "rule_id": rule.get("id"), "title": rule.get("title"),
             "level": rule.get("level", "medium"), "mitre": rule.get("mitre", []),
             "source": rule["_source"], "event_type": ev["event_type"],
             "source_ip": ev.get("source_ip"), "user": ev.get("user"),
             "command": ev.get("command"), "count": count}
    with alerts_lock:
        recent_alerts.appendleft(alert)
        with open(ALERTS, "a") as f:
            f.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {alert['level'].upper():6} {alert['title']} "
          f"src={alert['source_ip']} user={alert['user']} {','.join(alert['mitre'])}")


def evaluate(ev, rules):
    for rule in rules:
        if not matches(rule, ev):
            continue
        th = rule.get("threshold")
        if not th:
            fire(rule, ev)
            continue
        groupkey = ev.get(th.get("by", "source_ip"))
        wk = (rule.get("id"), groupkey)
        dq = windows[wk]
        nowt = time.time()
        dq.append(nowt)
        while dq and nowt - dq[0] > th.get("window", 60):
            dq.popleft()
        if len(dq) >= th.get("count", 5):
            fire(rule, ev, count=len(dq))


def detection_loop():
    # Wait for the log file, then read from the start and follow
    while not os.path.exists(LOG):
        time.sleep(0.5)
    f = open(LOG, "r", errors="ignore")
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.4)
            continue
        ev = parse(line)
        if not ev:
            continue
        with open(EVENTS, "a") as e:
            e.write(json.dumps(ev) + "\n")
        evaluate(ev, load_rules())


DASH = """<!doctype html><html><head><meta charset=utf-8><title>Mini-SOC</title>
<meta http-equiv=refresh content=5>
<style>body{{font:14px system-ui;background:#0e1419;color:#e6edf3;margin:0;padding:20px}}
h1{{font-size:20px}}table{{border-collapse:collapse;width:100%}}
td,th{{padding:7px 10px;border-bottom:1px solid #2c3843;text-align:left}}
th{{color:#9aa7b3}}.high{{color:#f28b82;font-weight:700}}.medium{{color:#f0a44b}}.low{{color:#5fd38a}}
.pill{{background:#1f2932;border-radius:6px;padding:2px 7px;font-size:12px}}</style></head>
<body><h1>Mini-SOC &mdash; live alerts</h1>
<p class=pill>{n} alerts &middot; auto-refresh 5s</p>
<table><tr><th>Time (UTC)</th><th>Severity</th><th>Alert</th><th>Source IP</th><th>User</th><th>ATT&amp;CK</th><th>Count</th><th>Rule</th></tr>
{rows}</table></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with alerts_lock:
            data = list(recent_alerts)
        if self.path.startswith("/api"):
            body = json.dumps(data).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(body); return
        rows = "".join(
            f"<tr><td>{a['detected_at']}</td><td class={a['level']}>{a['level'].upper()}</td>"
            f"<td>{a['title']}</td><td>{a['source_ip'] or ''}</td><td>{a['user'] or ''}</td>"
            f"<td>{','.join(a['mitre'])}</td><td>{a['count'] or ''}</td>"
            f"<td class=pill>{a['rule_id']} ({a['source']})</td></tr>" for a in data) \
            or "<tr><td colspan=8>No alerts yet. Run the attack from lab04-attacker.</td></tr>"
        body = DASH.format(n=len(data), rows=rows).encode()
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    threading.Thread(target=detection_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
