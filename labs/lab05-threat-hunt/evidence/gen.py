#!/usr/bin/env python3
"""Generate a day of noisy logs with a multi-stage web intrusion hidden inside,
plus a private answer key. Everything is randomized per run."""
import json
import random
import sys
from datetime import datetime, timedelta

CASES, ANSWERS = sys.argv[1], sys.argv[2]
r = random.Random()

DAY = datetime(2026, 11, 7, 0, 0, 0)
SERVER_IP = "10.0.0.10"

# ---- randomized incident facts ----
def rand_ip():
    return f"{r.randint(11,223)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"

attacker_ip = rand_ip()
exfil_ip = rand_ip()
shell_name = r.choice(["kitten", "img2", "up_tmp", "logo", "cache", "thumb", "note"]) + str(r.randint(1, 99))
webshell_path = f"/uploads/{shell_name}.php"
secret_file = "/var/www/html/config.php"
persist_user = r.choice(["svc", "backup", "www", "nginx", "support", "ops"]) + str(r.randint(10, 99))

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]
GOOD_PATHS = ["/", "/products", "/products/42", "/cart", "/about", "/contact",
              "/static/app.css", "/static/app.js", "/static/logo.png", "/favicon.ico",
              "/search?q=widget", "/login", "/account"]
SCAN_PATHS = ["/admin", "/administrator", "/wp-login.php", "/wp-admin", "/.env",
              "/phpmyadmin", "/backup.zip", "/backup.sql", "/.git/config", "/config.php.bak",
              "/server-status", "/.aws/credentials", "/shell.php", "/old", "/test.php",
              "/admin/login", "/api/v1/users", "/db.sql", "/.htpasswd", "/uploads/"]


def ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def alog(ip, dt, method, path, status, size, ua):
    return f'{ip} - - [{ts(dt)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


access = []
# ---- background web traffic across the whole day ----
normal_ips = [rand_ip() for _ in range(40)]
for _ in range(1500):
    dt = DAY + timedelta(seconds=r.randint(0, 86399))
    ip = r.choice(normal_ips)
    path = r.choice(GOOD_PATHS)
    status = r.choices([200, 304, 200, 302, 404], weights=[60, 15, 10, 10, 5])[0]
    access.append((dt, alog(ip, dt, "GET", path, status, r.randint(200, 9000), r.choice(UAS))))

# a couple of harmless internet scanners (noise / decoys), small bursts of 404
for _ in range(3):
    noise_ip = rand_ip()
    base = DAY + timedelta(seconds=r.randint(0, 86399))
    for i in range(r.randint(5, 12)):
        dt = base + timedelta(seconds=i * 2)
        access.append((dt, alog(noise_ip, dt, "GET", r.choice(SCAN_PATHS), 404, 162, "curl/7.88.1")))

# ---- the real attack ----
atk_ua = "python-requests/2.31.0"
# 1) recon: directory brute force, mostly 404, one window
recon = DAY.replace(hour=8, minute=0)
for i, p in enumerate(SCAN_PATHS * 3):
    dt = recon + timedelta(seconds=i * 3)
    st = 404 if p not in ("/uploads/", "/admin/login") else r.choice([403, 301])
    access.append((dt, alog(attacker_ip, dt, "GET", p, st, 162, atk_ua)))
# 2) exploit: upload the web shell via a vulnerable endpoint
up = recon + timedelta(minutes=7)
access.append((up, alog(attacker_ip, up, "POST", "/admin/upload.php", 200, 54, atk_ua)))
# 3) web shell usage
for i, cmd in enumerate(["id", "whoami", "uname%20-a", f"cat%20{secret_file}"]):
    dt = up + timedelta(minutes=1 + i)
    access.append((dt, alog(attacker_ip, dt, "GET", f"{webshell_path}?cmd={cmd}", 200, r.randint(300, 2600), atk_ua)))

access.sort(key=lambda x: x[0])
with open(f"{CASES}/access.log", "w") as f:
    f.write("\n".join(line for _, line in access) + "\n")

# ---- auth.log ----
auth = []

def aline(dt, msg):
    auth.append((dt, f'{dt.strftime("%b %e %H:%M:%S")} shop {msg}'))

for h in range(0, 24):                       # hourly cron noise
    dt = DAY.replace(hour=h, minute=17)
    aline(dt, f"CRON[{r.randint(1000,9999)}]: pam_unix(cron:session): session opened for user root(uid=0)")
dt = DAY.replace(hour=7, minute=42)          # a legit admin login
aline(dt, f"sshd[{r.randint(1000,9999)}]: Accepted publickey for deploy from 10.0.0.25 port 52001 ssh2")
# attacker pivots in over SSH with stolen creds, then persists
p = DAY.replace(hour=8, minute=20)
for i in range(6):
    aline(p + timedelta(seconds=i*2), f"sshd[{r.randint(1000,9999)}]: Failed password for deploy from {attacker_ip} port {50000+i} ssh2")
aline(p + timedelta(seconds=14), f"sshd[{r.randint(1000,9999)}]: Accepted password for deploy from {attacker_ip} port 50010 ssh2")
aline(p + timedelta(minutes=1), f"useradd[{r.randint(1000,9999)}]: new user: name={persist_user}, UID=1050, GID=1050, home=/home/{persist_user}, shell=/bin/bash")
aline(p + timedelta(minutes=1, seconds=20), f"usermod[{r.randint(1000,9999)}]: add '{persist_user}' to group 'sudo'")
aline(p + timedelta(minutes=2), f"passwd[{r.randint(1000,9999)}]: password changed for {persist_user}")
auth.sort(key=lambda x: x[0])
with open(f"{CASES}/auth.log", "w") as f:
    f.write("\n".join(line for _, line in auth) + "\n")

# ---- conn.log (outbound connections: ts,src,dst,dport,bytes_out) ----
conn = ["timestamp,src_ip,dst_ip,dst_port,bytes_out"]
rows = []
for _ in range(200):
    dt = DAY + timedelta(seconds=r.randint(0, 86399))
    rows.append((dt, f"{dt.isoformat()},{SERVER_IP},{rand_ip()},{r.choice([80,443,53])},{r.randint(500,80000)}"))
# the exfiltration: one huge outbound transfer to the attacker's drop server
dt = DAY.replace(hour=8, minute=30)
rows.append((dt, f"{dt.isoformat()},{SERVER_IP},{exfil_ip},443,{r.randint(40_000_000, 90_000_000)}"))
rows.sort(key=lambda x: x[0])
conn += [row for _, row in rows]
with open(f"{CASES}/conn.log", "w") as f:
    f.write("\n".join(conn) + "\n")

# ---- case briefing ----
with open(f"{CASES}/CASE.txt", "w") as f:
    f.write(
        "CASE #2026-1107 - Northwind online shop\n"
        "=======================================\n"
        "Finance noticed the product database appears to have leaked. The web server (10.0.0.10)\n"
        "may be compromised. You have three evidence files for the day of 2026-11-07:\n\n"
        "  access.log  - web server access log (Apache combined format)\n"
        "  auth.log    - Linux authentication log from the web server\n"
        "  conn.log    - outbound network connections (CSV: timestamp,src,dst,dport,bytes_out)\n\n"
        "Reconstruct what happened and answer the questions in the lab README.\n")

json.dump({"attacker_ip": attacker_ip, "webshell_path": webshell_path,
           "secret_file": secret_file, "persist_user": persist_user,
           "exfil_ip": exfil_ip}, open(ANSWERS, "w"), indent=2)
print("generated:", attacker_ip, webshell_path, persist_user, exfil_ip)
