#!/bin/bash
# Lab 07 target setup. Builds a low-priv foothold and FIVE independent privesc vectors,
# each guarding a root-only flag with a runtime-random value.
set -e

rand() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-12; }

# ---- flags (root-only, mode 600) --------------------------------------------
mkdir -p /root/flags
echo "FLAG{suid_$(rand)}"  > /root/flags/suid.txt
echo "FLAG{sudo_$(rand)}"  > /root/flags/sudo.txt
echo "FLAG{cron_$(rand)}"  > /root/flags/cron.txt
echo "FLAG{caps_$(rand)}"  > /root/flags/caps.txt
chown -R root:root /root/flags
chmod 700 /root/flags
chmod 600 /root/flags/*.txt

# ---- the foothold user (you "already have" these creds) ----------------------
if ! id webdev >/dev/null 2>&1; then
    useradd -m -s /bin/bash webdev
    echo 'webdev:Foothold-2024!' | chpasswd
fi

# ---- VECTOR 1: SUID binary (GTFOBins) ---------------------------------------
# find keeps its owner's (root) privileges when run; -exec ... -p gives a root shell.
chmod u+s /usr/bin/find

# ---- VECTOR 2: sudo misconfiguration (GTFOBins) -----------------------------
# webdev may run awk as root with no password -> awk can spawn a shell.
echo 'webdev ALL=(root) NOPASSWD: /usr/bin/awk' > /etc/sudoers.d/webdev
chmod 440 /etc/sudoers.d/webdev

# ---- VECTOR 3: cron job on a world-writable script --------------------------
# root runs this every minute; the script is writable by anyone.
cat > /opt/maintenance/cleanup.sh <<'EOF'
#!/bin/bash
# Nightly tidy-up (runs as root via cron). Safe by default.
rm -f /tmp/*.tmp 2>/dev/null
EOF
chown root:root /opt/maintenance/cleanup.sh
chmod 777 /opt/maintenance/cleanup.sh          # <-- the mistake: world-writable
cat > /etc/cron.d/maintenance <<'EOF'
* * * * * root /opt/maintenance/cleanup.sh
EOF
chmod 644 /etc/cron.d/maintenance

# ---- VECTOR 4: Linux capability on a copy of python -------------------------
# cap_setuid lets this binary change its UID to 0 without being SUID-root.
cp /usr/bin/python3 /opt/scripts/pyadmin
setcap cap_setuid+ep /opt/scripts/pyadmin || echo "[!] setcap failed (SETFCAP cap missing?)"
chmod 755 /opt/scripts/pyadmin

# a friendly MOTD hint
cat > /etc/motd <<'EOF'

  app-server  (Lab 07 - privilege escalation)
  You are 'webdev', a low-privileged user. Your job: become root.
  Enumerate the system and find FIVE ways up. Read: /root/flags/*.txt

EOF

# ---- start services ---------------------------------------------------------
service cron start || cron
exec /usr/sbin/sshd -D -e
