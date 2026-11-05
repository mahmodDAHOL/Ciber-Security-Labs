#!/bin/sh
# First start only: plant weak credentials and misconfigurations.
# Later restarts keep whatever hardening the student applied.
rand() { head -c"$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
chmod 700 /root
if [ ! -f /root/.lab/init ]; then
  PW=$(shuf -n1 /root/.lab/list.txt)
  echo "deploy:$PW" | chpasswd
  echo "$PW" > /root/.lab/deploy_pw
  echo "root:$(rand 16)" | chpasswd
  echo "FLAG{root_$(rand 6)}" > /root/flag.txt
  chmod 600 /root/flag.txt
  echo 'deploy ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/deploy
  chmod 440 /etc/sudoers.d/deploy
  chmod 644 /etc/shadow
  touch /root/.lab/init
fi
mkdir -p /run/sshd
ssh-keygen -A >/dev/null
# Keep sshd alive even if it is stopped by mistake; reload config with: kill -HUP $(cat /run/sshd.pid)
while true; do /usr/sbin/sshd -D -e; sleep 1; done
