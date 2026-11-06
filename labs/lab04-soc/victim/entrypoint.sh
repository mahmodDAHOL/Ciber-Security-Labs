#!/bin/sh
mkdir -p /run/sshd /logs
ssh-keygen -A >/dev/null 2>&1
# Start rsyslog first so it owns /dev/log before sshd logs to it
rsyslogd
sleep 1
echo "victim up: sshd + rsyslog, auth events -> /logs/auth.log"
# No -e: sshd logs via syslog (authpriv) so rsyslog forwards it to /logs/auth.log
while true; do /usr/sbin/sshd -D; sleep 1; done
