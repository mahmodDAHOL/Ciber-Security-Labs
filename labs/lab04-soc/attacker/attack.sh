#!/bin/sh
# Simulated intrusion against the victim, used both for the initial incident and for replays.
#   1) SSH password brute force (many failures from one IP)
#   2) a successful login with the cracked password
#   3) privilege escalation via sudo
TARGET=10.10.40.20
USER=webadmin
PASS='Summer2024!'
SSH="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 -o PreferredAuthentications=password -o PubkeyAuthentication=no"

echo "[*] Brute forcing $USER@$TARGET ..."
i=1
while [ "$i" -le 14 ]; do
  sshpass -p "wrong_$i" $SSH "$USER@$TARGET" true 2>/dev/null
  i=$((i+1))
done

echo "[*] Logging in with the cracked password and escalating ..."
sshpass -p "$PASS" $SSH "$USER@$TARGET" 'sudo -n id' 2>/dev/null

echo "[*] Done. Check the SIEM."
