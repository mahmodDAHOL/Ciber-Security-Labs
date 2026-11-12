#!/bin/bash
# Samba Active Directory Domain Controller for Lab 09.
# Provisions NORTHWIND.LOCAL on first boot with deliberately attackable accounts/config, then runs samba.
# /var/lib/samba is a Docker volume (ext4) so Samba can store the security.NTACL xattrs it needs.
set -e

# so direct SamDB/ldb access loads the partition + dsdb modules (sees the domain naming context)
export LDB_MODULES_PATH=/usr/lib/x86_64-linux-gnu/samba/ldb

REALM="NORTHWIND.LOCAL"
DOMAIN="NORTHWIND"
ADMINPASS="Admin#Northwind2026"
VOL="/var/lib/samba"
PRIV="$VOL/private"
ANSWERS="$VOL/.lab09_answers.json"

PW_SVC="Welcome123!"        # service account (has an SPN)
PW_SPRAY="Spring2025!"      # reused weak password found by spraying (asmith)

if [ ! -f "$PRIV/sam.ldb" ]; then
    echo "[*] Provisioning domain $REALM ..."
    LOOT="FLAG{ad_loot_$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
    DESC="FLAG{ad_ldap_$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --use-rfc2307 --realm="$REALM" --domain="$DOMAIN" \
        --server-role=dc --dns-backend=SAMBA_INTERNAL \
        --adminpass="$ADMINPASS" --host-name=dc01 >/dev/null
    ln -sf "$PRIV/krb5.conf" /etc/krb5.conf

    echo "[*] Weakening config (the deliberate misconfigurations)"
    # allow simple LDAP binds over 389 and legacy (RC4) Kerberos — both realistic misconfigs
    sed -i '/^\[global\]/a\        ldap server require strong auth = no\n        kerberos encryption types = all' /etc/samba/smb.conf
    samba-tool domain passwordsettings set --complexity=off --min-pwd-length=1 \
        --history-length=0 --min-pwd-age=0 --max-pwd-age=0 >/dev/null

    echo "[*] Creating users"
    samba-tool user create jdoe     "Autumn2024"  --given-name=John  --surname=Doe     >/dev/null
    samba-tool user create asmith   "$PW_SPRAY"   --given-name=Alice --surname=Smith   >/dev/null
    samba-tool user create bwilson  "ReallyLongUnguessablePadding_8842" --given-name=Bob --surname=Wilson >/dev/null
    samba-tool user create svc_mssql "$PW_SVC"    --given-name=SQL   --surname=Service >/dev/null
    samba-tool user create mjones   "Zx9#qLp2_Vt7Rk" --given-name=Mary --surname=Jones >/dev/null
    samba-tool user create tclark   "Qw8!zR4_mN0pLs" --given-name=Tom  --surname=Clark >/dev/null

    echo "[*] svc_mssql gets an SPN -> (identifiable as Kerberoastable)"
    samba-tool spn add MSSQLSvc/sql01.northwind.local:1433 svc_mssql >/dev/null

    echo "[*] Staging loot share (needs valid domain creds to read)"
    mkdir -p /srv/data
    cat >> /etc/samba/smb.conf <<EOF

[data]
   path = /srv/data
   read only = yes
   valid users = @"NORTHWIND\\Domain Users"
EOF
    cp /etc/samba/smb.conf "$VOL/smb.conf.saved"

    echo "[*] Recording answers for the grader"
    cat > "$ANSWERS" <<EOF
{
  "svc_user": "svc_mssql",
  "svc_spn": "MSSQLSvc/sql01.northwind.local:1433",
  "asrep_user": "jdoe",
  "spray_user": "asmith",
  "spray_pw": "$PW_SPRAY",
  "loot_flag": "$LOOT",
  "desc_flag": "$DESC"
}
EOF
    chmod 600 "$ANSWERS"
    echo "[*] Provisioning complete."
else
    echo "[*] Domain already provisioned; restoring config."
    cp "$VOL/smb.conf.saved" /etc/samba/smb.conf
    ln -sf "$PRIV/krb5.conf" /etc/krb5.conf
fi

# (re)create the loot share contents each start (lives on the ephemeral overlay fs)
LOOT=$(python3 -c "import json;print(json.load(open('$ANSWERS'))['loot_flag'])")
DESC=$(python3 -c "import json;print(json.load(open('$ANSWERS'))['desc_flag'])")
mkdir -p /srv/data
echo "Backup service account note. $LOOT" > /srv/data/credentials.txt
chmod -R a+r /srv/data

# Post-start LDAP tweaks (idempotent), applied once the DC is up:
#  - jdoe: mark AS-REP roastable (UF_DONT_REQUIRE_PREAUTH) so recon can find it
#  - mjones: stash a secret in the description attribute (classic AD misconfig)
(
    for i in $(seq 1 60); do
        if ldbsearch -H ldap://localhost -U "Administrator%$ADMINPASS" \
               -b "DC=northwind,DC=local" "(sAMAccountName=jdoe)" dn >/dev/null 2>&1; then
            JDN=$(ldbsearch -H ldap://localhost -U "Administrator%$ADMINPASS" -b "DC=northwind,DC=local" "(sAMAccountName=jdoe)" dn 2>/dev/null | sed -n 's/^dn: //p')
            MDN=$(ldbsearch -H ldap://localhost -U "Administrator%$ADMINPASS" -b "DC=northwind,DC=local" "(sAMAccountName=mjones)" dn 2>/dev/null | sed -n 's/^dn: //p')
            ldbmodify -H ldap://localhost -U "Administrator%$ADMINPASS" >/dev/null 2>&1 <<EOF
dn: $JDN
changetype: modify
replace: userAccountControl
userAccountControl: 4260352

dn: $MDN
changetype: modify
replace: description
description: Temp vendor access note - rotate me. $DESC
EOF
            echo "[*] Post-start LDAP tweaks applied"
            break
        fi
        sleep 3
    done
) &

echo "[*] Starting Samba AD DC (foreground)"
exec samba -i -s /etc/samba/smb.conf
