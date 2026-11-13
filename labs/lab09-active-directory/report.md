# Internal Penetration Test: NORTHWIND.LOCAL Active Directory

| | |
|---|---|
| **Engagement** | Lab 09 — Internal AD penetration test (initial access) |
| **Target** | `NORTHWIND.LOCAL` domain · DC `dc01` (`10.10.90.10`) |
| **Starting access** | Network access only — no credentials |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-12 |
| **Overall risk** | **High** — unauthenticated enumeration → weak-credential foothold → sensitive data access |

> Lab exercise against a real (Samba) AD domain. Flags regenerate on reset — proof of access, not secrets.
> Scope: enumeration and initial access. (Kerberos roasting/DCSync are out of scope here — the recon that
> precedes them is included.)

## 1. Executive summary
Starting with **no credentials**, I enumerated the domain, discovered a user with a **weak, guessable
password** via password spraying, and used that foothold to read a **restricted file share** and a **secret
stored in an LDAP attribute**. I also identified an account configured as **AS-REP roastable** — an attack
path that, on a production Windows DC, leads to offline credential cracking. The chain is driven entirely by
**weak credentials and over-exposed information**, each with a direct fix (§4).

**Weakest link.** The weak password on `asmith` — everything else in the chain depends on getting that first
foothold. No creds, enumerate, spray, and one seasonal password opens the door. I'd fix that first: a strong
password policy plus MFA kills the spray, and the rest of the chain never even starts.

## 2. Findings at a glance
| # | Finding | MITRE ATT&CK | Severity |
|---|---------|--------------|----------|
| F-1 | Unauthenticated domain user enumeration | T1087 Account Discovery | Low |
| F-2 | Weak/guessable account password (spray) | T1110.003 Password Spraying | **High** |
| F-3 | Sensitive data on a credentialed SMB share | T1021.002 | Medium |
| F-4 | Secret stored in an LDAP `description` attribute | T1552 Unsecured Credentials | Medium |
| F-5 | AS-REP-roastable account (no Kerberos pre-auth) | T1558.004 | Medium |

## 3. Detailed findings

### F-1 — Unauthenticated user enumeration · Low · T1087
**Description.** The Kerberos KDC distinguishes valid from invalid usernames (pre-auth response vs. principal
unknown), allowing username enumeration with no credentials.
**PoC:** `kerbrute userenum -d northwind.local --dc 10.10.90.10 users.txt` → valid users incl. the service
account `svc_mssql`.
**Impact.** Provides the username list that powers password spraying (F-2). Low on its own, enabling in chain.
**Remediation.** Can't fully disable (protocol behaviour), but monitor for enumeration bursts; avoid predictable
service-account names; alert on high volumes of pre-auth failures.

### F-2 — Weak password found by spraying · High · T1110.003
**Description.** The account `asmith` used a weak seasonal password. Spraying one candidate across all users
avoids lockouts and found it.
**PoC:** `kerbrute passwordspray -d northwind.local --dc 10.10.90.10 users.txt 'Spring2025!'`
→ `VALID LOGIN: asmith@northwind.local:Spring2025!`.
**Impact.** Initial domain foothold — authenticated access to SMB, LDAP, and more.
**Remediation.** Enforce a strong password policy + MFA; ban seasonal/breached passwords (Azure AD Password
Protection / a denylist); alert on spraying (many accounts, few passwords, in a short window).

### F-3 — Sensitive data on an SMB share · Medium · T1021.002
**Description.** With `asmith`'s credentials, a non-default SMB share on the DC was readable and held sensitive
data.
**PoC:**
```bash
smbclient -L //10.10.90.10 -U 'NORTHWIND\asmith%Spring2025!'
smbclient //10.10.90.10/data -U 'NORTHWIND\asmith%Spring2025!' -c 'get credentials.txt'
# -> FLAG{ad_loot_...}
```
**Impact.** Any authenticated user reaches the data; shares are a top source of credential sprawl in real AD.
**Remediation.** Least-privilege share ACLs; don't store secrets on shares; audit share permissions regularly.

### F-4 — Secret in an LDAP attribute · Medium · T1552
**Description.** A user's `description` attribute (readable by any authenticated user) contained a credential.
**PoC:**
```bash
ldapsearch -x -H ldap://10.10.90.10 -D 'asmith@northwind.local' -w 'Spring2025!' \
  -b 'DC=northwind,DC=local' '(objectClass=user)' sAMAccountName description
# -> description on mjones: ... FLAG{ad_ldap_...}
```
**Impact.** Credential disclosure to every domain user; BloodHound/ldapsearch sweep these automatically.
**Remediation.** Never store secrets in `description`/`info`/`comment`; audit directory attributes for secrets.

### F-5 — AS-REP-roastable account · Medium · T1558.004
**Description.** `jdoe` is configured with "do not require Kerberos pre-authentication" (`DONT_REQ_PREAUTH`),
making it AS-REP roastable.
**PoC (recon):**
```bash
ldapsearch -x -H ldap://10.10.90.10 -D 'asmith@northwind.local' -w 'Spring2025!' \
  -b 'DC=northwind,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName   # -> jdoe
```
On a Windows DC the next step is `GetNPUsers.py` → crack the AS-REP hash offline.
**Impact.** If the account's password is weak, an attacker cracks it offline with no lockout risk.
**Remediation.** Remove `DONT_REQ_PREAUTH` unless strictly required; where required, enforce a long random
password; monitor AS-REQ-without-preauth requests.

## 4. Remediation summary (priority order)
| Priority | Action | Finding |
|----------|--------|---------|
| 1 | Strong password policy + MFA; ban seasonal/breached passwords | F-2 |
| 2 | Least-privilege SMB share ACLs; remove secrets from shares | F-3 |
| 3 | Remove secrets from LDAP attributes | F-4 |
| 4 | Require Kerberos pre-auth; strong passwords on any exception | F-5 |
| — | **Ongoing:** monitor spraying + enumeration; run BloodHound defensively to find attack paths | all |

## 5. Lessons learned
- **No creds ≠ no access:** enumeration + spraying turns "network access only" into a domain foothold fast.
- **Authenticated ≠ trusted:** once in, shares and LDAP attributes leak far more than they should — least
  privilege and secret hygiene matter as much as the password policy.
- **Spraying is loud if you're watching:** many accounts failing one password in a short window is a
  high-signal detection (ties directly to the Lab 04 SIEM threshold rules).

**What the SIEM would catch.** The password spray (F-2) is the most detectable, and it ties straight to the
threshold rule I built in Lab 04. The rule: count logon / Kerberos pre-auth failures across the domain in a
short window and alert when many *different* accounts fail from one source in, say, a minute. Spraying is the
opposite shape to brute force — few passwords, many accounts — so the detection is "N distinct accounts
failing in T seconds," not "N failures on one account." The enumeration (F-1) also shows up as a burst of
pre-auth requests for usernames. The LDAP/SMB reads (F-3, F-4) are quieter and harder to catch.
