# Lab 09: Active Directory — Enumeration, Spraying & Initial Access

**Roadmap:** Phase 4 (Active Directory attacks) · **Time:** 4–6 hours · **Points:** 14

## Scenario
Northwind runs a Windows domain, **`NORTHWIND.LOCAL`**, served by a domain controller at `10.10.90.10`
(`dc01.northwind.local`). You're on an internal network pentest with **no credentials yet** — just a foothold
host on the network (your attack box). Your goal is the classic AD kill-chain opening: **enumerate the
domain, discover a valid credential, and use it to reach data you shouldn't**.

> The DC is a real Kerberos/LDAP/SMB Active Directory domain (built on Samba). You attack it with the same
> tools used against Windows AD: `kerbrute`, `ldapsearch`, `smbclient`, Impacket.

## A note on scope (read this)
This lab focuses on the part of AD attacks that is **identical on Linux and Windows**: unauthenticated
enumeration, password spraying, LDAP/SMB reconnaissance, and credentialed access. The DC is a Samba AD DC,
and Samba's Kerberos differs from Windows enough that **Impacket's roasting/replication attacks
(AS-REP roasting, Kerberoasting, DCSync) do not work reliably against it** — so here you'll *identify* the
roastable accounts (the recon that precedes those attacks) and we cover the exploitation conceptually. To
practice the full roast-and-crack against a true Windows DC, use **HackTheBox / TryHackMe** AD boxes or a
Windows-based GOAD lab. Everything in *this* lab is the real, transferable groundwork.

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab09-active-directory"
docker compose up -d --build
```
First boot provisions the domain (~1 minute). Then jump on the attack box:
```powershell
docker exec -it lab09-attacker bash
```
From there the DC is `10.10.90.10` / `dc01.northwind.local`. You have `kerbrute`, `ldapsearch`,
`smbclient`, Impacket, and two wordlists: `/root/users.txt` (usernames) and `/root/wordlist.txt` (passwords).

## Read first (about 1.5 h)
1. AD reconnaissance methodology: https://www.thehacker.recipes/a-d/recon
2. Password spraying: https://www.thehacker.recipes/a-d/movement/credentials/bruteforcing/password-spraying
3. LDAP enumeration: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ldap.html
4. kerbrute (user enum + spray): https://github.com/ropnop/kerbrute
5. AS-REP roasting & Kerberoasting (concepts — the recon you do here leads into these): https://www.thehacker.recipes/a-d/movement/kerberos/

---

## Tasks (14 pts)
Each flag looks like `FLAG{ad_..._...}`. Submit flags, usernames, or the SPN as asked.

| # | Task | Technique | Pts |
|---|------|-----------|-----|
| 1 | **Unauth user enumeration.** Without creds, enumerate valid domain users with `kerbrute userenum` and `/root/users.txt`. Submit the **service account's** username (the one whose name marks it as a service). | T1087 (Account Discovery) | 2 |
| 2 | **Password spraying.** One user reuses a weak seasonal password. Spray `/root/users.txt` with a likely candidate and submit the **username** that logs in. | T1110.003 | 3 |
| 3 | **SMB loot.** Use the recovered credentials to list and read the restricted SMB share on the DC. Submit the flag in the file there. | T1021.002 | 3 |
| 4 | **LDAP secret.** Authenticated LDAP enumeration reveals a credential/secret an admin carelessly stored in a user's **`description`** attribute. Submit the flag. | T1552 (Unsecured Credentials) | 3 |
| 5 | **Attack-path recon.** Find the account configured as **AS-REP roastable** (its `userAccountControl` has `DONT_REQ_PREAUTH`). Submit its **username**. | T1558.004 (recon) | 2 |
| 6 | **Knowledge.** What is the MITRE ATT&CK **sub-technique ID** for Password Spraying? | — | 1 |

### Starter commands (figure out the exact flags/filters yourself)
```bash
# Task 1 - who exists? (no creds needed; Kerberos tells you which usernames are valid)
kerbrute userenum -d northwind.local --dc 10.10.90.10 /root/users.txt

# Task 2 - spray a seasonal password across everyone (think: Spring/Summer/Autumn + year + !)
kerbrute passwordspray -d northwind.local --dc 10.10.90.10 /root/users.txt '<password>'

# Task 3 - with user:pass, list shares then read the non-default one
smbclient -L //10.10.90.10 -U 'NORTHWIND\<user>%<pass>'
smbclient //10.10.90.10/<share> -U 'NORTHWIND\<user>%<pass>' -c 'ls; get <file>'

# Task 4 - dump every user's description attribute over LDAP and read them
ldapsearch -x -H ldap://10.10.90.10 -D '<user>@northwind.local' -w '<pass>' \
  -b 'DC=northwind,DC=local' '(objectClass=user)' sAMAccountName description

# Task 5 - LDAP bitwise filter for the DONT_REQ_PREAUTH bit (0x400000 = 4194304)
ldapsearch -x -H ldap://10.10.90.10 -D '<user>@northwind.local' -w '<pass>' \
  -b 'DC=northwind,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
```

### Hints
<details><summary>Task 2</summary>Seasonal passwords follow <code>Season+Year+!</code>. The year is recent, the season isn't winter or summer. Spray one candidate at a time to avoid lockouts (policy is off here, but it's good practice).</details>
<details><summary>Task 4</summary>Request the <code>description</code> attribute for all users and skim them — one reads like a note an admin left behind. The flag is inside it.</details>
<details><summary>Task 5</summary>The magic LDAP OID <code>1.2.840.113556.1.4.803</code> is a bitwise-AND match. <code>4194304</code> is the <code>DONT_REQ_PREAUTH</code> bit. Exactly one account matches.</details>

---

## Submitting
In chat: `lab 9 task 1: svc_...`, `lab 9 task 3: FLAG{ad_loot_...}`, `lab 9 task 6: T1110.003`, etc.

## Write it up
In `lab09-active-directory/report.md`, write an **internal AD pentest** report: the enumeration that found the
attack surface, the spray that gave initial access, what that access exposed (SMB share, LDAP secrets), and the
attack paths you identified (AS-REP-roastable user, SPN account). Remediation: strong/unique passwords + MFA,
no secrets in LDAP attributes, least-privilege share ACLs, require Kerberos pre-auth, and monitoring for
spraying (many failed logons across accounts) — tie this back to the detections you built in Lab 04.

## Reset (new flags)
```powershell
docker compose down -v; docker compose up -d --build
```
Wait ~1 minute for the domain to re-provision.
