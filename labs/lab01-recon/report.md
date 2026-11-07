# Internal Network Assessment: Northwind Widgets

| | |
|---|---|
| **Engagement** | Internal network penetration test (lab exercise) |
| **Scope** | `10.10.10.0/24`, tester positioned at `10.10.10.5` |
| **Date** | 2026-11-03 |
| **Tester** | Mahmod Aldahol |
| **Classification** | Confidential |

> Northwind Widgets is a fictional company. All testing took place in an isolated Docker lab owned by the tester.

---

## 1. Executive summary

An attacker with only a network connection inside Northwind's office gained access to the **intranet administration area in under an hour**, without exploiting any software vulnerability.
They did it by chaining five configuration weaknesses: files left on the public web server, an FTP server that accepts anyone, passwords sent across the network unencrypted, and an intranet that lets any logged-in user open admin pages.

**Overall risk: High.**
The most important fixes are to **enable HTTPS on the intranet** and **restrict the admin area to administrators**. Together they would have broken this attack chain.

---

## 2. Methodology

The test followed a standard internal pentest flow (PTES):

1. **Discovery:** find live hosts
2. **Enumeration:** identify services and versions
3. **Exploitation:** abuse misconfigurations to gain access
4. **Post-exploitation:** capture credentials from a compromised workstation and reuse them

Tools: `nmap 7.93`, `curl`, `ftp`, `tcpdump`, `base64`.

---

## 3. Attack chain

```
[1] nmap ping sweep          → 4 hosts found
[2] nmap service scan        → web (80), ftp (21), intranet (8080, Basic auth)
[3] robots.txt               → hidden path /backup-2024/
[4] filename guessing        → /backup-2024/notes.txt: "anonymous FTP still enabled"
[5] anonymous FTP            → it-notes.txt: "ws01 polls intranet over HTTP with alice's account"
[6] tcpdump on ws01          → Authorization: Basic header captured
[7] base64 decode            → alice's cleartext password
[8] credential reuse         → /admin/flag.txt readable by a non-admin user
```

### 3.1 Host discovery

```bash
nmap -sn 10.10.10.0/24
```

| IP | Hostname (reverse DNS) | Role |
|---|---|---|
| 10.10.10.20 | lab01-web | Public website |
| 10.10.10.30 | lab01-ftp | File server |
| 10.10.10.40 | lab01-ws01 | Staff workstation |
| 10.10.10.50 | lab01-intranet | Intranet portal |

Reverse DNS names revealed the purpose of each host before any port was scanned.

### 3.2 Service enumeration

```bash
nmap -sV 10.10.10.20 10.10.10.30 10.10.10.50
```

| Host | Port | Service |
|---|---|---|
| 10.10.10.20 | 80/tcp | nginx 1.27.5 |
| 10.10.10.30 | 21/tcp | vsftpd |
| 10.10.10.50 | 8080/tcp | IntranetPortal/1.0, returns `401` with `WWW-Authenticate: Basic realm="Northwind Intranet"` |

### 3.3 Web server: hidden backup folder

```bash
curl -i http://10.10.10.20/robots.txt        # Disallow: /backup-2024/
curl -i http://10.10.10.20/backup-2024/      # 403 Forbidden (listing off, folder exists)
```

Common filenames were then tried against the folder:

```bash
for f in index.html backup.zip backup.tar.gz db.sql notes.txt readme.txt config.php .env passwords.txt; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://10.10.10.20/backup-2024/$f)
  echo "$code  $f"
done
# 200  notes.txt   (all others 404)
```

`notes.txt` contained: *"Old site files moved to the FTP server. Anonymous login is still enabled (TODO: disable)."*

### 3.4 Anonymous FTP

```
ftp 10.10.10.30
Name: anonymous      Password: (blank)
ftp> cd pub
ftp> get it-notes.txt
```

`it-notes.txt` contained: *"The intranet portal on 10.10.10.50 still uses plain HTTP with Basic auth. Workstation ws01 polls it automatically with alice's account every few seconds."*

### 3.5 Credential capture on ws01

With access to workstation ws01, its traffic to the intranet was captured:

```bash
tcpdump -i eth0 -A port 8080
# GET /status HTTP/1.1
# Authorization: Basic YWxpY2U6V2ludGVy****************
echo 'YWxpY2U6V2ludGVy...' | base64 -d
# alice:Winter-59****!
```

A new request arrived every 5 seconds, so the credentials could be captured almost immediately.

### 3.6 Credential reuse and admin access

From the attacker machine (not ws01):

```bash
curl -i http://10.10.10.50:8080/admin/flag.txt                         # 401 Unauthorized
curl -u alice:'Winter-59****!' http://10.10.10.50:8080/                  # portal home, links to /admin
curl -u alice:'Winter-59****!' http://10.10.10.50:8080/admin/flag.txt    # 200 OK, admin content
```

A standard staff account was able to read the administration area.

---

## 4. Findings

| ID | Finding | Risk |
|---|---|---|
| F1 | Credentials transmitted in cleartext (HTTP Basic auth) | **High** |
| F2 | Broken access control on `/admin` | **High** |
| F3 | Anonymous FTP exposes internal information | **Medium** |
| F4 | Sensitive files on web server, path disclosed in `robots.txt` | **Medium** |
| F5 | Web server version disclosure | **Low** |

### F1: Credentials transmitted in cleartext (High)

**Description:** The intranet uses HTTP Basic authentication over unencrypted HTTP. Basic auth only Base64-*encodes* the username and password. It does not encrypt them, so anyone who can observe the traffic can read them. An automated job on ws01 sends alice's credentials every 5 seconds.

**Impact:** Anyone on the network path, or any compromised host, can steal valid credentials and log in as alice.

**Evidence:** Section 3.5.

**Recommendations:**
- Serve the intranet over **HTTPS only** (TLS 1.2+), and redirect or block plain HTTP.
- Replace Basic auth with session- or token-based login, and add **MFA** for remote and admin access.
- Run automated jobs under a dedicated **service account** with minimal rights, not a person's account.
- **Reset alice's password immediately.**

### F2: Broken access control on `/admin` (High)

**Description:** The portal checks that a user is logged in (authentication) but not whether they are allowed to open admin pages (authorization). A regular account, alice, could read `/admin/flag.txt`. This falls under **OWASP Top 10 2021, A01: Broken Access Control**.

**Impact:** Any staff account, or any stolen staff credential (see F1), gives administrator-level access.

**Evidence:** Section 3.6.

**Recommendations:**
- Enforce role-based access control on the server for every `/admin` route. Deny by default.
- Add automated tests that confirm non-admin users receive `403` on admin endpoints.
- Log and alert on access to admin paths.

### F3: Anonymous FTP exposes internal information (Medium)

**Description:** The FTP server accepts the `anonymous` login with no password and serves internal IT notes. FTP also sends all data and credentials in cleartext.

**Impact:** Unauthenticated users can read internal documents. In this test, the notes revealed the intranet's weak authentication and a username.

**Evidence:** Section 3.4.

**Recommendations:**
- Set `anonymous_enable=NO` in `vsftpd.conf`.
- Replace FTP with **SFTP**, or decommission it if it's no longer needed.
- Review stored files and remove internal documentation from file-sharing services.

### F4: Sensitive files on web server, path disclosed in `robots.txt` (Medium)

**Description:** `robots.txt` lists `/backup-2024/`, a folder of internal notes. Directory listing is disabled (`403`), but files inside it can be read by anyone who guesses their names. `robots.txt` is public and is one of the first files attackers check. Hiding a path there is security through obscurity.

**Impact:** Disclosure of internal information that led directly to F3.

**Evidence:** Section 3.3.

**Recommendations:**
- Remove backups and internal notes from the web root entirely.
- Never list sensitive paths in `robots.txt`.
- If a folder must stay on the server, protect it with authentication.

### F5: Web server version disclosure (Low)

**Description:** HTTP responses include `Server: nginx/1.27.5`.

**Impact:** Attackers can look up known vulnerabilities for that exact version without having to probe.

**Recommendations:** Add `server_tokens off;` to the nginx configuration and keep nginx up to date.

---

## 5. Remediation priority

| Priority | Action | Fixes |
|---|---|---|
| 1 (now) | Reset alice's password; enable HTTPS on the intranet | F1 |
| 2 (this week) | Enforce admin role checks on `/admin` | F2 |
| 3 (this week) | Disable anonymous FTP / migrate to SFTP | F3 |
| 4 (this month) | Clean the web root; fix `robots.txt`; `server_tokens off` | F4, F5 |
| 5 (this month) | Move the ws01 job to a service account; add MFA | F1 |

---

## 6. Evidence: packet capture

_Add a screenshot of Wireshark "Follow → HTTP Stream" showing the `Authorization: Basic` header here._

```bash
docker exec lab01-ws01 tcpdump -i eth0 -c 20 -w /tmp/ws01.pcap port 8080
docker cp lab01-ws01:/tmp/ws01.pcap .
```

---

## 7. Lessons learned

- **Chained low and medium findings can add up to a high-impact compromise.** None of these issues alone gave admin access. Combined, they did.
- **Encoding is not encryption.** Base64 can be reversed by anyone, with no key.
- **HTTPS alone would not have been enough.** It stops F1's sniffing, but F2, F3, F4 and F5 would remain. An attacker who controls ws01 could also read the credentials from the job's configuration or memory. Defense in depth means fixing every layer.
