# Lab 03: Cryptography, Hashing, Password Cracking & TLS/PKI

**Roadmap:** Phase 1 (Cryptography: hashing, symmetric/asymmetric, PKI, certificates) · **Time:** 3–5 hours · **Points:** 12

## Scenario
Two jobs at Northwind. First, a password database leaked, and you must prove how fast weak passwords fall.
Second, you're the admin finishing the TLS rollout you recommended in Lab 01: inspect the intranet's new
certificate, and use the company's certificate authority to reach a locked-down internal API.

> Don't read this folder's source files (Dockerfiles, entrypoints, server.py). They contain spoilers.

## Read first (about 2 h)
1. Hashing vs encryption vs encoding: https://www.ssl2buy.com/wiki/difference-between-hashing-and-encryption
2. How password hashes are stored (salts, `$6$` = sha512crypt): https://www.cyberciti.biz/faq/understanding-etcshadow-file/
3. John the Ripper basics: https://www.openwall.com/john/doc/EXAMPLES.shtml
4. TLS handshake, step by step: https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/
5. What a certificate authority is, and chains of trust: https://www.ssl.com/article/what-is-a-certificate-authority-ca/
6. `openssl` command cookbook (s_client, x509, req, genrsa): https://www.feistyduck.com/library/openssl-cookbook/online/

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab03-crypto-tls"
docker compose up -d --build
docker exec -it lab03-attacker bash
```
On the attacker you have `openssl`, `john`, `curl`, `nmap`. Two **read-only** mounts are provided:
`/mnt/loot/hashes.txt` (the leaked hashes) and `/mnt/pki/` (the company CA: `ca.crt`, `ca.key`). Copy them to `~` to work.

---

## Part A: Hashing & password cracking (7 pts)

| # | Task | Pts |
|---|------|-----|
| 1 | **Identify.** Look at `/mnt/loot/hashes.txt`. What hashing algorithm produced these hashes? (The prefix tells you.) | 1 |
| 2 | **Know your prefixes.** What algorithm produces a bare 32-hex-character digest like `5f4dcc3b5aa765d61d8327deb882cf99`? | 1 |
| 3 | **Crack.** Use John the Ripper with the wordlist to crack the hashes. Submit **admin's** password. | 3 |
| 4 | **Crack.** Submit **svc-backup's** password. | 2 |

```bash
cp /mnt/loot/hashes.txt ~/
john --format=crypt --wordlist=/root/wordlists/common-passwords.txt ~/hashes.txt
john --show --format=crypt ~/hashes.txt
```

### Hints
<details><summary>Tasks 1 & 2</summary>Modern Linux hashes start with <code>$6$</code>, which the <code>crypt(5)</code> man page maps to a SHA-512 based scheme. A plain unsalted 32-hex digest is the classic broken web-app hash.</details>
<details><summary>Tasks 3 & 4</summary>If <code>john</code> says "No password hashes left to crack", run <code>john --show</code> to print what it already found (it caches results in <code>~/.john/john.pot</code>).</details>

---

## Part B: TLS & PKI (5 pts)

| # | Task | Pts |
|---|------|-----|
| 5 | **Inspect a certificate.** The intranet now serves HTTPS on `https://10.10.30.20:8443`. Connect with `openssl s_client`, read its certificate, and find the **flag hidden in the certificate's fields**. | 2 |
| 6 | **Use the CA (mutual TLS).** The internal API at `https://10.10.30.40:8443` only answers clients holding a certificate **signed by the Northwind Root CA**. As the admin, you hold the CA (`/mnt/pki`). Issue yourself a client certificate, then retrieve the API's flag. | 3 |

### Task 5 walk-through
```bash
openssl s_client -connect 10.10.30.20:8443 </dev/null 2>/dev/null | openssl x509 -noout -text | less
```
Read the **Subject** line closely. One field holds a `FLAG{...}`.
Notice that **Issuer == Subject**: this certificate is *self-signed*, which is why a browser would warn. For your report,
compare that with the signed server in task 6.

### Task 6 walk-through
```bash
cp /mnt/pki/ca.crt /mnt/pki/ca.key ~/      # you are the admin; you hold the CA
# 1) Make your own key + certificate signing request (CSR)
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=analyst"
# 2) Sign the CSR with the Northwind CA -> your client certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
# 3) Present it to the API (and trust the server via the same CA)
curl --cacert ca.crt --cert client.crt --key client.key https://10.10.30.40:8443/
```
Try it first **without** `--cert`/`--key` and watch the handshake be rejected. That's mutual TLS in action.

### Hints
<details><summary>Task 5</summary><code>openssl x509 -noout -subject</code> prints just the subject line in one shot.</details>
<details><summary>Task 6</summary>The flag only comes back if your client cert is trusted. If you get an SSL error, confirm you signed <code>client.csr</code> with <b>ca.key</b> (not a self-signed cert), and that you passed <code>--cacert ca.crt</code>.</details>

---

## Submitting
In chat: `lab 3 task 1: sha512crypt`, `lab 3 task 3: <password>`, `lab 3 task 5: FLAG{...}`, etc.

## Write it up
In `lab03-crypto-tls/report.md`: how long cracking took and why salting + a slow hash still didn't save weak passwords;
the difference between a self-signed cert (task 5) and a CA-signed cert (task 6); and what mutual TLS protects against.

## Reset
```powershell
docker compose down -v; docker compose up -d --build   # new passwords, new flags, new CA
```
