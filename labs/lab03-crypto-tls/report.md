# Cryptography Assessment: Password Hashing & TLS/PKI

| | |
|---|---|
| **Engagement** | Credential-strength review + TLS/PKI exercise (lab) |
| **Scope** | Leaked password database; intranet TLS (10.10.30.20); internal API mTLS (10.10.30.40) |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-05 |
| **Classification** | Confidential |

> Lab exercise on an isolated Docker network. Cracked passwords and certificate flags are from this run.

---

## 1. Executive summary
Two exercises. First, a leaked password database was analyzed: both user passwords were **cracked in under a second**
despite using a strong, salted hashing algorithm (SHA-512 crypt), because the passwords themselves were weak.
Second, the organization's TLS rollout was reviewed: the intranet uses a **self-signed certificate** (no verified
identity), and an internal API was accessed correctly using a **client certificate signed by the corporate CA**
(mutual TLS), demonstrating a working chain of trust.

**Key message:** a strong hash does not protect a weak password, and encryption without verified identity does not
protect against impersonation.

---

## 2. Part A — Password hashing & cracking

### 2.1 Hash identification
The leaked `hashes.txt` entries began with `$6$`, identifying **SHA-512 crypt** (salted, key-stretched). For
reference, a bare 32-hex-character digest would be **MD5** (unsalted, broken for password storage).

### 2.2 Cracking
```bash
john --format=crypt --wordlist=/root/wordlists/common-passwords.txt hashes.txt
john --show --format=crypt hashes.txt
# admin:dallas
# svc-backup:hunter
```
Both fell to a dictionary attack almost instantly.

| Account | Password | Note |
|---------|----------|------|
| admin | `dallas` | administrative account |
| svc-backup | `hunter` | **service account** — high value, rarely rotated |

### 2.3 Findings
| ID | Finding | Risk |
|----|---------|------|
| C1 | Weak passwords on user and service accounts | **High** |
| C2 | Service account password in a common-password list | **High** |

**Why salting/slow hashing didn't help:** salts defeat precomputed (rainbow-table) attacks and force per-hash work,
but a password that appears in a wordlist is found on the first pass regardless. **Remediation:** enforce long
passphrases or random secrets; use a password manager / vault for service accounts; add MFA; monitor for
cracking-tool activity after any database breach.

---

## 3. Part B — TLS & PKI

### 3.1 Intranet certificate inspection (self-signed)
```bash
openssl s_client -connect 10.10.30.20:8443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```
- A flag was embedded in the certificate subject: `FLAG{tls_445b11825bae}`.
- **Issuer == Subject**, i.e. the certificate is **self-signed**. It encrypts traffic but proves no identity, so a
  browser warns and a man-in-the-middle presenting their own self-signed cert cannot be distinguished.

### 3.2 Internal API via mutual TLS (CA-signed)
The API at `10.10.30.40:8443` only answers clients holding a certificate signed by the **Northwind Root CA**.
Acting as the CA holder, a client certificate was issued and used:
```bash
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=analyst"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
curl --cacert ca.crt --cert client.crt --key client.key https://10.10.30.40:8443/
# FLAG{mtls_3a1d4e550d12}
```
Without a client certificate the handshake was rejected — confirming mutual authentication is enforced.

### 3.3 Findings / observations
| ID | Finding | Risk |
|----|---------|------|
| C3 | Intranet uses a self-signed TLS certificate (no verified identity) | **Medium** |
| C4 | (Positive) Internal API correctly enforces mutual TLS via the corporate CA | — |

**Remediation for C3:** issue the intranet certificate from the corporate CA (or a public CA) so clients can verify
identity; distribute the CA root to clients; disable plain HTTP.

---

## 4. Lessons learned
- **Self-signed vs CA-signed:** both encrypt; only the CA-signed cert proves *who* the server is. Self-signed is
  acceptable for internal testing, never for anything a user or service must trust.
- **Mutual TLS** authenticates *both* ends with certificates — strong for service-to-service and zero-trust designs,
  because it relies on possession of a private key that never leaves the host, not a reusable password.
- **The CA key is the crown jewel:** whoever holds it can mint a trusted certificate for any identity. Real CAs
  protect it in hardware security modules.
- **Encoding ≠ encryption ≠ hashing:** Base64 is reversible by anyone; encryption is reversible with a key; hashing
  is one-way. Each has its place, and confusing them causes real breaches.
