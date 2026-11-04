# Lab 01: Network Recon & Cleartext Protocols

**Roadmap:** Phase 1 (Networking & Security Foundations) · **Time:** 2–4 hours · **Points:** 12

## Scenario
You've been hired to do an authorized internal assessment of **Northwind Widgets**, a small fictional company.
You're plugged into their network at `10.10.10.5`. The network is `10.10.10.0/24`. Find out what is
running, get in where you can, and show the business why cleartext protocols are dangerous.

> Everything runs in Docker on your PC, on an isolated network. **Don't read the lab's source files**
> (Dockerfiles, scripts). They contain spoilers. Use the tools the way a real tester would.

## Read first (about 1.5 h)
1. Nmap basics: https://nmap.org/book/man-briefoptions.html and the TryHackMe room "Nmap" (free)
2. robots.txt and why it leaks information: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
3. How FTP works (active vs passive, anonymous login): https://www.jscape.com/blog/active-v-s-passive-ftp-simplified
4. HTTP Basic authentication: https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
5. tcpdump primer: https://danielmiessler.com/p/tcpdump/

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab01-recon"
docker compose up -d --build
docker exec -it lab01-attacker bash      # your attack box
```

## Tasks
| # | Task | Pts |
|---|------|-----|
| 1 | **Host discovery.** How many target hosts are on `10.10.10.0/24`? Don't count yourself (`.5`) or the Docker gateway (`.1`). | 1 |
| 2 | **Port scan.** Scan every host you found and identify the services. Which TCP port is the intranet portal (`10.10.10.50`) listening on? | 1 |
| 3 | **Web enumeration.** Explore the web server. Developers left something behind. Submit the flag you find. | 2 |
| 4 | **FTP.** A note on the web server mentions FTP. Log in and get the flag. | 2 |
| 5 | **Sniffing.** You've also compromised workstation **ws01** (`docker exec -it lab01-ws01 sh`). Capture its traffic and recover **alice's password**. | 3 |
| 6 | **Use the credentials.** Log in to the intranet admin area and submit the flag. | 3 |

Flags look like `FLAG{...}`. They're randomly generated each time the lab starts.

### Hints (only if you're stuck for more than 20 minutes)
<details><summary>Task 1</summary><code>nmap -sn</code> does a ping sweep without port scanning.</details>
<details><summary>Task 2</summary><code>nmap -sV</code> on each host. Look beyond ports 80 and 21.</details>
<details><summary>Task 3</summary>Search engines are told not to index certain paths. Where are they told that?</details>
<details><summary>Task 4</summary>The username is <code>anonymous</code>. After logging in, use <code>ls</code>, <code>cd</code> and <code>get</code>. The client starts in passive mode. Don't type <code>passive</code>, because that turns it off.</details>
<details><summary>Task 5</summary><code>tcpdump -i eth0 -A port 8080</code>. Look for an <code>Authorization:</code> header, then decode it. What encoding is it?</details>
<details><summary>Task 6</summary><code>curl -u user:pass http://...</code>. The portal's home page links to the admin area.</details>

## Submitting answers
Paste your answers to Claude in chat (e.g. "lab 1 task 3: FLAG{...}"). Claude checks them and records your progress.
Or check them yourself:
```powershell
python ..\check.py 01 3 "FLAG{...}"
```

## Write it up (required, this is portfolio material)
Write a short report in `lab01-recon/report.md`:
1. **Findings.** For each issue: what it is, how you found it (commands), its impact, and the fix.
2. **Bonus.** Save a capture with `tcpdump -w /tmp/ws01.pcap`, then copy it out with
   `docker cp lab01-ws01:/tmp/ws01.pcap .` and open it in Wireshark. Use "Follow HTTP stream".
3. **Reflection.** Why is Basic auth over HTTP unsafe, and what does HTTPS change?

When you're done, Claude will ask you three concept questions, the kind that come up in interviews.

## Stop or reset
```powershell
docker compose down -v          # stop and wipe (new flags next time)
```
