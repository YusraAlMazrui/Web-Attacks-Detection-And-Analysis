# Section 1: Detecting Web Attacks

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section covers the fundamentals of web attacks from a **defender's / SOC analyst's** point of view: how each attack works, what it looks like in logs and HTTP requests, how to tell whether it succeeded, and how to prevent it.

| # | Topic | 
|---|-------|----------|
| 1 | SQL Injection (SQLi) | 
| 2 | Cross-Site Scripting (XSS) |
| 3 | Command Injection | 
| 4 | IDOR | 
| 5 | LFI & RFI | 

---

## Foundations

### Why web attacks matter
Web applications are the most common entry point for attackers: every organization has them, they hold critical data, and they are complex with many attack vectors. The course cites Acunetix research that 75% of cyber attacks happen at the web application level.

### OWASP
- **OWASP** (Open Worldwide Application Security Project) is a non-profit focused on **web application** security.
- Its free scanning tool is **ZAP** (Zed Attack Proxy).
- **OWASP Top 10 (2021 edition, as covered in the course):** Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable and Outdated Components, Identification and Authentication Failures, Software and Data Integrity Failures, Security Logging and Monitoring Failures, SSRF.

### HTTP basics
- **Request** = request line (method + resource), headers, optional body.
- **Response** = status line, headers, body.
- **Status code classes:** 1xx informational, 2xx success, 3xx redirect, 4xx client error, 5xx server error.

---

## 1. SQL Injection (SQLi)

**What it is:** user-supplied data is placed directly into an SQL query without sanitization.

**Types**
- **In-band (classic):** query and result use the same channel; easiest to exploit.
- **Inferential (blind):** the response isn't visible, so the attacker infers results from behaviour.
- **Out-of-band:** results come back through a different channel (e.g. DNS).

**How it works:** a login query like `... WHERE username = '<input>' AND password = '<input>'` can be turned into an always-true condition with `' OR 1=1 -- -`. Everything after `-- -` is a comment, so the password check is ignored.

**What attackers gain:** authentication bypass, command execution, data exfiltration, creating/modifying/deleting database entries.

**Detecting automated tools (e.g. sqlmap)**
1. Check the **User-Agent** (tools often announce themselves).
2. Check **request frequency**: a human sends roughly 1 request/second; tools send far more.
3. Check the **payload content** (some contain the tool's name).
4. Complex, high-volume payloads suggest automation (a heuristic, not a rule).
5. To judge success, compare **response sizes**.

**Prevention:** use a framework correctly and keep it updated, sanitize all user data (headers and URLs too, not only forms), avoid raw SQL queries.

**Lab:** analysed Apache access logs from a DVWA (Damn Vulnerable Web Application) target.
- Found when the exploitation phase started, who the attacker was, and which SQLi type was used.
- Judged success by reading the requests that followed the injection attempts and their responses.

---

## 2. Cross-Site Scripting (XSS)

**What it is:** malicious script is executed in a victim's browser through a legitimate web application.

**Types**
- **Reflected (non-persistent):** payload is in the request; most common.
- **Stored (persistent):** payload is saved on the server; the most dangerous type.
- **DOM-based:** the payload runs because client-side script modifies the DOM in an unexpected way.

**Example idea:** a script injected through a URL parameter that redirects the user to another site (`window.location=...`).

**What attackers gain:** session theft, credential capture, redirecting users.

**Detection**
- Look for keywords such as `script` and `alert`.
- Learn the commonly used XSS payloads.
- Watch for special characters like `<` and `>` (and their URL-encoded forms) in user input.
- Requests from libraries like `urllib` plus high request volume point to an automated scanner.

**Lab:** analysed logs from a DVWA target.
- Identified the start of the attack, the attacker's IP, whether it was successful, and the XSS type.

---

## 3. Command Injection

**What it is:** unsanitized user input is passed straight to the operating system shell, letting the attacker run OS commands. Typically the first step toward taking control of the system.

**How it works:** `;` ends a command, so `cp letsdefend;ls;.txt` executes three separate commands. The attacker may not see the output, but the OS still runs them.

**Prevention:** sanitize all input (even file names), run the web app with least privilege, use containers (e.g. Docker).

**Detection**
1. Examine **every part** of the request, not just the obvious parameters.
2. Look for terminal keywords: `dir`, `ls`, `cp`, `cat`, `type`, etc.
3. Know common payloads, especially **reverse shells**.

**Worked example: Shellshock.** A request whose **User-Agent** contained a bash command (reading `/etc/passwd`) instead of browser info. Shellshock (disclosed 2014) abuses how bash handles environment variables.

**Lab:** analysed DVWA command-execution logs.
- Determined when the attack started, the attacker's IP, and whether it succeeded.

---

## 4. Insecure Direct Object Reference (IDOR)

**What it is:** missing or broken authorization lets one user access another user's objects by changing a parameter (e.g. `?id=1` to `?id=2`). It falls under **Broken Access Control**, #1 in the OWASP Top 10 (2021).

**Key point:** unlike most web vulnerabilities, IDOR is **not** caused by poor input sanitization; it's an authorization failure.

**What attackers gain:** personal data, unauthorized documents, unauthorized actions (modify/delete).

**Prevention:** always verify the requester is authorized for the object; accept only the minimum parameters necessary.

**Detection**
- Check **all** parameters.
- Look for many requests to the same page from one source (brute-forcing IDs).
- Look for **patterns** such as `id=1, id=2, id=3`.

**Worked example (from the course):** requests came through Cloudflare IPs (so the app sat behind Cloudflare); about 15-16 requests in a short time and a `wfuzz` User-Agent showed an automated tool. With no response bodies available, **response sizes and status codes** were used to infer success: identical small sizes were ignored, and 302 redirects suggested failure (but that alone isn't conclusive).

**Lab:** analysed IDOR logs from a DVWA target.
- Identified when the attack started, the source IP, whether it succeeded, and whether it came from an automated tool.

---

## 5. Local & Remote File Inclusion (LFI / RFI)

| | LFI | RFI |
|---|---|---|
| Included file lives on | the **same** server | **another** server controlled by the attacker |
| Typical goal | read sensitive files (e.g. `/etc/passwd`) | execute attacker-hosted code |

**How it works:** a parameter such as `language=en` maps to `website/en/home.php`. By supplying `../../../../etc/passwd`, the attacker climbs out of the directory and includes a system file. Each `../` moves up one directory.

> **Caveat:** the course shows a trailing `%00` (null byte) to cut off the appended `/home.php`. This only works on **old PHP versions** (before 5.3.4). Modern PHP rejects it.

**What attackers gain:** code execution, sensitive information disclosure, denial of service.

**Detection**
- Examine all request fields.
- Look for `/`, `.`, `\` and `../` sequences.
- Know the files commonly targeted in LFI (e.g. `/etc/passwd`).
- For RFI, look for `http://` / `https://` inside parameters, since attackers typically host the file on a small web server of their own.

**Lab:** analysed file-inclusion logs from a DVWA target.
- Identified the attacker's IP, when the attack started, and whether it succeeded.

---

## Key takeaways

- Most web-attack detection comes down to the same log checks: **User-Agent, request frequency, payload content, response size/status code**.
- Knowing common payloads and keywords for each attack makes triage much faster.
- Response size and status code are useful clues for success when response bodies aren't logged, but they're **not proof** on their own.
- Many of these vulnerabilities share one root cause: **trusting user input**. IDOR is the exception (authorization).

## Skills practised

Log analysis (Apache access logs), attacker identification (IP, timeline), automated-tool detection, success/failure assessment, attack classification.

---

*Next: [Section 2: Detecting Web Attacks - 2](02-detecting-web-attacks-2.md)*
