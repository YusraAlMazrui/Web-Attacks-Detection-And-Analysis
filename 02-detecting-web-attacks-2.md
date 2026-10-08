# Section 2: Detecting Web Attacks - 2

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section continues with four more web attacks, again focused on how to **recognize them in access logs**, what impact they have, and how to prevent them.

| # | Topic | 
|---|-------|
| 1 | Open Redirection |
| 2 | Directory Traversal | 
| 3 | Brute Force | 
| 4 | XML External Entity (XXE) | 

The labs in this section use `access.log` files from a web server hosting a blog-style application, organized in separate folders per attack (`Open-Redirection`, `Directory-Traversal`, `Brute-Force`, `XML-External-Entity`).

---

## 1. Open Redirection

**What it is:** the application redirects users to a URL without validating it. An attacker crafts a legitimate-looking link on the trusted site that carries a malicious destination in a parameter.

**Types**
1. **URL-based:** the most common; a URL parameter is used directly in the redirect.
2. **JavaScript-based:** client-side script redirects to a user-controlled value.
3. **Meta refresh-based:** an HTML `meta refresh` tag uses an untrusted URL.
4. **Header-based:** the `Location` header is built from user input.
5. **Parameter-based:** a URL or form parameter feeds the redirect process.

**Impact:** phishing, malware distribution, social engineering, reputation damage, legal/regulatory consequences.

**Prevention**
- Validate and sanitize any input used in a redirect.
- Use an **allow-list** (whitelist) of trusted destinations instead of blocking bad patterns.
- Avoid user-controlled data in redirects altogether where possible.
- Enforce authentication/authorization, follow secure coding practices, keep software updated.
- Educate users about suspicious links.

**Lab:** analysed an `access.log`.
- Found when the exploitation phase started, the attacker's IP, and which **parameter** was abused.
- Looked for URLs inside parameters pointing to external domains.

---

## 2. Directory Traversal

**What it is:** manipulating input to reach files **outside the web root** (the "dot-dot-slash" attack), e.g. `picture.php?name=../../etc/passwd`.

**How it differs from LFI:** the two look similar. Directory traversal is about reading files by escaping the intended directory; LFI is about making the application *include* (and potentially execute) a local file.

**Possible vectors:** user input, cookies, HTTP headers (Referer, User-Agent), file uploads, direct requests, URL manipulation.

**Impact:** disclosure of sensitive data, arbitrary code execution, denial of service, full system compromise.

**Prevention**
1. Input validation and sanitization.
2. Access controls and least-privilege file permissions.
3. Relative paths where possible.
4. Whitelisting allowed characters/values.
5. Secure coding (don't build file paths from raw user input; avoid dangerous functions like `eval()` / `system()`).
6. Web Application Firewall (WAF).

**Detection**
- Look for `../`, `..\` and **encoded variants** (URL-encoding, Unicode). Attackers use encoding to bypass WAFs.
- Know sensitive target files.
  - **Linux:** `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/hosts`, `/etc/issue`
  - **Windows:** `boot.ini`, `inetpub\wwwroot\web.config`, `inetpub\wwwroot\global.asa`, `sysprep.inf`, IIS log folders

**Lab:** analysed an `access.log`.
- Identified when the exploitation phase started, the attacker's IP, and the vulnerable parameter.

---

## 3. Brute Force

**What it is:** systematically trying credentials (username/password combinations) against a login until one works, usually with automated tools or scripts.

**Why a form is vulnerable:** no limit on login attempts and no bot protection. The course showed a simple PHP login form and a Python `requests` script looping over usernames and passwords.

**Impact:** denial of service (resource exhaustion), data leakage, account takeover, password-reuse risk, legal and reputational consequences for the victim organization.

**Prevention**
- Account lockout policies
- CAPTCHA
- Rate limiting
- Multi-factor authentication
- Monitoring login attempts
- Strong password policies
- **WAF** help: IP blocking and user-behaviour analysis

**Detection**
- Collect **authentication logs** (successes *and* failures).
- Look for many failed logins from one IP or against one account.
- Look for repeated requests to the login page or to non-existent pages.
- Use an **IDS/IPS**, and look for dictionary attacks and password spraying.
- Tools: ELK stack (Elasticsearch, Logstash, Kibana), regular expressions.
- Example regex idea: match repeated `POST/GET /login.php` requests with `401`/`403` status codes and capture the client IP, then count per IP.

**Response:** block IPs (e.g. `deny` rules in nginx, **Fail2ban**), lock accounts, add controls.

> **Important nuance from the course:** if a log only contains failed logins, you can't tell whether the attack succeeded. Successful logins typically show a `200` or a redirect, so you need to review the successful-login entries too. Attackers who get in may then use the valid account.

**Lab:** analysed an nginx-style `access.log`.
- Identified the attacker's **User-Agent**, source IP, and the time of the **successful login** after the brute-force attempts.

---

## 4. XML External Entity (XXE)

**What it is:** an attack on applications that parse XML. The attacker defines an **external entity** in the XML (via a `DOCTYPE`) that points to a local file or URL. A poorly configured parser then loads it.

**Possible vectors:** form fields that accept XML, uploaded XML files, APIs that accept XML (SOAP/REST), XML used in configuration.

**Impact:** information disclosure, **SSRF**, denial of service, and in some cases remote code execution.

**Prevention**
1. **Disable external entity processing** in the parser (the most effective step).
2. Validate and sanitize XML input.
3. Use secure, up-to-date parsers.
4. Whitelist allowed entities and DTDs.
5. Access controls to limit damage.
6. Secure coding practices.

> **Caveat:** the course mentions `libxml_disable_entity_loader()` in PHP. That function is **deprecated since PHP 8.0**, and newer libxml versions don't load external entities by default. Check the parser settings for your version.

**Detection:** search logs and requests for the keywords **`DOCTYPE`, `ELEMENT`, `ENTITY`** (and `SYSTEM`).

Payload types covered: basic XXE, blind XXE, and XXE using a PHP filter wrapper.

**Lab:** analysed an `access.log`.
- Identified the attacker's IP, the **parameter** carrying the XML, and which **file** the attacker tried to read.

---

## Key takeaways

- Each of these attacks leaves recognizable fingerprints in the request line: external URLs (open redirect), `../` (traversal), repeated logins (brute force), `DOCTYPE`/`ENTITY` (XXE).
- **Encoding** (URL, Unicode) is a common evasion technique, so detection should look at decoded values as well.
- For brute force, **failed attempts alone don't answer "did it work?"**. Check what came after.
- Prevention often reduces to: validate with an allow-list, apply least privilege, and add layered controls (WAF, rate limiting, MFA).

## Skills practised

Log analysis (`access.log`), identifying exploitation start time, attacker attribution (IP, User-Agent), parameter identification, detecting encoded payloads, recognizing successful logins after brute force.

---

*Previous: [Section 1: Detecting Web Attacks](01-detecting-web-attacks.md) | Next: [Section 3: Detecting Advanced Web Attacks](03-detecting-advanced-web-attacks.md)*
