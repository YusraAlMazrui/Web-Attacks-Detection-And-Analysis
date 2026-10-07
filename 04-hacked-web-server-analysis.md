# Section 4: Hacked Web Server Analysis

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](../README.md) for all sections.

## Overview

This section is about **post-attack analysis**: working out what happened on a web server after (or during) an attack. It covers how to read web server logs, how common attacks on servers, applications and programming languages show up in evidence, how to find web shells, and a full walkthrough of a compromised WordPress server.

## Contents

1. Introduction to Hacked Web Server Analysis
2. Log Analysis on Web Servers
3. Attacks on Web Servers
4. Attacks Against Web Applications
5. Vulnerabilities on Servers
6. Vulnerabilities in Programming Language
7. Discovering the Web Shell
8. Hacked Web Server Analysis Example

---

## 1. Introduction to Hacked Web Server Analysis

**Log recording** is the recording of events that happen on a server. Thanks to logs, undesired situations such as system errors and security risks can be analysed.

**Three steps to keep in mind during log analysis**
1. **Access** the logs.
2. Determine the **purpose** of the analysis (what question am I answering?).
3. **Filter** the records to extract the data that matches that purpose.

---

## 2. Log Analysis on Web Servers

- Requests made with the **POST** method may **not be logged by default**, and the **data sent in a POST body is not in the logs**.
- This can be compensated for with modules such as **mod_forensic** or **mod_security**.
- Otherwise, **network traffic** has to be examined to see POST data.

**Anatomy of an access log line** (combined format)

```
192.168.2.232 - - [20/Aug/2017:17:48:45 +0300] "POST /index.html HTTP/1.1" 200 3380 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0"
```

| Part | Meaning |
|---|---|
| `192.168.2.232` | client IP address |
| `[20/Aug/2017:17:48:45 +0300]` | timestamp (with timezone offset) |
| `"POST /index.html HTTP/1.1"` | method, resource, protocol |
| `200` | HTTP status code |
| `3380` | response size in bytes |
| `"-"` | referrer |
| `"Mozilla/5.0 ..."` | User-Agent |

### Lab 1: Log analysis on nginx and Apache2

**Environment:** a Linux VM with logs in `/var/log/nginx/` (`access.log`, `access.log.1`, `access.log.2.gz`, `error.log`, ...) and `/var/log/apache2/access.log.1`.

**Tasks**
- Find the **year** of a request to a specific path on the Nginx server.

![Images/04-Lab1-Q1.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/2b05e0c3975df05e2e0296325896fda658c526f5/Images/04-Lab1-Q1.png)

- Find the **IP address** that tried to read `/etc/passwd` on the Nginx server.

![Images/04-Lab1-Q2.png]

- Find the **IP address** that attempted a **SQL injection** on the Apache2 server.

![Images/04-Lab1-Q3.png]

**How I approached it**
- Opened the nginx log in a text editor and searched for the requested path and the `/etc/passwd` string.
- On Apache2 I filtered the log from the terminal with `grep` for SQL keywords (for example `select`).
- Observations worth noting:
  - The nginx entries for the suspicious requests returned **502** responses, so those requests did not return file contents.
  - The Apache SQLi request returned **200** with the same response size as the normal homepage request, a hint that the page output did not change (a hint, not proof).
  - Rotated logs ending in `.gz` are compressed. They can be read with `zcat` / `zgrep` instead of `cat` / `grep`.

---

## 3. Attacks on Web Servers

### Tomcat Application Server
- **Cause:** the server uses **mod_jk**, and the application server decodes URLs sent by the client.
- **Idea:** abuse **directory traversal** by encoding `..` **twice**: `..` → `%2e` → `%252e`.
- Requesting a path built from `%252e%252e/` segments leads to the **Tomcat Manager** login prompt. With **default credentials** the admin panel is reachable, and a web shell can then be deployed through it.
- **Log evidence:** requests to `manager/html` with a `200` response, and requests from the suspicious IP that succeeded:
  - `cat access.log | grep manager/html | grep 200`
  - `cat access.log | grep <attacker IP> | grep 200`
- **Protection:** update **mod_jk**.

### GlassFish (CVE-2011-0807)
- A **remote code execution** vulnerability. The admin panel is reached through authentication bypass or default credentials, and remote access is gained by **uploading a malicious file** (in the demo, a Metasploit module against Sun GlassFish Enterprise Server 2.1).
- **Recon:** the attacker first scans with **nmap** to see open ports and services (the scan showed the GlassFish service on a non-standard HTTP port).
- **Log evidence:** `netstat -an` shows the server communicating with an **unrecognized address on port 4444** (Metasploit's default listener port), followed by a lot of TCP traffic on that port after the GET requests. The course notes this traffic was encrypted, so the attacker's commands can't be read from the network capture.
- **Protection:** don't leave default usernames/passwords; install updates.

### JBoss
- **Remote code execution** in JBoss AS versions 3, 4, 5 and 6 (demo target: JBoss 6 on Ubuntu 14.04, using a public exploit from Exploit-DB, ID 36575).
- **Log evidence:** HTTP requests containing parameters or commands such as **`id`, `whoami`, `uname -a`**, sent to a path like `/jbossass/jbossass.jsp`. The file that receives the requests can be located on disk:
  - `find /opt/jboss-6.0.0.Final/ -type f -name "jbossass.jsp"`
- **Protection:** upgrade to JBoss EAP 7; don't run the software as a privileged user.

> **Note:** the course text writes `jbossass.jps` in one place; the actual file is `.jsp` (as in the `find` command). Likewise `/examples/jps/` in the Tomcat example should read `/examples/jsp/`.

### Lab 2: Apache2 log analysis (multiple attackers)

**Environment:** `/var/log/apache2/access.log.1` on a Linux VM.

**Tasks**
- For an attacker IP given in the question, find **on which day of the month** its XSS attempts happened.
- Identify **the name of the attack** a second IP attempted.
- Find the **User-Agent** of a POST request at a specific timestamp.

**How I approached it**
- Filtered the log by IP: `sudo cat /var/log/apache2/access.log.1 | grep <IP>`
- Filtered by exact timestamp: `... | grep 27/Sep/2022:10:56:39` style filters.
- Observations:
  - One IP tried **several attack types in sequence** (SQLi, UNION-based SQLi, then XSS), which looks like manual probing.
  - The second IP's requests were **XSS filter-evasion payloads** (event handlers, `javascript:` URIs, CSS `expression(...)`, unusual escapes), the kind produced by fuzzing lists.
  - A POST request's **body isn't visible** in the access log (see lesson 2), but its **User-Agent** is, and a non-browser User-Agent is a useful hint that a tool, not a person with a browser, sent it.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![Filtering the log by attacker IP](images/attacks-lab-01-grep-by-ip.png)
![SQLi and XSS attempts in the log](images/attacks-lab-02-sqli-xss-requests.png)
![Filtering by timestamp](images/attacks-lab-03-grep-timestamp.png)
-->

---

## 4. Attacks Against Web Applications

### Injection (SQL injection)
Manipulating the query sent to the server. During detection the goal is to **trigger error messages** that reveal database details.

| Purpose | Technique shown in the course |
|---|---|
| First test | a single quote `'` |
| Find number of columns | `ORDER BY n--` |
| Find column data types | `UNION SELECT 1,null,null--` |
| Logic-based detection | `id=6`, `id=7-1`, `id=6 OR 1=1`, `id=6 OR 11-5=6` |
| Time-based detection | `SLEEP(25)`, `BENCHMARK(...)` payloads |

A demo showed a `UNION SELECT null, version()` payload returning the database version in the page.

**Detection:** the most-used characters and words in SQLi are `'`, `--`, `union`, `select`, `from`, `or`, `@`, `version`, `char`, `varchar`, `exec`. In URLs the quote appears as `%27`:

```
cat access.log | grep -E "%27|--|union|select|from|or|@|version|char|varchar|exec"
```

> **Tip:** the course command is missing its closing quote (fixed above). `from` and `or` are very common substrings, so expect **false positives**; add `-i` for case-insensitive matching and narrow the results afterwards.

**Protection:** prepared statements, validating and filtering input, restricting user privileges.

### Broken Authentication and Session Management
- Demo: after logging in as `user1`, the **cookie value was simply the username**. Changing the cookie to `admin` switched the session to the admin user **without a password**.
- **Log evidence:** the access log showed nothing unusual. The abnormality (cookie changing from `user=user1` to `user=admin` from the same IP) was only visible in the **network traffic** (Wireshark), because cookies aren't in the access log.
- **Protection:** strong authentication and session management; prevent XSS so cookies can't be stolen.

### Cross-Site Scripting (XSS)
- Found in input fields (search boxes, messages, guestbooks) using **GET or POST**. Classic test payload: `"><script>alert(1)</script>`. Event handlers (`onclick`, `onload`, `onmouseover`, ...) are used when `<script>` is filtered.
- **Log evidence:** POST-based XSS only shows the request to the page (the body isn't logged). GET-based XSS is found by filtering for `<`, `>` (URL-encoded as `%3C`, `%3E`) and words like `alert`, `script`, `src`, `cookie`, `onerror`, `document`:

```
cat access.log | grep -E "%3C|%3E|alert|script|src|cookie|onerror|document"
```

- **Protection:** verify that input matches the expected type; use an **allow-list**, not a block-list.

### Security Misconfiguration
Caused by incorrect, weak or **default** settings. Example: the automatically created `admin` account keeps its default password, so an attacker can log in with default credentials.
**Protection:** change default configurations, keep software updated, disable unused services and ports.

### Cross-Site Request Forgery (CSRF)
Makes a victim perform an action against their will. Demo: a fake page with a hidden form and a single "Click" button that submits a **password-change request** to the target application.
- **Log evidence:** a GET request to the CSRF page with `password_new=...&password_conf=...&Change=Click`. This shows the victim's browser changed the password.
- **Protection:** use the framework's CSRF protections; use **tokens** and sessions.

> A password change sent with **GET** puts the new password in the URL (and so in the logs). State-changing actions should use POST plus a CSRF token.

---

## 5. Vulnerabilities on Servers

### Apache: Shellshock (CVE-2014-6271)
- Affects Apache setups using **mod_cgi / mod_cgid** with vulnerable **Bash** (versions 1.14 to 4.3).
- Exploited by putting a malicious value in the **`HTTP_USER_AGENT`** environment variable that is handed to CGI scripts.
- **Log evidence:** a **HEAD** request to `/cgi-bin/status` where the **User-Agent starts with `() { :;};`** followed by a shell command instead of browser information. In the demo, the response headers contained the contents of `/etc/passwd`.
- **Protection:** upgrade Bash (`sudo apt-get update && sudo apt-get install --only-upgrade bash`).

### Nginx
Per the vulnerability statistics shown in the course, there was **no critical Nginx vulnerability between 2010 and 2017** (mostly denial of service, overflow and information-related issues). That reflects the data at the time of the course, so check current advisories.

### IIS
**MS15-034** (HTTP.sys)
- Remote code execution / denial of service through a specially crafted HTTP request. Affects IIS using **HTTP.sys** on Windows 7, 8, 8.1, Server 2008 R2, 2012 and 2012 R2.
- Recon with **nmap** showed IIS 7.5. The test request used an abnormal **`Range` header** with a huge byte range, and the demo target crashed with a blue screen.
- Detection idea: unusually large or malformed `Range` headers in requests.

**CVE-2017-7269**
- A **buffer overflow** in the `ScStoragePathFromUrl` function of the **WebDAV** service in **IIS 6.0** (Windows Server 2003 R2). The demo used a Metasploit module and opened a Meterpreter session.

---

## 6. Vulnerabilities in Programming Language

### PHP: CVE-2016-10033 (PHPMailer)
- Remote code execution because PHP's `mail()` function, used by the **PHPMailer** library, doesn't fully check the extra-parameters feature.
- The demo exploit created a **backdoor file** (`backdoor.php`) and ran commands through it as the web server user (`www-data`).
- **Log evidence:** requests to `/backdoor.php?cmd=...` where the `cmd` value is **Base64-encoded** (decoding the values reveals commands like `whoami` and `id`).
- **Protection:** affects versions up to 5.2.18, so update.

### Java: null-byte session injection
- Demo against an application built on the **Play! Framework (1.2.5)**. The registration request had `%00%00admin%3a1%00` appended to the username. Because of the null bytes, the server **misinterpreted the session data** and treated the new user as an admin.
- **Log evidence:** the registration looked normal in the logs, but the **cookie values** (`PLAY_SESSION`) in the network capture contained `%00` and `admin:1`.
- **Protection:** fixed in updated versions, so update.

---

## 7. Discovering the Web Shell

A **web shell** is a script placed on a server that gives the person who installed it control of the server. Well-known examples: **c99** and **r57**.

**What a simple PHP shell looks like:** it takes a `cmd` request parameter and passes it to a function such as `system()`, which is how it runs OS commands.

**Finding shells on the server (grep)**
- Search for dangerous functions in the web root:
  - `grep -Rn "system *(" /var/www`
- Shells often use more than `system`. The course's broader search:

```
grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|php_uname|eval) *\(" /var/www
```

> **Note:** these functions also appear in legitimate code, so results need manual review. The course also lists `edoced_46esab`, which is `base64_decode` **written backwards**, a trick used to dodge simple string searches.

**Shell hiding methods**
| Method | How it works | What to search for |
|---|---|---|
| **Remote summoning** | The shell isn't on the server. The code is pulled from another address (e.g. a paste site) and run | `curl` / remote fetch followed by `eval` |
| **Encrypted code** | Shell code is encrypted to bypass firewalls and decrypted at runtime | `eval(` with `openssl_decrypt` / decoding functions |
| **Hiding in a picture** | Malicious code is placed in an image's **EXIF** metadata (e.g. with `exiftool`) and run by PHP when it reads that metadata | `exif_read_data()` and `preg_replace()` (with the `/e` modifier) in PHP files; inspect image metadata |

### Lab 3: Find the web shell

**Environment:** a Linux VM with a web root at `/var/www/html/` (containing a `files` folder).

**Tasks**
- Find the **filename** of a PHP shell on the server.
- Decide whether a web shell is **hidden inside an image** on the server (Y/N).

**How I approached it**
- Ran the `grep -Rn "system *(" /var/www` search to find files calling `system()` and reviewed the matching file.
- For the image question, the course's method is to check images for abnormal EXIF fields and search the code for `exif_read_data` / `preg_replace`.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![grep search for system()](images/webshell-lab-01-grep-system.png)
![Web root folder](images/webshell-lab-02-web-root.png)
![Checking images for hidden code](images/webshell-lab-03-image-check.png)
-->

---

## 8. Hacked Web Server Analysis Example (WordPress)

A **post-attack analysis** of a fully compromised WordPress server. The investigation followed the attacker step by step.

| Step | What was done | Evidence |
|---|---|---|
| 1. Admin panel access? | `cat access.log \| grep POST \| grep wp-login` | Many POST requests to `wp-login.php` from the **same IP** |
| 2. What was sent? | **Wireshark** filter: `ip.src == <attacker> && ip.dst == <server> && http.request.method == POST` | Repeated login attempts with `log` / `pwd` form fields, confirming a **brute-force attack** on `wp-login` |
| 3. What did they do in the admin panel? | Checked `error.log` | An attempt to use `fsockopen()` and a request to a non-existent path, suggesting the attacker had changed the **404 error page** |
| 4. What did the 404 page contain? | Looked at the page's changed code | Code that **opens a connection to the attacker's own address on port 1234** (a reverse shell) |
| 5. What commands were run? | Examined commands run by the **`www-data`** user (shell history) | `uname -a`, `id`, browsing to the WordPress folder, `cat wp-config.php`, `history`, then `su root` |
| 6. How did they become root? | Reviewed `wp-config.php` | The **database password was the same as the root password**, so the attacker gained root and took over the server |

**Extra observation from the log screenshot:** WordPress usually returns **200** for a failed login and a **302 redirect** after a successful one. In the output, a long run of 200s from one IP is followed by 302 responses, which fits a brute force that eventually succeeded. Always confirm with other evidence.

**Attack chain:** brute force on `wp-login` → admin access → edited 404 page for a reverse shell → `www-data` shell → read `wp-config.php` → **password reuse** → root.

**Lessons**
- Don't use weak or default admin credentials (`admin`/`admin`); add login rate limiting and MFA.
- Don't let admins edit theme/page files from the dashboard if it isn't needed.
- **Never reuse passwords** between services (database vs OS).
- Combine **access logs, error logs and network captures**; each shows different parts of the attack.

---

## Key takeaways

- A hacked-server investigation uses **three evidence sources**: access/error logs, network traffic, and the file system.
- **POST data and cookies are not in access logs**, so network captures (Wireshark) fill the gap.
- Many of these attacks leave a specific log fingerprint: `%252e` double encoding, `manager/html`, port 4444 connections, a User-Agent starting with `() { :;};`, `%00` in cookies, `/backdoor.php?cmd=`.
- Default credentials, outdated software and **password reuse** appear again and again as the root cause.
- Web shells can be hidden (remote fetch, encryption, image metadata), so searching for just `system(` isn't enough.
- Keep a list of **grep patterns** per attack, but treat results as leads: patterns like `from|or` cause many false positives.

## Skills practised

Web server log analysis (nginx, Apache2), filtering with `grep` / `zgrep`, timestamp and IP-based triage, recognizing SQLi/XSS/CSRF in logs, identifying server-level exploitation evidence, web shell hunting (grep, EXIF), Wireshark display filters, post-compromise timeline reconstruction.

---

*Previous: [Section 3: Detecting Advanced Web Attacks](../03-detecting-advanced-web-attacks/README.md) | Back to [README](../README.md)*
