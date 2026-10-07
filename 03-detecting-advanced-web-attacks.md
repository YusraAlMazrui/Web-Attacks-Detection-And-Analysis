# Section 3: Detecting Advanced Web Attacks

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section moves to more advanced, injection-style attacks that target template engines, expression interpreters, HTTP headers, server-side requests and NoSQL databases.

| # | Topic | Lab done |
|---|-------|----------|
| 1 | Server-Side Template Injection (SSTI) | Yes |
| 2 | Expression Language Injection (ELI) | Yes |
| 3 | HTTP Header Injection | Yes |
| 4 | Server-Side Request Forgery (SSRF) | Yes |
| 5 | NoSQL Injection | Yes |

The labs use one log file per attack: `SSTI.log`, `ELI.log`, `HTTP.log`, `SSRF.log`, `NoSQL.log`.

---

## 1. Server-Side Template Injection (SSTI)

**What it is:** the attacker injects code into a template that the **server-side template engine** then evaluates. Unlike SQLi or XSS, the target is the template engine itself.

**Template engines mentioned:** Mustache, Handlebars, Twig, Jinja2.

**Possible vectors:** query-string parameters, form data, cookies, and other data sources (APIs, databases) that reach the template engine unsanitized.

**Impact:** data disclosure, code execution (possible server takeover), malware injection, DoS, reputation damage.

**Prevention**
- Never build templates from raw user input; pass user data as template *variables*.
- Validate input against a strict allow-list.
- Use context-specific escaping and sanitize input.
- Use a secure/sandboxed template engine configuration, and keep everything patched.

> **Caveat:** the course also lists a Content Security Policy (CSP). CSP limits the impact of XSS in the browser, but it does **not** stop server-side template injection.

**Detection:** look for **test payloads** that probe for evaluation, such as `{{7*7}}`, `{{3*3}}`, `${6*6}`, `<%= 3 * 3 %>`, `@(6+5)`, `#{3*3}`. If the response contains the computed value, the template engine is evaluating input.

**Reading the course's example log**
- A `GET` to `/greet` with `{{7*7}}` and a `200` response: payload reached the app and the request succeeded.
- A `POST` to `/search` with no visible payload: the payload could be in the body, which an access log doesn't show.
- A `GET` to `/admin` with `{{1+2}}` and a `500`: an error during evaluation. The course reads this as a possible defence; it's equally possible the engine tried to evaluate the input, so it deserves follow-up rather than being written off.

**Lab:** analysed `SSTI.log`.
- Identified the **affected parameter**, the **file** the attacker tried to read, and the attacker's IP.

---

## 2. Expression Language Injection (ELI)

**What it is:** injecting malicious expressions into an application that uses an expression language (e.g. JSP EL, JSF, Spring). The interpreter evaluates the attacker's expression.

**Possible vectors:** user input fields, URLs, hidden fields, cookies, HTTP headers.

**Impact:** data theft, account takeover (session hijack / auth bypass), server compromise, application disruption, chaining with other vulnerabilities (SQLi, RCE, XSS).

**Detection:** look for expression syntax like `${...}` and for Java-related calls inside parameters. The course lists payload families that:
- execute commands through the Java `Runtime` class (directly or via reflection with `Class.forName`),
- read or write **session** and **request** attributes (`sessionScope`, `request.setAttribute`, ...),
- reveal application details such as the context path.

**Lab:** analysed `ELI.log`.
- Identified the attacker's IP, the **command** they tried to run in the shell context, and **how many payloads** were tried against the vulnerable parameter.
- Skill used: URL-decoding long payloads to read what was really being executed, and counting requests to one parameter.

---

## 3. HTTP Header Injection

**What it is:** injecting content into HTTP headers. The course first recapped header categories: **request** (User-Agent, Host, Accept, Cookie), **response** (Content-Type, Content-Length, Server, Set-Cookie), **general** (Cache-Control, Connection, Date) and **entity** (Content-Encoding, Content-Language, Content-Disposition).

**Techniques**
1. **CRLF injection:** inserting carriage-return/line-feed characters (`%0D%0A`) to add or alter headers.
2. **Response splitting:** using CRLF to make the server produce multiple responses (cache poisoning, information leakage).
3. **Content spoofing:** manipulating `Content-Type` / `Content-Disposition` so the browser handles content differently than intended.

**Payload patterns covered:** extra headers via `\r\n`, modifying `Referer` with `%0D%0A`, cache poisoning through a fake second response, XSS inside a header (e.g. User-Agent), cookie manipulation.

**Detection**
- Network traffic analysis (IDS): unexpected line breaks or unusual characters in headers.
- Log analysis: unusually long headers, special characters, malicious content.
- **SIEM** correlation rules.
- **Regex** matching for known payloads and `%0D%0A` patterns.
- Signature-based detection using threat intel.
- Real-time alerts (header length limits, forbidden characters).

**Lab:** analysed `HTTP.log`.
- Identified the attacker's IP, the date the attack started, and what vulnerability the **final payload** would trigger if successful.
- Skill used: reading a malicious payload in a header (a script injected into a field) and classifying the resulting vulnerability.

---

## 4. Server-Side Request Forgery (SSRF)

**What it is:** the attacker controls a URL or parameter in a request that the **server** makes to internal or external systems, so the server can be used to reach resources the attacker can't.

**Exploitation techniques**
1. **URL manipulation:** change the target URL/domain/scheme.
2. **IP address abuse:** use IPs (often internal ones) instead of domain names.
3. **Protocol abuse:** `file://`, FTP, SMB, SMTP, not only HTTP.
4. **Port scanning and service enumeration** of internal networks.
5. **SSRF chaining:** pivot from one vulnerable system to another.
6. **Request smuggling** combined with SSRF.

**Prevention (from the course):** allow-list trusted domains, parse the URL to extract the domain, check it against the list, and reject anything else with `403 Forbidden`.

**Cloud SSRF (AWS metadata service)**
The link-local address `169.254.169.254` serves instance metadata. SSRF against it can expose:
- IMDS version details,
- **user data** (scripts/config that may contain secrets),
- **temporary IAM role credentials** under `.../iam/security-credentials/<role-name>`,
- path traversal inside the metadata tree and endpoint-override abuse.

Stolen credentials can then be used against AWS services.

**Detection with regex (ideas from the course)**
- `file://` URLs
- `http(s)/ftp://` URLs inside parameters
- URLs containing raw IP addresses
- URLs without a protocol prefix
- Any request referencing `169.254.169.254`

Tune these patterns to the environment.

**Lab:** analysed `SSRF.log`.
- Identified the attacker's IP, the payload used to reach the **AWS metadata** endpoint, and when the attack started.

---

## 5. NoSQL Injection

**Background:** NoSQL databases use flexible schemas, scale horizontally and come in four models: key-value (Redis, Riak), document (MongoDB, CouchDB), column-family (Cassandra, HBase) and graph (Neo4j, Amazon Neptune).

**NoSQLi vs SQLi**

| | SQL injection | NoSQL injection |
|---|---|---|
| Target | SQL (relational) databases | NoSQL databases |
| Data model | fixed schema | flexible (varies by database) |
| Query language | SQL syntax | database-specific syntax and operators |
| Technique | append SQL, comment characters | inject operators or alter query structure |
| Impact | data access/modification, admin actions | data access/manipulation, privilege escalation, DoS, full compromise |

**Detection (indicators in `access.log`)**
- **Unusual query structures** and operators/logical conditions.
- **Suspicious characters:** `'`, `"`, `$`, `&` and operators such as `$gt`, `$ne`.
- **Unexpected data flow:** user input concatenated into queries.
- **Abnormal input length:** very long or very short values.
- **Error responses** from malformed queries.
- **Repeated or unusual requests** to the same parameters/endpoints.
- **Unexpected query results** (missing or unusual data).
- **Outliers:** high request volume, excessive wildcards, unusual HTTP methods or User-Agents.

**Lab:** analysed `NoSQL.log`.
- Identified the attacker's IP, when the attack began, and how many payloads were sent to the vulnerable parameter.
- Skill used: filtering log lines by parameter and counting payload attempts.

---

## Key takeaways

- Advanced attacks often start with **harmless-looking probes** (`{{7*7}}`, `${6*6}`) to test whether input gets evaluated. Spotting the probe catches the attack early.
- **Encoded payloads** are the norm, so decode URLs before judging.
- Access logs have limits (e.g. POST bodies aren't shown), so absence of a payload doesn't mean absence of an attack.
- Counting payloads against one parameter is a quick way to see persistence and automation.
- Cloud environments add new SSRF targets such as the metadata service.

## Skills practised

Reading and URL-decoding complex payloads, identifying probe payloads, attacker attribution, timeline reconstruction, counting payload attempts, mapping a payload to the vulnerability it triggers, building regex detections.

---

*Previous: [Section 2](02-detecting-web-attacks-2.md)*
