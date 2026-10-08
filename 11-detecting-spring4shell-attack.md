# Section 11: Detecting Spring4Shell Attack

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section covers **Spring4Shell (CVE-2022-22965)**, a critical **remote code execution** vulnerability in **Spring Framework Core**. It focuses on how the attack abuses Spring's data binding to drop a JSP web shell, which applications are actually vulnerable, how to recognize it in web server logs, and how to remediate it.

| # | Topic |
|---|-------|
| 1 | Introduction to Spring4Shell |
| 2 | Vulnerability details and attack vectors |
| 3 | Detection and response |
| 4 | Mitigation and remediation |
| 5 | Check if you're vulnerable |
| 6 | SOC analyst perspective (detection) |

---

## 1. What is Spring4Shell?

- **Spring4Shell** (disclosed **March 29–30, 2022**, **CVE-2022-22965**, **CVSS 9.8**) is a critical RCE in **Spring Framework Core** — the widely used Java web framework.
- It was **initially confused** with **CVE-2022-22963** (a SpEL injection in **Spring Cloud Function**). They're separate: Spring4Shell is in **Spring Core** (`spring-webmvc` / `spring-webflux`).
- A specially crafted HTTP request bypasses built-in protections and leads to **remote code execution** — with active exploitation and public PoCs seen in the wild.

**Impact:** arbitrary command execution with the application's privileges → unauthorized access, data breaches, full system compromise.

---

## 2. How the attack works

Spring4Shell abuses Spring's **data binding** — the feature that maps request parameters onto object properties. On a vulnerable setup, an attacker can reach **`class.module.classLoader…`** through that binding and **reconfigure Tomcat's logging valve (AccessLogValve)** to write a file of their choice.

**Attack flow**
1. The attacker sends a **POST** with parameters that set `class.module.classLoader.resources.context.parent.pipeline.first.*` properties.
2. Those properties point Tomcat's access-log pipeline at a new file: a **`.jsp`** in the web root (e.g. `tomcatwar.jsp` under `webapps/ROOT`), with the log "pattern" set to attacker Java code.
3. Tomcat writes that **JSP web shell** to disk.
4. The attacker requests the web shell (e.g. `GET /tomcatwar.jsp?cmd=…`) and **runs commands** via `Runtime.getRuntime().exec(...)`.

> **Precision note:** the course describes this as generic "command injection." More precisely it's a **data-binding / class-loader manipulation** flaw — the request parameters don't run a command directly; they **reconfigure Tomcat to drop a web shell**, which then executes commands. The detection keyword the course gives (`class.module.classLoader.resources`) is exactly right.

---

## 3. Check if you're vulnerable

Per the Spring advisory, an app is exposed to Spring4Shell only when **all** of these hold:

1. **JDK 9 or higher.**
2. **Apache Tomcat** as the servlet container.
3. **Traditional WAR packaging** (not a Spring Boot executable JAR — Boot apps are generally *not* vulnerable).
4. A dependency on **`spring-webmvc`** or **`spring-webflux`**.
5. A vulnerable **Spring Framework version**: **5.3.0–5.3.17**, **5.2.0–5.2.19**, and older unsupported releases.

> These are the exact conditions my **[Log4Shell notes (Section 5)](05-detecting-log4shell-attack.md)** flagged as belonging to Spring4Shell rather than Log4j — this is where they actually apply.

---

## 4. Detecting Spring4Shell (SOC analyst perspective)

### Key indicator
The payload almost always contains the string **`class.module.classLoader.resources`** (and often **`getRuntime().exec`**). That keyword in a **POST** request body is the headline signal.

### The catch: it's in the request *body*
Spring4Shell payloads ride in **POST data**, which default nginx logs don't record. To see them, enable **request-body logging**:
```nginx
http {
    ...
    log_format postdata '$request_body';
}
```
(Apply the `postdata` format to the relevant `access_log` directive.)

### Pattern matching
Once the body is logged, search for the class-loader pattern:
```
.*class\.module\.classLoader\.resources.*
```
```bash
grep -iE 'class\.module\.classLoader\.resources|getRuntime\(\)\.exec' access.log
```

### Also watch for
- Unusual URLs / parameters, encoded keywords, odd URL structures.
- **Abnormal request behaviour**: repeated POSTs to one endpoint, oversized payloads, bursts from one IP.
- A follow-up **request to a newly created `.jsp`** (e.g. `tomcatwar.jsp`) — if that returns **`200`**, the web shell likely landed.

> A log match is the **attempt**. Confirm success by checking whether the dropped JSP exists / responds and whether commands ran.

---

## 5. Mitigation and remediation

- **Upgrade Spring Framework** to **≥ 5.3.18** or **≥ 5.2.20**.
  - Maven: `<spring-framework.version>5.3.18</spring-framework.version>`
  - Gradle: `ext['spring-framework.version'] = '5.3.18'`
- If you can't upgrade immediately, apply **Spring's official workaround** (restricting disallowed data-binding fields).
- **Secure input handling** — validate/sanitize and bind only expected fields.
- **Secure configuration** — disable unneeded features/modules.
- **Security auditing, logging/monitoring, IDS**, and regular **penetration testing**.

---

## 6. Lab: Spring4Shell log analysis

**Environment:** a Linux VM with one nginx `access.log` at `/root/Desktop/access.log`. The attacker sent Spring4Shell payloads (the `class.module.classLoader…` pattern) to a `/spring-form/greeting` endpoint to drop a `tomcatwar.jsp` web shell.

**Tasks**

- What was the **attacker IP address**?

![Images/11-Lab-Attacker-IP.png](Images/11-Lab-Attacker-IP.png)

- What is the **start date and time** of the attack? *(Day/Month/Year:Hour:Minute:Second)*

![Images/11-Lab-Attack-Time.png](Images/11-Lab-Attack-Time.png)

- What is the **attacker's user agent**?

![Images/11-Lab-User-Agent.png](Images/11-Lab-User-Agent.png)

**Answers**

| Question | Answer |
|---|---|
| Attacker IP | `68.39.225.163` |
| Attack start | `23/Apr/2023:05:32:13` |
| User agent | `python-requests/2.25.1` |

**How I approached it**
- Searched the log for `class.module.classLoader.resources` to surface the Spring4Shell payloads.
- Took the **source IP** and the **timestamp** of the first matching POST, and read the **User-Agent** field.
- The `python-requests/2.25.1` user agent confirms **automated/scripted** exploitation, not a browser.

**Observations**
- The payload set the Tomcat pipeline's **`suffix=.jsp`**, **`prefix=tomcatwar`**, **`directory=webapps/ROOT`** and a malicious **`pattern=`** — the textbook Spring4Shell web-shell drop.
- Watch the follow-up requests: a hit on **`/tomcatwar.jsp`** returning **`200`** indicates the web shell was successfully written and reachable (vs the earlier `/spring-form/tomcatwar.jsp` 404 before it was placed).

---

## Key takeaways

- Spring4Shell (**CVE-2022-22965**) is a **data-binding RCE** in Spring Core that abuses **`class.module.classLoader…`** to make **Tomcat write a JSP web shell** — it is *not* the same as the Spring Cloud bug **CVE-2022-22963**.
- Only a specific setup is vulnerable: **JDK 9+, Tomcat, WAR packaging, `spring-webmvc`/`webflux`, Spring 5.3.0–5.3.17 / 5.2.0–5.2.19** — the very conditions my Log4Shell notes flagged as actually being Spring4Shell.
- The detection signature is **`class.module.classLoader.resources`** in **POST bodies** — which means you must **enable request-body logging** to catch it.
- Confirm success by checking for a **newly dropped `.jsp`** returning `200`.
- The fix is **upgrading to Spring 5.3.18 / 5.2.20**.

## Skills practised

Understanding Spring data-binding RCE and the Tomcat web-shell mechanism, distinguishing Spring4Shell from the related Spring Cloud CVE, recognizing the `class.module.classLoader.resources` signature in POST payloads, configuring request-body logging and regex detection, reconstructing the attack from logs (IP, time, user agent), judging attempt vs success via the dropped JSP, and remediation planning.

---

*Previous: [Section 10: Detecting Insecure Deserialization](10-detecting-insecure-deserialization.md) | Back to [README](README.md)*
