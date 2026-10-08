# Section 8: JWT Attacks and Detection

> Part of my **Web Attack Detection and Analysis** course notes. See the [README](README.md) for all sections.

## Overview

This section covers **JSON Web Tokens (JWTs)** and how they're attacked, in particular **`kid` (Key ID) injection**, which can lead to authentication bypass, SQL injection, remote code execution and directory traversal. It focuses on how JWTs are structured, why the `kid` parameter is a weak point, what malicious tokens look like, and how a SOC detects and responds to these attacks.

| # | Topic |
|---|-------|
| 1 | Authentication and authorization |
| 2 | JSON Web Tokens (JWT) |
| 3 | The `kid` (Key ID) parameter |
| 4 | `kid` injection attacks |
| 5 | `kid` SQLi, RCE and directory traversal |
| 6 | SOC member approach |

---

## 1. Background: authentication vs authorization

Two related but distinct ideas underpin everything here:

- **Authentication** = *verifying who you are* (checking credentials (password), certificate, biometric, MFA). Success establishes a trusted identity.
- **Authorization** = *deciding what you're allowed to do* once authenticated (roles, permissions, least privilege).

JWTs are used for **both**: the token proves identity and carries the claims that drive authorization decisions. That's exactly why forging or tampering with a JWT is so damaging: break the token and you can impersonate a user **and** inherit their privileges.

---

## 2. JSON Web Tokens (JWT)

A **JWT** (RFC 7519) is a compact, self-contained way to transmit claims as a signed JSON object. It's **stateless**, the server doesn't need to store a session; it just verifies the token's signature.

A JWT has **three Base64URL-encoded parts joined by dots**: `header.payload.signature`.

| Part | Contains |
|---|---|
| **Header** | Token type and the signing algorithm (`alg`), e.g. `HS256`, `RS256` |
| **Payload** | The claims, e.g. `sub` (subject/user ID), `name`, `iat` (issued-at), plus custom claims |
| **Signature** | Header + payload signed with a secret key (HMAC) or private key (RSA/ECDSA), proves integrity and authenticity |

**Example token:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
Decoded header → `{"alg":"HS256","typ":"JWT"}`
Decoded payload → `{"sub":"1234567890","name":"John Doe","iat":1516239022}`

The recipient re-computes the signature with the key and compares, if it matches, the token wasn't tampered with. **The whole security model rests on the server trusting the right key.** That's what `kid` attacks target.

> HS256 (symmetric, one shared secret) is used above for simplicity. JWTs can also use asymmetric algorithms (RS256, ES256) where a **private** key signs and a **public** key verifies.

---

## 3. The `kid` (Key ID) parameter

`kid` is an **optional header parameter** that tells the server **which key** to use when verifying the signature, useful when an app rotates keys or holds several. On receiving a token, the server reads `kid` and fetches the matching key (from a database, a file, or a key store).

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "my_key_id"
}
```

**The risk:** `kid` is just a string the client sends, and the server often uses it to **build a database query or a file path**. If that value isn't validated, the attacker controls *which key* the server verifies against, and from there, SQL injection, command injection or path traversal.

> Note: `kid` belongs in the **header**, not the payload. One example in the course text shows `kid` inside the payload, that's not how it's used; the server reads `kid` from the header when selecting the verification key.

---

## 4. `kid` injection attacks

### `kid` SQL injection
If the app looks up the key in a database using `kid`:
```sql
SELECT key FROM keys WHERE key='key1'
```
An attacker sets `kid` to inject a `UNION SELECT`:
```json
{ "alg": "HS256", "typ": "JWT", "kid": "ABC' UNION SELECT 'XYZ" }
```
The query becomes:
```sql
SELECT key FROM keys WHERE key='ABC' UNION SELECT 'XYZ'
```
Now the key comes back as **`XYZ`**, a value the attacker chose, so they can **sign a forged token** with `XYZ` and the server will accept it.

### `kid` remote code execution (command injection)
If `kid` is passed into a shell/OS command, the attacker injects a command with a pipe or separator:
```json
{ "alg": "HS256", "typ": "JWT", "kid": "key1|/usr/bin/uname" }
```
The injected command runs with the application's privileges → **RCE**.

### `kid` directory traversal
If the key is read from the **filesystem** by `kid`, the attacker points it at a file whose contents they can predict:
```json
{ "alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null" }
```
`/dev/null` is empty, so the verification key becomes an **empty string**, the attacker signs a malicious token with an empty key and **bypasses signature verification entirely**. A static file (e.g. a CSS file) works the same way.

The same traversal can be aimed at sensitive files to **read** them:
```json
{ "alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd" }
```

### Other common JWT weaknesses (from the course)
- **Insecure key management**, a leaked signing secret lets anyone forge tokens.
- **Weak signature algorithms**, outdated/weak crypto makes forgery feasible.
- **Insufficient input validation** on `kid` or payload fields → the injections above.

> **Related attacks worth knowing (beyond the course text):** the **`alg: none`** attack (token says it's unsigned, and a lax server accepts it with no signature) and the **RS256 → HS256 key-confusion** attack (attacker switches the algorithm and signs with the public key as if it were an HMAC secret). Both are classic JWT forgery techniques a SOC analyst should recognize.

---

## 5. Detecting JWT `kid` injection (SOC approach)

The course lays out a SOC workflow: **threat-intel monitoring → log monitoring/analysis → security-event detection (SIEM) → real-time monitoring (WAF, IDS/IPS) → incident response → post-incident review.** The practical core for an analyst is spotting **malicious `kid` values** in JWTs.

### What a malicious `kid` looks like
Decode the JWT header (the first `.`separated segment) and inspect `kid` for:
- **SQL injection**: `UNION SELECT`, `' OR 1=1 --`, stray quotes.
- **Command injection**: `|`, `;`, `&`, `$()`, backticks, paths to binaries (`/usr/bin/...`).
- **Directory traversal**: `../`, `/dev/null`, `/etc/passwd`, absolute paths to static files.
- Anything that isn't a plain, expected key identifier.

### Pulling JWTs out of logs
```bash
# Find JWT-shaped strings (three base64url parts) in a log
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' access.log

# Decode a header segment to read alg / kid (Base64URL; pad if needed)
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d 2>/dev/null; echo
```

### What to alert on / correlate
- JWTs where the decoded `kid` contains SQL, shell or traversal characters.
- A sudden burst of requests with varied/malformed `kid` values from one source (fuzzing).
- `alg` set to `none`, or an unexpected algorithm switch for a given issuer.
- Correlate JWT anomalies with auth-server and app logs to confirm a bypass actually happened (e.g. a low-privilege user suddenly acting as admin).

---

## 6. Mitigation

- **Validate and sanitize the `kid` parameter**, treat it as untrusted input; **allowlist** it to known key identifiers rather than using it to build queries or paths.
- If `kid` selects a key file, **constrain it to a safe directory** and reject traversal sequences.
- **Never** interpolate `kid` directly into SQL (use parameterized queries) or into shell commands.
- **Secure key management**, protect signing secrets/private keys; rotate them; never expose them.
- **Use strong algorithms** and pin the expected `alg` server-side; reject `none` and unexpected algorithm switches.
- Use **well-maintained JWT libraries**, and enforce **expiration** and a **revocation** path.
- Regular **code review, security assessments and pen-testing** of the JWT handling.

---

## Key takeaways

- A JWT is `header.payload.signature`; its security depends entirely on the server verifying with the **right key**, which is what `kid` attacks subvert.
- **`kid` is attacker-controlled input.** If the server uses it to build a DB query or file path without validation, it opens **SQL injection, RCE and directory traversal**.
- The `/dev/null` (empty-key) traversal trick is especially dangerous, it makes **signature verification pass for a forged token**.
- Detection = **decode the JWT header and inspect `kid`** for SQL, shell or traversal patterns, then correlate with auth/app logs to confirm impact.
- `kid` is a **header** parameter (the course text places it in the payload in one example, that's incorrect).
- Fixes are standard injection hygiene: **allowlist/validate `kid`**, parameterized queries, safe path handling, strong key management, and pinning the algorithm.

## Skills practised

Understanding JWT structure and the auth/authz model, decoding Base64URL tokens, recognizing `kid`-based SQLi / command-injection / directory-traversal payloads, extracting and inspecting JWTs from logs, writing SIEM/WAF detection logic for anomalous `kid` values, and planning mitigation for token-based auth flaws.

---

*Previous: [Section 7: F5 BIG-IP iControl REST RCE Detection](07-detecting-f5-icontrol-rest-rce.md) | Next: [Section 9: SAML Vulnerabilities and Detection](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/bac9d053b210b708c2885940bd3268d2dd26a405/09-saml-vulnerabilities-and-detection.md)*
