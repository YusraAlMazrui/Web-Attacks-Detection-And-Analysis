# Web Attack Detection and Analysis: Course Notes

My notes and lab write-ups from the **Web Attack Detection and Analysis** course. The focus is on the defender's side: recognizing web attacks in logs and HTTP requests, judging whether they succeeded, and knowing how to prevent them.

## Contents

| Section | Topics |
|---------|--------|
| [1. Detecting Web Attacks](01-detecting-web-attacks/README.md) | SQL Injection, XSS, Command Injection, IDOR, LFI & RFI | 
| [2. Detecting Web Attacks - 2](02-detecting-web-attacks-2/README.md) | Open Redirection, Directory Traversal, Brute Force, XXE | 
| [3. Detecting Advanced Web Attacks](03-detecting-advanced-web-attacks/README.md) | SSTI, Expression Language Injection, HTTP Header Injection, SSRF, NoSQL Injection | 

## How each file is organized

For every attack: **what it is**, **how it works**, **impact**, **prevention**, **detection indicators**, and the **lab** I completed (environment, what I had to find, and the skills used).

## Approach used across the labs

Each lab gave a log file to investigate. The recurring questions were:

1. When did the exploitation phase start?
2. Which IP did the attack come from?
3. Which parameter or file was targeted?
4. Was it automated, and what type of attack was it?
5. Was it successful?

The main evidence: **User-Agent**, **request frequency**, **payload content** (decoded), and **response size / status code**.

## Skills

Log analysis, attack classification, attacker attribution, timeline reconstruction, payload decoding, regex-based detection, success/failure assessment.

## Note

Labs were done in a provided training environment against intentionally vulnerable targets and sample logs. These notes are for learning and defensive purposes only.
