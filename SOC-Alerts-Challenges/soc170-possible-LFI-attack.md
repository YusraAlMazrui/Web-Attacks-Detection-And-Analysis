# 120 - SOC Lab: SOC170 - Passwd Found in Requested URL - Possible LFI Attack

> Sub-file of [Section 1: Detecting Web Attacks](README.md). Platform: **LetsDefend** (practice alert, SOC analyst role).

## Summary

| | |
|---|---|
| Alert | SOC170 - Passwd Found in Requested URL - Possible LFI Attack |
| Severity | High |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |
| Source IP | 106.55.45.162 (external) |
| Target | WebServer1006 (172.16.17.13) |
| Request | `GET https://172.16.17.13/?file=../../../../etc/passwd` |
| Alert trigger | URL contains `passwd` |
| Device action | Allowed |
| **Verdict** | **True positive, attack unsuccessful** |

---

## 1. Review the alert

Before investigating, I read the alert details, since a lot can already be learned from them:

- **Source IP address** of the request
- **Target IP address** and **hostname** of the device being targeted
- The **URL** that triggered the alert
- Other context: HTTP method (GET), User-Agent, and what the device did with the request (*Allowed*)

The requested URL passes `../../../../etc/passwd` in a `file` parameter. This is the classic LFI pattern covered in [Section 1](README.md#5-local--remote-file-inclusion-lfi--rfi): `../` sequences to climb out of the web directory, then a sensitive system file.

![images/SOC170-Case-Details.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/67e2eda88382f28c65b2688963492b6de883e6b8/Images/SOC170-Case-Details.png)


## 2. Start the playbook

I opened the alert with the `>>` button and created the case (ticket) to begin the investigation. Playbooks differ per organization; this lab uses the LetsDefend playbook.

![Images/SOC170-Ticket-Created.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/1a136f2342386e8f2e6d241f20e7c2ed95c149c7/Images/SOC170-Ticket-Created.png) 

## 3. Is the traffic from inside or outside the network?

Playbook step 1: determine whether the source is internal or external.

- In **Endpoint Security**, I checked the list of internal hosts (you can also search by IP in the search bar).

  ![images/soc170-endpoint-01-endpoint-search.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/6fc0f3b6d8b5a3e133bfabf9f9c810e8050f0497/Images/SOC170-endpoint-search.png)
  
- The source IP returned **no matches**, so it isn't part of the internal network. It comes from an **external source (the Internet)**.

![(Images/SOC170-106.55.45.162-NOTFOUND.png)
](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/c04d12ec35929d3872154cbb311b07a812f3b2ae/Images/SOC170-106.55.45.162-NOTFOUND.png)

## 4. Collect data on the IP (reputation)

I checked the source IP on **VirusTotal**.

- **VirusTotal:** no security vendor flagged the IP as malicious. It belongs to a Tencent cloud network (country: CN).
- The IP is not currently reported as malicious, **but a clean reputation doesn't mean the request is benign**. Cloud IPs are new or rotating, so I judged the traffic itself.

![Images/SOC170-VirusTotal-Check.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/cb07ade87c8d4a111fbd1472750bfe4f472ef826/Images/SOC170-VirusTotal-Check.png)

## 5. Examine the traffic

- Opened **Log Management**.
- Used **Show filter**, selected the **source address** field and entered the attacker IP from the alert.

![Images/SOC170-Log-Filter.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/21f2fa12c8efbcc54c9f49e0beb7438ab33cede1/Images/SOC170-Log-Filter.png)

## 6. Malicious or not?

**Malicious.** No normal user would request a URL like this: a `file` parameter filled with repeated `../` and a system password file.

## 7. Attack type

**LFI & RFI** (Local File Inclusion). It's local because the target is a file on the server itself (`/etc/passwd`) rather than a file from an attacker-hosted URL.

## 8. Was the attack successful?

I reviewed the **firewall raw log** for the request:

- Because this is an LFI attack, I read through **all fields of the URL** for LFI indicators: `../../../../` traversal plus `/etc/passwd`.

| Field | Value |
|---|---|
| Device action | Permitted |
| Request method | GET |
| HTTP response size | **0** |
| HTTP response status | **500** |

A **500 (server error)** with a **response size of 0** means no file contents were returned to the attacker, so the attempt **failed**.

> **Note on confidence:** the firewall *permitted* the request, so the block didn't come from the network layer. The evidence for failure is the server's response. Response size and status are strong indicators when response bodies aren't logged, but they are indicators rather than proof.

![Images/SOC170-Raw-Log.png](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/7b7168e80b58e466e90b6b6f04752aefef7c0877/Images/SOC170-Raw-Log.png)

## 9. Remaining playbook steps

- **Planned test?** **No**, Penetration tests and attack-simulation tools (e.g. Verodin, AttackIQ, Picus) can trigger false positives. Here the source is an external IP, not a simulation host.
- **Direction of traffic:** Internet to Company Network.
- **Artifacts:** added the attacker IP (`106.55.45.162`, comment: *Attacker*).
- **Tier 2 escalation:** the playbook calls for escalation when the attack succeeds or when an internal device is compromised. Since this was an external attack that **did not succeed**, escalation wasn't required. (Always follow your organization's own escalation procedure.)
- **Analyst note:** wrote a short summary:
  > An external IP "106.55.45.162" from the TencentCloud network attempted an LFI attack against WebServer1006 (172.16.17.13) on March 01, 2022, at 10:10 AM. After reviewing the logs and investigating the activity, I confirmed it was a true positive, and the attack was unsuccessful.
- **Final result:** **True Positive** and closed the case.

## What I learned

- An alert's details already contain the key facts (source, target, hostname, trigger URL), so **read them carefully first**.
- The investigation follows a repeatable flow: *alert, internal vs external, IP reputation, traffic review, malicious?, attack type, success?, artifacts, escalation, note, verdict*.
- **IP reputation is supporting evidence, not the decision.** A clean IP can still send a malicious request.
- **A true positive can still be an unsuccessful attack**, and that distinction decides whether to escalate.
- A good analyst note says **who, what, where, when, and the outcome** in a few lines.
- The User-Agent in this alert (`MSIE 6.0; Windows NT 5.1`) is a very old browser string, which is unusual for real users today and is worth noting as a possible sign of a tool or spoofed client.

## Skills practised

Alert triage, IP reputation checks (VirusTotal), log filtering in a SIEM, LFI indicator recognition, success/failure assessment from response status and size, case documentation, escalation decisions.

---

*Back to [Section 1](README.md) | [README](../README.md)*
