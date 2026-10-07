# SOC Lab: SOC170 - Passwd Found in Requested URL - Possible LFI Attack

> Sub-file of [Section 1: Detecting Web Attacks](README.md). Platform: **LetsDefend** (practice alert, SOC analyst role).

## Summary

| | |
|---|---|
| Alert | SOC170 - Passwd Found in Requested URL - Possible LFI Attack |
| Severity / difficulty | High / Easy |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |
| Source IP | 106.55.45.162 (external) |
| Target | WebServer1006 (172.16.17.13) |
| Request | `GET https://172.16.17.13/?file=../../../../etc/passwd` |
| Alert trigger | URL contains `passwd` |
| Device action | Allowed (not blocked) |
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

## 3. Is the traffic from inside or outside the network?

Playbook step 1: determine whether the source is internal or external.

- In **Endpoint Security**, I checked the list of internal hosts (you can also search by IP in the search bar).
- The source IP returned **no matches**, so it isn't part of the internal network. It comes from an **external source (the Internet)**.

![(images/soc170-endpoint-01-endpoint-search.png)](https://github.com/YusraAlMazrui/Web-Attacks-Detection-And-Analysis/blob/6fc0f3b6d8b5a3e133bfabf9f9c810e8050f0497/Images/SOC170-endpoint-search.png)


## 4. Collect data on the IP (reputation)

I checked the source IP on **VirusTotal**, **AbuseIPDB** and **Cisco Talos**.

- **VirusTotal:** no security vendor flagged the IP as malicious. It belongs to a Tencent cloud network (country: CN).
- The IP is not currently reported as malicious, **but a clean reputation doesn't mean the request is benign**. Cloud IPs are new or rotating, so I judged the traffic itself.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![VirusTotal result](images/soc170-reputation-01-virustotal.png)
![AbuseIPDB result](images/soc170-reputation-02-abuseipdb.png)
![Cisco Talos result](images/soc170-reputation-03-talos.png)
-->

## 5. Examine the traffic

- Opened **Log Management** and switched the view from **Pro** to **Basic** for easier reading.
- Used **Show filter**, selected the **source address** field and entered the attacker IP from the alert.
- Because this is a possible LFI, I read through **all fields of the URL** for LFI indicators. They were easy to spot: `../../../../` traversal plus `/etc/passwd`.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![Log Management filtered by source address](images/soc170-logs-01-log-filter.png)
![LFI indicators in the URL](images/soc170-logs-02-lfi-indicators.png)
-->

## 6. Malicious or not?

**Malicious.** No normal user would request a URL like this: a `file` parameter filled with repeated `../` and a system password file.

## 7. Attack type

**LFI & RFI** (Local File Inclusion). It's local because the target is a file on the server itself (`/etc/passwd`) rather than a file from an attacker-hosted URL.

## 8. Was the attack successful?

I reviewed the **firewall raw log** for the request:

| Field | Value |
|---|---|
| Device action | Permitted |
| Request method | GET |
| HTTP response size | **0** |
| HTTP response status | **500** |

A **500 (server error)** with a **response size of 0** means no file contents were returned to the attacker, so the attempt **failed**.

> **Note on confidence:** the firewall *permitted* the request, so the block didn't come from the network layer. The evidence for failure is the server's response. Response size and status are strong indicators when response bodies aren't logged, but they are indicators rather than proof. Extra checks that would strengthen the conclusion:
> - Look for **other requests from the same source IP** (retries with different payloads/encodings, or a later `200` with a non-zero response size).
> - Check the **web server's own logs** for errors or file-access events around the same time.
> - Look for **follow-up activity** from the target, such as new outbound connections or logins.
> In this lab the filtered logs showed only this single request.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![Raw log: response size 0, status 500](images/soc170-success-01-raw-log.png)
-->

## 9. Remaining playbook steps

- **Planned test?** Penetration tests and attack-simulation tools (e.g. Verodin, AttackIQ, Picus) can trigger false positives. I checked for any sign that this was a planned test. Here the source is an external IP, not a simulation host.
- **Direction of traffic:** Internet to Company Network.
- **Artifacts:** added the attacker IP (`106.55.45.162`, comment: *Attacker*).
- **Tier 2 escalation:** the playbook calls for escalation when the attack succeeds or when an internal device is compromised. Since this was an external attack that **did not succeed**, escalation wasn't required. (Always follow your organization's own escalation procedure.)
- **Analyst note:** wrote a short summary:
  > An external IP "106.55.45.162" from the TencentCloud network attempted an LFI attack against WebServer1006 (172.16.17.13) on March 01, 2022, at 10:10 AM. After reviewing the logs and investigating the activity, I confirmed it was a true positive, but the attack was unsuccessful.
- **Final result:** **True Positive** and closed the case.

**Screenshots**

_Add your lab screenshots here: save them in the `images/` folder, then replace the example lines below._

<!--
![Artifacts added](images/soc170-closing-01-artifacts.png)
![Analyst note](images/soc170-closing-02-analyst-note.png)
![Review and submit (True Positive)](images/soc170-closing-03-final-verdict.png)
-->

## What I learned

- An alert's details already contain the key facts (source, target, hostname, trigger URL), so **read them carefully first**.
- The investigation follows a repeatable flow: *alert, internal vs external, IP reputation, traffic review, malicious?, attack type, success?, artifacts, escalation, note, verdict*.
- **IP reputation is supporting evidence, not the decision.** A clean IP can still send a malicious request.
- **A true positive can still be an unsuccessful attack**, and that distinction decides whether to escalate.
- A good analyst note says **who, what, where, when, and the outcome** in a few lines.
- The User-Agent in this alert (`MSIE 6.0; Windows NT 5.1`) is a very old browser string, which is unusual for real users today and is worth noting as a possible sign of a tool or spoofed client.

## Skills practised

Alert triage, IP reputation checks (VirusTotal, AbuseIPDB, Cisco Talos), log filtering in a SIEM, LFI indicator recognition, success/failure assessment from response status and size, case documentation, escalation decisions.

---

*Back to [Section 1](README.md) | [README](../README.md)*
