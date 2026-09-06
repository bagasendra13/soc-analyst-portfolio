# End-to-End Phishing & Incident Investigation

> Hands-on investigation of a simulated targeted phishing attack, covering
> the attack chain from initial access to data exfiltration.

## Overview

This project investigates a simulated targeted phishing campaign against
a finance employee. The investigation covers phishing email analysis,
malicious file analysis, PowerShell activity, endpoint discovery,
command-and-control communication, and data exfiltration.

The objective is to reconstruct the attack chain and identify the
attacker's Tactics, Techniques, and Procedures (TTPs).

---

## Objectives

- Analyze a phishing email and its headers
- Investigate a malicious LNK attachment
- Analyze PowerShell execution and downloaded payloads
- Investigate endpoint discovery activity
- Analyze C2 communication
- Identify sensitive data accessed by the attacker
- Investigate DNS-based data exfiltration
- Reconstruct the attack timeline
- Map observed TTPs to MITRE ATT&CK
- Identify potential detection opportunities

---

## Tools & Technologies

- Thunderbird
- LNKParse3
- Wireshark
- Tshark
- jq
- grep
- sed
- CyberChef
- MITRE ATT&CK

---

# Investigation

## 1. Initial Access — Phishing

### Objective

Identify the source of the phishing email and analyze its characteristics.

### Analysis

The investigation started by analyzing the phishing email and reviewing
its headers to identify the sender, recipient, mail infrastructure,
and suspicious domains.

### Key Findings

- Phishing theme: Invoice / unpaid invoice
- Target: Finance employee
- Malicious attachment: Encrypted ZIP archive
- Mail relay: [YOUR FINDING]
- Sender domain: [YOUR FINDING]

### Evidence

[Add screenshot or sanitized evidence here.]

### MITRE ATT&CK

- **T1566 — Phishing**
- [Add sub-technique if applicable]

---

## 2. Execution — Malicious LNK

### Objective

Analyze the malicious attachment and identify the payload executed
when the victim opened the file.

### Analysis

The encrypted attachment was extracted and the contained LNK file
was analyzed using LNKParse3.

The LNK command-line arguments contained an encoded PowerShell payload.

### Key Findings

- File: `Invoice_20230103.lnk`
- File type: Windows Shortcut
- Payload: Encoded PowerShell command
- Payload encoding: Base64

### Analysis Method

LNKParse3 was used to extract metadata and command-line arguments
from the malicious LNK file.

The encoded payload was then decoded to understand the executed command.

### Evidence

[Add sanitized screenshot here.]

### MITRE ATT&CK

- **T1204.002 — User Execution: Malicious File**
- **T1059.001 — Command and Scripting Interpreter: PowerShell**

---

## 3. PowerShell Activity

### Objective

Investigate PowerShell activity following execution of the malicious LNK.

### Analysis

PowerShell logs were analyzed to identify commands executed by the attacker,
external network connections, downloaded payloads, and subsequent activity.

Command-line tools such as `jq`, `grep`, and `sed` were used to filter
and analyze the available log data.

### Key Findings

- PowerShell was used to download additional payloads.
- The attacker communicated with external infrastructure.
- Additional tools were downloaded to the compromised workstation.

### Evidence

[Add sanitized screenshot here.]

### MITRE ATT&CK

- **T1059.001 — PowerShell**
- [Additional techniques if identified]

---

## 4. Discovery & Enumeration

### Objective

Identify information gathered by the attacker after gaining access
to the workstation.

### Analysis

PowerShell activity was analyzed to identify enumeration commands
and downloaded utilities.

The investigation identified **Seatbelt**, a Windows security
enumeration tool, being downloaded and executed.

Additional activity involved the use of `sq3.exe` to access a
SQLite database associated with Microsoft Sticky Notes.

### Key Findings

- Enumeration tool: Seatbelt
- SQLite utility: `sq3.exe`
- Accessed database: `plum.sqlite`
- Associated software: Microsoft Sticky Notes

### Evidence

[Add sanitized screenshot here.]

### MITRE ATT&CK

- **T1087 — Account Discovery**
- **T1012 — Query Registry**
- [Add only techniques supported by your evidence]

---

## 5. Collection — Sensitive Data

### Objective

Identify sensitive information accessed by the attacker.

### Analysis

The PowerShell logs revealed that the attacker accessed a KeePass
database file containing sensitive information.

### Key Findings

- File: `protected_data.kdbx`
- File type: KeePass database
- Application: KeePass
- Sensitive data: [Describe without exposing the actual data]

### Evidence

[Add sanitized screenshot here.]

### MITRE ATT&CK

- **T1005 — Data from Local System**

---

## 6. Command & Control

### Objective

Identify the infrastructure and communication protocol used
by the attacker.

### Analysis

Network traffic was analyzed using Wireshark to identify
communications between the compromised workstation and attacker-controlled
infrastructure.

HTTP traffic revealed command-and-control communication and
an attacker-hosted payload server.

### Key Findings

- C2 IP: [SANITIZED / LAB IP]
- C2 domain: [SANITIZED]
- Protocol: HTTP
- HTTP method: POST
- Server software: Python

### Evidence

[Add sanitized Wireshark screenshot here.]

### MITRE ATT&CK

- **T1071.001 — Web Protocols: HTTP/HTTPS**

---

## 7. Data Exfiltration

### Objective

Determine how the sensitive file was exfiltrated from the compromised
workstation.

### Analysis

The investigation identified a DNS-based exfiltration mechanism.

The sensitive file was converted to hexadecimal data, split into
smaller chunks, and transmitted through DNS queries.

Wireshark and Tshark were used to extract and reconstruct the
exfiltrated data.

### Key Findings

- Exfiltrated file: `protected_data.kdbx`
- Encoding: Hexadecimal
- Exfiltration protocol: DNS
- Tool: `nslookup`
- Destination: [SANITIZED]

### Evidence

[Add sanitized screenshot here.]

### MITRE ATT&CK

- **T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol**

---

# Attack Timeline

| Time | Event | Evidence |
|---|---|---|
| [TIME] | Phishing email received | Email headers |
| [TIME] | Malicious LNK executed | LNK artifact |
| [TIME] | PowerShell executed | PowerShell logs |
| [TIME] | Payload downloaded | PowerShell logs |
| [TIME] | Enumeration performed | PowerShell logs |
| [TIME] | Sensitive file accessed | Endpoint logs |
| [TIME] | C2 communication | Wireshark |
| [TIME] | Data exfiltration | DNS traffic |

---

# Attack Chain

```text
Phishing Email
      ↓
Malicious LNK
      ↓
PowerShell Execution
      ↓
Payload Download
      ↓
System Enumeration
      ↓
Sensitive Data Collection
      ↓
C2 Communication
      ↓
DNS Data Exfiltration
```
# MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566 | Phishing email |
| Execution | T1059.001 | PowerShell execution |
| Discovery | [Txxxx] | Enumeration activity |
| Collection | T1005 | KeePass database accessed |
| Command & Control | T1071.001 | HTTP communication |
| Exfiltration | T1048.003 | DNS-based exfiltration |	

# Indicators of Compromise
| Type | Indicator | Description |
|---|---|---|
| Domain | [DOMAIN] | Attacker infrastructure |
| IP | [IP] | C2 / hosting server |
| File | Invoice_20230103.lnk | Malicious attachment |
| File | protected_data.kdbx | Sensitive data targeted |
| Tool | Seatbelt | Enumeration utility |

Sensitive credentials, passwords, personal information, and financial
information have been intentionally excluded from this report.

# Detection Opportunities
Phishing
Monitor suspicious sender domains.
Detect invoice-themed phishing emails.
Monitor malicious .lnk attachments.
PowerShell
Monitor suspicious PowerShell execution.
Detect encoded or obfuscated PowerShell commands.
Monitor PowerShell processes initiating external connections.
Endpoint Activity
Monitor unusual process execution.
Detect suspicious enumeration utilities.
Correlate process creation with network activity.
Command & Control
Monitor outbound HTTP connections to suspicious infrastructure.
Investigate unusual HTTP POST requests.
DNS Exfiltration
Monitor unusually long DNS queries.
Detect high-frequency DNS queries to suspicious domains.
Monitor abnormal DNS query patterns.

# Investigation Summary
This investigation demonstrated a complete attack chain beginning with
a targeted phishing email and progressing through malicious LNK execution,
PowerShell activity, endpoint discovery, sensitive data collection,
command-and-control communication, and DNS-based data exfiltration.

The investigation required correlation of email artifacts, endpoint logs,
PowerShell activity, and network traffic to reconstruct the attack timeline
and identify relevant attacker techniques.

# Lessons Learned
Phishing investigations require analysis of both email content and headers.
Endpoint and network telemetry should be correlated during incident investigation.
PowerShell logging can provide valuable evidence of attacker activity.
DNS traffic can be abused as a covert channel for data exfiltration.
Timeline reconstruction helps connect individual events into a complete attack chain.

# References
TryHackMe — Boogeyman
MITRE ATT&CK
