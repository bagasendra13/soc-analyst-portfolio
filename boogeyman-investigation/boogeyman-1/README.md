# Boogeyman 1 — Incident Investigation

## Overview

This write-up documents my investigation of the **Boogeyman 1** challenge from TryHackMe.

The investigation covers three main areas:

- Email Analysis
- Endpoint Security Analysis
- Network Traffic Analysis

The objective was to investigate a simulated phishing attack, trace the attacker's activity across the endpoint and network, identify Indicators of Compromise (IOCs), and reconstruct the attack chain.

---

## Investigation Objectives

- Analyze a suspected phishing email
- Identify the attacker and victim email addresses
- Analyze email headers and attachments
- Extract and analyze a malicious LNK file
- Decode the payload contained in the LNK command line
- Investigate endpoint activity using PowerShell logs
- Identify attacker infrastructure
- Analyze network traffic using Wireshark
- Investigate DNS-based data exfiltration
- Identify the exfiltrated file and its contents
- Map observed attacker behavior to MITRE ATT&CK

---

## Environment

| Category | Details |
|---|---|
| Platform | TryHackMe |
| Room | Boogeyman |
| Part | 1 |
| Category | SOC / Incident Investigation |
| Operating System | Windows |
| Email Artifact | `dump.eml` |
| Endpoint Artifact | `powershell.json` |
| Network Capture | `capture.pcapng` |
| Tools | Linux CLI, `jq`, `grep`, `lnkparse`, Wireshark, TShark, CyberChef, KeePass |

---

# Investigation
## 1. Email Analysis

### Objective

The first stage of the investigation focused on analyzing the phishing email and its attachment.

The objective was to identify the sender, recipient, mail relay service, attachment, and payload contained inside the malicious LNK file.

---

### 1.1 Email Identification

I first analyzed the email artifact to identify the sender and recipient.

The raw email was inspected using:

```bash
cat dump.eml
```

I then searched through the raw email content to identify relevant indicators and email headers.

#### Observation

The email contained a suspicious sender and an attachment that required further investigation.

#### Finding

| Item | Value |
|---|---|
| Sender | `agriffin@bpakcaging.xyz` |
| Recipient | `julianne.westcott@hotmail.com` |
| Mail Relay | Elastic Email |

The `DKIM-Signature` and `List-Unsubscribe` headers indicated the use of **Elastic Email** as the third-party mail relay service.

---

### 1.2 Malicious Attachment

The phishing email contained an encrypted ZIP attachment.

After downloading the attachment, I extracted it using the password provided in the investigation:

```text
[REDACTED]
```

The extracted file was:

```text
Invoice_20230103.lnk
```

#### Observation

The attachment contained a Windows Shortcut (`.lnk`) file rather than a normal invoice document.

#### Analysis

LNK files can contain command-line arguments that execute additional commands when the shortcut is opened. Therefore, the file was analyzed further using `lnkparse`.

---

### 1.3 LNK Analysis

The extracted LNK file was analyzed using:

```bash
lnkparse Invoice_20230103.lnk
```

#### Observation

The **Command Line Arguments** field contained an encoded payload.

```text
[Encoded Base64 payload]
```

#### Analysis

The payload appeared to be Base64-encoded PowerShell content.

After decoding, the payload revealed a PowerShell command that downloaded additional content from the attacker's infrastructure.

#### Finding

The LNK file acted as the initial execution mechanism and was used to launch a PowerShell-based payload.

# 2. Endpoint Security Analysis

## Objective

The second stage focused on analyzing endpoint activity to understand what happened after the initial payload execution.

The available PowerShell log data was analyzed to identify commands, downloaded tools, accessed files, and potential data exfiltration activity.

---

## 2.1 PowerShell Log Analysis

I processed the PowerShell log data using `jq` to sort events chronologically and extract relevant `ScriptBlock` content.

```bash
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' | \
jq '{ScriptBlockText}' | sort | uniq
```

#### Observation

The PowerShell activity revealed several suspicious actions, including the download and execution of additional tools.

#### Analysis

The activity indicated that the attacker continued operating on the compromised endpoint after the initial phishing stage.

---

## 2.2 Attacker Infrastructure

The investigation identified the following domains:

| Purpose | Domain |
|---|---|
| File Hosting | `files.bpakcaging.xyz` |
| C2 / Supporting Infrastructure | `cdn.bpakcaging.xyz` |

These domains were associated with the attacker's infrastructure and were observed during the endpoint and network investigation.

---

## 2.3 Enumeration Tool

The attacker downloaded and used an enumeration tool:

```text
Seatbelt
```

#### Observation

Seatbelt was used during post-compromise activity to gather information from the compromised Windows system.

#### Finding

The use of Seatbelt indicates that the attacker performed host reconnaissance after gaining access to the endpoint.

---

## 2.4 Sensitive File Discovery

The attacker also used `sq3.exe` to access a SQLite database:

```text
C:\Users\j.westcott\AppData\Local\Packages\
Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\
LocalState\plum.sqlite
```

#### Observation

The file `plum.sqlite` was accessed using the downloaded SQLite binary.

#### Analysis

The database belongs to Microsoft Sticky Notes and may contain locally stored user information.

#### Finding

The attacker accessed a locally stored application database containing potentially sensitive user information.

---

## 2.5 Data Exfiltration

The investigation identified an exfiltrated file:

```text
protected_data.kdbx
```

The `.kdbx` extension is associated with KeePass password database files.

#### Observation

The attacker attempted to exfiltrate sensitive information stored in the KeePass database.

The data was encoded using hexadecimal encoding and transferred through DNS queries.

#### Finding

The attacker used DNS-based communication to exfiltrate encoded sensitive data from the compromised endpoint.

# 3. Network Traffic Analysis

## Objective

The final stage focused on analyzing the provided packet capture to identify the attacker's infrastructure, C2 communication, and DNS-based exfiltration.

---

## 3.1 Packet Capture Analysis

I opened the provided packet capture using Wireshark:

```text
capture.pcapng
```

I used the following Wireshark filter to identify HTTP traffic associated with the attacker's infrastructure:

```text
http contains files.bpakcaging.xyz
```

#### Observation

The packet capture contained HTTP communication with the attacker-controlled infrastructure.

Following the relevant TCP stream revealed that the presumed file/payload server was hosted using Python.

#### Finding

The attacker used a Python-based HTTP server to host files or payloads.

---

## 3.2 C2 Communication

The HTTP traffic was further analyzed by following the relevant TCP streams.

#### Observation

The HTTP method used by the C2 communication for command output was:

```text
POST
```

#### Finding

The attacker used HTTP `POST` requests to communicate command output back to the C2 infrastructure.

## 3.3 DNS Exfiltration

The packet capture also contained suspicious DNS traffic.

I extracted DNS query names using:

```bash
tshark -r capture.pcapng \
-Y 'dns' \
-T fields \
-e dns.qry.name |
grep ".bpakcaging.xyz" |
cut -f1 -d '.' |
grep -v -e "files" -e "cdn" |
uniq |
tr -d '\n' > extracted.txt
```

#### Observation

A large amount of seemingly random data was embedded within DNS queries to the attacker-controlled domain.

#### Analysis

The structure of the DNS queries indicated that data was being encoded and transferred through DNS requests.

The extracted data was reconstructed and processed to recover the exfiltrated file.

#### Finding

DNS was used as the protocol for exfiltrating the sensitive file.

---

## 3.4 Exfiltrated KeePass Database

The extracted data was reconstructed into a binary file and opened using KeePass.

The password recovered during the network investigation was used to access the database.

```text
[REDACTED]
```

#### Observation

The database contained sensitive information, including payment-related data.

#### Finding

The investigation confirmed that sensitive information had been successfully exfiltrated from the compromised endpoint.

# Attack Timeline

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Phishing email received | `dump.eml` | Initial delivery mechanism |
| 2 | Encrypted attachment extracted | `Invoice_20230103.lnk` | Malicious LNK identified |
| 3 | LNK analyzed | `lnkparse` output | Encoded PowerShell payload discovered |
| 4 | Payload downloaded | HTTP traffic | Attacker infrastructure identified |
| 5 | Post-compromise activity | PowerShell logs | Attacker executed additional commands |
| 6 | Enumeration | Seatbelt | Host reconnaissance performed |
| 7 | Database access | `plum.sqlite` | Local application data accessed |
| 8 | Sensitive file identified | `protected_data.kdbx` | KeePass database targeted |
| 9 | Data encoded | Hex | Data prepared for exfiltration |
| 10 | Exfiltration | DNS traffic | Data transferred through DNS |

---

# Indicators of Compromise

| Type | Value | Description |
|---|---|---|
| Sender | `agriffin@bpakcaging.xyz` | Phishing sender |
| Domain | `bpakcaging.xyz` | Attacker infrastructure |
| Domain | `files.bpakcaging.xyz` | File hosting |
| Domain | `cdn.bpakcaging.xyz` | Supporting infrastructure |
| File | `Invoice_20230103.lnk` | Malicious shortcut |
| File | `protected_data.kdbx` | Exfiltrated KeePass database |
| File | `plum.sqlite` | Microsoft Sticky Notes database |
| Tool | `Seatbelt` | Host enumeration |
| Tool | `sq3.exe` | SQLite database access |
| Protocol | DNS | Data exfiltration |

# MITRE ATT&CK Mapping

> MITRE ATT&CK mappings should only be included when supported by the evidence observed during the investigation.

| Tactic | Technique | ID | Evidence | Description |
|---|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious email attachment | Phishing email delivered a malicious attachment |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | LNK command line | PowerShell was used to execute the payload |
| Discovery | System Information Discovery | T1082 | Seatbelt activity | Host information was enumerated |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP traffic | HTTP was used for C2 communication |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | DNS traffic | Data was exfiltrated through DNS |
| Collection | Data from Local System | T1005 | `plum.sqlite` | Sensitive local application data was accessed |

# Key Findings

The investigation identified the following:

- A phishing email was used as the initial attack vector.
- The email contained an encrypted ZIP attachment containing a malicious LNK file.
- The LNK file contained an encoded PowerShell payload used to retrieve additional content from attacker infrastructure.
- The attacker performed post-compromise enumeration using Seatbelt.
- The attacker accessed the Microsoft Sticky Notes SQLite database using `sq3.exe`.
- A KeePass database named `protected_data.kdbx` was targeted.
- The attacker used HTTP for C2 communication.
- Sensitive data was encoded and exfiltrated through DNS queries.

---

# Investigation Conclusion

The investigation revealed a multi-stage attack beginning with a phishing email containing an encrypted archive.

The archive contained a malicious LNK file whose command-line arguments contained an encoded PowerShell payload. The payload enabled the attacker to retrieve additional resources from attacker-controlled infrastructure.

After gaining access to the endpoint, the attacker performed host enumeration, accessed local application data, and targeted a KeePass database containing sensitive information.

Network analysis confirmed the presence of HTTP-based C2 communication and DNS-based data exfiltration.

The investigation demonstrated how email, endpoint, and network artifacts can be correlated to reconstruct an attack chain and identify attacker behavior.

# Skills Demonstrated

- Phishing Email Analysis
- Email Header Analysis
- IOC Identification
- LNK File Analysis
- PowerShell Log Analysis
- Windows Endpoint Investigation
- Log Analysis
- Network Traffic Analysis
- Wireshark
- TShark
- DNS Analysis
- HTTP Analysis
- Data Exfiltration Analysis
- MITRE ATT&CK Mapping
- Incident Timeline Reconstruction
- Evidence-Based Investigation

---

# Lessons Learned

- Email headers can provide valuable information about the origin and infrastructure used in phishing campaigns.
- LNK files should be treated as potentially dangerous execution mechanisms and analyzed for embedded command-line arguments.
- Endpoint and network logs can be correlated to reconstruct attacker activity.
- DNS traffic can be abused as a covert channel for data exfiltration.
- Understanding normal application behavior is useful when investigating access to files such as SQLite databases.
