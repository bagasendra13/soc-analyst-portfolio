# Boogeyman 2 — Incident Investigation

## Overview

This write-up documents my investigation of the **Boogeyman 2 — Spear Phishing Human Resources** challenge from TryHackMe.

For this investigation, I used a Linux-based analysis environment to investigate a simulated spear-phishing attack against a Human Resources employee. The investigation started from the phishing email and malicious Word document, then continued into memory forensics to identify the execution chain, malicious processes, C2 connection, and persistence mechanism.

The investigation covers the following areas:

- Phishing Email Analysis
- Malicious Office Document Analysis
- VBA Macro Analysis
- Memory Forensics
- Process Tree Analysis
- Malware Payload Analysis
- Command and Control (C2) Analysis
- Persistence Analysis
- IOC Identification
- MITRE ATT&CK Mapping

The main objective was to reconstruct the attack chain from the initial phishing email to the execution of the malicious payload, establishment of C2 communication, and persistence on the compromised Windows workstation.

## Investigation Objectives

- Identify the phishing email sender and victim
- Identify the malicious email attachment
- Calculate the MD5 hash of the attachment
- Determine whether the attachment is malicious
- Analyze the VBA macro contained in the Word document
- Identify the URL used to download the Stage 2 payload
- Identify the process that executed the Stage 2 payload
- Identify the full path of the Stage 2 payload
- Analyze the Windows memory dump using Volatility
- Identify the malicious process used to establish the C2 connection
- Identify the URL used to download the malicious binary
- Identify the full path of the malicious C2 process
- Identify the C2 IP address and port
- Identify the original file path of the malicious email attachment
- Identify the scheduled task used for persistence
- Reconstruct the complete attack chain
- Map the observed activity to MITRE ATT&CK techniques

## Environment

| Category | Details |
|---|---|
| Platform | TryHackMe |
| Room | Boogeyman |
| Part | 2 |
| Task | Spear Phishing Human Resources |
| Analysis OS | Linux |
| Target OS | Windows |
| Email Attachment | `Resume_WesleyTaylor.doc` |
| Memory Dump | `WKSTN-2961.raw` |
| Tools | Linux CLI, `md5sum`, `olevba`, VirusTotal, Volatility, `strings`, `grep` |

# Investigation

## 1. Phishing Email Analysis

### Objective

The first step of the investigation was to identify the phishing email and determine who sent it, who the target was, and what attachment was delivered.

### 1.1 Email Identification

The phishing email contained the following information:

| Item | Value |
|---|---|
| Sender | `westaylor23@outlook.com` |
| Victim | `maxine.beck@quicklogisticsorg.onmicrosoft.com` |
| Attachment | `Resume_WesleyTaylor.doc` |

The email was crafted to look like a resume-related email and was targeted at a Human Resources employee.

#### Finding

The attacker used a spear-phishing email to deliver a malicious Microsoft Word document to the victim. The document was used as the initial entry point into the victim's system.

### 1.2 Attachment MD5 Hash

After identifying the attachment, I calculated its MD5 hash using the following command:

```bash
md5sum Resume_WesleyTaylor.doc
```
I then checked the hash using VirusTotal to determine whether the file had already been identified as malicious.

Observation
The file was flagged as malicious by VirusTotal.

Finding
The attachment was confirmed to be malicious.

## 2. Malicious Document Analysis

### 2.1 VBA Macro Analysis

The next step was to inspect the contents of the malicious Word document and determine whether it contained any macros.

I used `olevba` to extract and analyze the VBA code:

```bash
olevba Resume_WesleyTaylor.doc
```
The output showed suspicious VBA macro activity. The macro contained code responsible for downloading the next stage of the payload from an external URL.

The URL used to download the Stage 2 payload was:
```bash
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
```
Finding
The malicious Word document used a VBA macro to download the next-stage payload from attacker-controlled infrastructure.

### 2.2 Stage 2 Payload Execution

Further analysis of the VBA macro showed that the downloaded Stage 2 payload was executed using:

```text
wscript.exe
```
The full path of the Stage 2 payload was:
```bash
C:\ProgramData\update.js
```

C:\ProgramData\update.js

This indicates that the attacker used Windows Script Host to execute a JavaScript payload.

The initial execution chain can be summarized as:
```text
Resume_WesleyTaylor.doc
        ↓
VBA Macro
        ↓
Download update.png
        ↓
C:\ProgramData\update.js
        ↓
wscript.exe
```

Finding
The malicious Word document acted as the first stage of the attack, while update.js served as the Stage 2 payload and was executed through wscript.exe

## 3. Memory Forensics

### Objective

After analyzing the malicious document, I moved to the provided Windows memory dump to investigate the processes created during the attack.

The memory dump used for the investigation was:

```text
WKSTN-2961.raw
```
I used Volatility to analyze the process tree, command lines, and network connections.

### 3.1 Process Tree Analysis
I first searched the process tree for wscript.exe:
```bash
vol -f WKSTN-2961.raw windows.pstree.PsTree | grep wscript.exe
```
The malicious wscript.exe process was identified with PID: `4260`

I then searched for the process ID to investigate its relationship with other processes:
```bash
vol -f WKSTN-2961.raw windows.pstree.PsTree | grep 4260
```
The parent PID associated with the wscript.exe process was: `1124`
The process tree also revealed another suspicious process that was responsible for establishing the C2 connection.
The PID of this malicious process was: `6216`

Finding
The Stage 2 payload was executed by wscript.exe with PID 4260.
The malicious process used to establish the C2 connection was identified with PID 6216.

## 4. Stage 3 Payload Analysis

### 4.1 Malicious Binary Download URL

After identifying the Stage 2 payload, I investigated what additional binary was downloaded by the JavaScript payload.

I searched the memory dump for references to the attacker's domain using:

```bash
strings WKSTN-2961.raw | grep boogeyman
```
The following URL was identified:
```bash
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```
The downloaded binary was named: `update.exe`

Finding
The Stage 2 JavaScript payload downloaded the malicious binary from:
```bash
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```

### 4.2 Malicious C2 Process

I then investigated the command line associated with PID `6216` using Volatility:

```bash
vol -f WKSTN-2961.raw windows.cmdnline.CmdLine | grep 6216
```
The command line revealed that the malicious binary was executed from:
```bash
C:\Windows\Tasks\updater.exe
```
Finding
The full path of the malicious process used to establish the C2 connection was:
```bash
C:\Windows\Tasks\updater.exe
```
The execution chain had now been extended to:
```text
Resume_WesleyTaylor.doc
        ↓
VBA Macro
        ↓
update.png
        ↓
C:\ProgramData\update.js
        ↓
wscript.exe
        ↓
update.exe
        ↓
C:\Windows\Tasks\updater.exe
        ↓
C2 Connection
```

## 5. Command and Control Analysis

### 5.1 C2 Connection

To identify the network connection initiated by the malicious binary, I used Volatility's `netscan` plugin:

```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan | grep updater.exe
```
The investigation identified the following connection: 
```bash
128.199.95.189:8080
```
Finding
The malicious binary established a C2 connection to:
```bash
128.199.95.189:8080
```
This IP address and port are important network Indicators of Compromise.
C2 IOC:
```bash
128.199.95.189:8080
```

## 6. Malicious Attachment Location

### Objective

The next step was to determine the full file path where the malicious email attachment was stored on the victim's Windows system.

I searched the command-line information from the memory dump using:

```bash
vol -f WKSTN-2961.raw windows.cmdline.CmdLine | grep Resume_Wesley
```
The following path was identified:
```bash
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```
Finding
The malicious attachment was stored in the victim's Outlook Internet cache at:
```bash
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```
This provides additional evidence connecting the malicious document to the victim's system.

## 7. Persistence Analysis

### 7.1 Scheduled Task

After establishing the C2 connection, the attacker implanted a scheduled task to maintain persistent access to the compromised system.

To identify the command used to create the scheduled task, I searched the memory dump for `schtasks`:

```bash
strings WKSTN-2961.raw | grep schtasks
```
The following command was identified:
```bash
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
```
Analysis
The command creates a scheduled task named: `Updater`
The task is configured to run: `DAILY`
at: `09:00`
The task executes PowerShell using the following options: `-NonI`, `-W hidden`, `-c`
The PowerShell command retrieves the `debug` value from:
```bash
HKCU:\Software\Microsoft\Windows\CurrentVersion
```
The retrieved value is then Base64-decoded and converted from Unicode before being executed using `IEX`.

Finding
The attacker used a scheduled task named `Updater` as a persistence mechanism.

The task executes a hidden PowerShell command that retrieves an encoded payload from the Windows Registry, decodes it, and executes it.

# Attack Chain

The complete attack chain reconstructed from the available evidence is:

```text
Spear Phishing Email
        │
        ▼
Resume_WesleyTaylor.doc
        │
        ▼
VBA Macro
        │
        ▼
Download update.png
        │
        ▼
C:\ProgramData\update.js
        │
        ▼
wscript.exe
        │
        ▼
Download update.exe
        │
        ▼
C:\Windows\Tasks\updater.exe
        │
        ▼
C2: 128.199.95.189:8080
        │
        ▼
Scheduled Task: Updater
        │
        ▼
Hidden PowerShell
        │
        ▼
Registry-based Payload
```

# Attack Timeline

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Spear-phishing email received | `westaylor23@outlook.com` | Attacker targeted an HR employee |
| 2 | Malicious attachment delivered | `Resume_WesleyTaylor.doc` | Initial malicious document |
| 3 | Attachment identified as malicious | MD5 `52c4384a0b9e248b95804352ebec6c5b` | VirusTotal flagged the file |
| 4 | VBA macro analyzed | `olevba` output | Macro downloaded the next-stage payload |
| 5 | Stage 2 downloaded | `update.png` | Payload retrieved from attacker infrastructure |
| 6 | Stage 2 executed | `wscript.exe` | JavaScript payload executed |
| 7 | Stage 2 path identified | `C:\ProgramData\update.js` | Malicious script stored on endpoint |
| 8 | Malicious binary downloaded | `update.exe` | Stage 3 payload retrieved |
| 9 | Malicious binary executed | `C:\Windows\Tasks\updater.exe` | Malicious C2 process identified |
| 10 | C2 established | `128.199.95.189:8080` | Malware communicated with attacker infrastructure |
| 11 | Persistence established | Scheduled task `Updater` | Attacker maintained persistent access |
| 12 | Hidden PowerShell executed | Registry-based payload | Encoded payload was decoded and executed |

# Indicators of Compromise

| Type | Value | Description |
|---|---|---|
| Email Sender | `westaylor23@outlook.com` | Spear-phishing sender |
| Victim | `maxine.beck@quicklogisticsorg.onmicrosoft.com` | Targeted user |
| File | `Resume_WesleyTaylor.doc` | Malicious email attachment |
| MD5 | `52c4384a0b9e248b95804352ebec6c5b` | Attachment hash |
| Domain | `boogeymanisback.lol` | Attacker infrastructure |
| URL | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` | Stage 2 download |
| URL | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` | Malicious binary download |
| File | `C:\ProgramData\update.js` | Stage 2 JavaScript payload |
| File | `C:\Windows\Tasks\updater.exe` | Malicious C2 binary |
| Process | `wscript.exe` | Stage 2 execution process |
| PID | `4260` | Malicious `wscript.exe` process |
| PID | `6216` | Malicious C2 process |
| C2 | `128.199.95.189:8080` | Attacker C2 endpoint |
| Scheduled Task | `Updater` | Persistence mechanism |

# MITRE ATT&CK Mapping

> MITRE ATT&CK mappings are based on the behavior directly observed during the investigation.

| Tactic | Technique | ID | Evidence | Description |
|---|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious `Resume_WesleyTaylor.doc` | Attacker delivered a malicious document through spear-phishing |
| Execution | User Execution: Malicious File | T1204.002 | Malicious Word document | The attack relied on execution of a malicious attachment |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | `update.js` executed by `wscript.exe` | JavaScript was used to execute the Stage 2 payload |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden PowerShell in scheduled task | PowerShell was used to decode and execute the persistence payload |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | `schtasks /Create ... /TN Updater` | Scheduled task was created to maintain persistent access |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 connection to `128.199.95.189:8080` | Web-based communication was used for C2 |
| Defense Evasion | Obfuscated/Compressed Files and Information | T1027 | Base64-encoded PowerShell payload | Encoded data was decoded before execution |

# Key Findings

The investigation identified the following:

- The attacker used a spear-phishing email targeting a Human Resources employee.
- The malicious sender was `westaylor23@outlook.com`.
- The victim was `maxine.beck@quicklogisticsorg.onmicrosoft.com`.
- The phishing attachment was `Resume_WesleyTaylor.doc`.
- The attachment had the MD5 hash `52c4384a0b9e248b95804352ebec6c5b`.
- VirusTotal flagged the attachment as malicious.
- The Word document contained malicious VBA macros.
- The macro downloaded a Stage 2 payload from `files.boogeymanisback.lol`.
- The Stage 2 payload was stored at `C:\ProgramData\update.js`.
- `wscript.exe` executed the malicious JavaScript payload.
- The Stage 2 payload downloaded `update.exe`.
- The malicious binary was executed from `C:\Windows\Tasks\updater.exe`.
- The malicious `wscript.exe` process had PID `4260`.
- The malicious C2 process had PID `6216`.
- The malware established a C2 connection to `128.199.95.189:8080`.
- The original malicious attachment was stored in the victim's Outlook Internet cache.
- The attacker established persistence using a scheduled task named `Updater`.
- The scheduled task executed hidden PowerShell.
- The PowerShell command retrieved an encoded value from the Windows Registry, decoded the Base64 content, and executed it using `IEX`.

# Investigation Conclusion

The investigation revealed a multi-stage spear-phishing attack targeting a Human Resources employee.

The attack began with a malicious Microsoft Word document delivered through email. The document contained VBA macros that downloaded a second-stage JavaScript payload from attacker-controlled infrastructure.

The Stage 2 payload was stored at `C:\ProgramData\update.js` and executed using `wscript.exe`. The JavaScript payload then downloaded a malicious executable named `update.exe`, which was executed from `C:\Windows\Tasks\updater.exe`.

Memory forensics confirmed that the malicious process established a C2 connection to `128.199.95.189:8080`.

After establishing the C2 connection, the attacker implemented persistence using a scheduled task named `Updater`. The task was configured to run daily at 09:00 and execute a hidden PowerShell command.

The PowerShell command retrieved a value from the Windows Registry, decoded the Base64-encoded content, and executed it using `IEX`.

By correlating the phishing email, malicious Office document, VBA macro, memory artifacts, process information, command lines, and network connections, the attack chain could be reconstructed from initial access through payload execution, C2 communication, and persistence.

# Skills Demonstrated

- Spear Phishing Investigation
- Malicious Office Document Analysis
- VBA Macro Analysis
- IOC Identification
- MD5 Hash Analysis
- VirusTotal Analysis
- Linux Command-Line Investigation
- Memory Forensics
- Volatility
- Process Tree Analysis
- Windows Process Investigation
- Command-Line Analysis
- Malware Payload Analysis
- C2 Investigation
- Persistence Analysis
- Scheduled Task Investigation
- PowerShell Analysis
- Registry-Based Payload Analysis
- MITRE ATT&CK Mapping
- Incident Timeline Reconstruction

# Lessons Learned

- Malicious Office documents can use VBA macros to initiate multi-stage attacks.
- File hashes can be used to identify and investigate known malicious files.
- `olevba` is useful for extracting and analyzing VBA macros from Office documents.
- Memory forensics can reveal processes, command lines, and network connections associated with malicious activity.
- Process tree analysis helps establish the relationship between the initial payload and subsequent malicious processes.
- Attackers can disguise malicious payloads using misleading file extensions, such as `update.png`.
- Volatility can be used to correlate malicious processes with their network connections.
- Scheduled tasks are a common persistence mechanism and should be investigated during post-compromise analysis.
- PowerShell can be used together with Base64 encoding and Registry-stored data to hide and execute payloads.
- Correlating email, endpoint, memory, and network evidence is important for reconstructing the complete attack chain.
