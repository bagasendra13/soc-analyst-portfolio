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
Resume_WesleyTaylor.doc
        ↓
VBA Macro
        ↓
Download update.png
        ↓
C:\ProgramData\update.js
        ↓
wscript.exe

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
