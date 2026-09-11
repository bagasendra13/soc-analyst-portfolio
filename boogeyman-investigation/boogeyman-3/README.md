# Boogeyman 3 — The Chaos Inside

## Overview

This write-up documents my investigation of the **Boogeyman 3 — The Chaos Inside** challenge from TryHackMe.

The scenario simulates a post-compromise intrusion against **Quick Logistics LLC**, where the threat actors had already obtained initial access and remained undetected before attempting to expand their access.

The attacker subsequently targeted **Evan Hutchinson**, the CEO of Quick Logistics LLC, through a suspicious email containing an ISO attachment disguised as a financial report:

`ProjectFinancialSummary_Q3.pdf`

Although the attachment appeared suspicious, Evan opened it. The attachment contained an **HTML Application (HTA)** file that acted as the initial malicious payload. After opening the document and observing no obvious activity, Evan reported the email to the security team.

The security team determined that the incident occurred between **August 29 and August 30, 2023**.

For this investigation, I used the **Elastic Stack (ELK)** to search and correlate endpoint telemetry, primarily using **Sysmon** and **Windows event data**.

The investigation reconstructed the attack from initial payload execution through:

- Persistence
- Command and Control
- UAC bypass
- Credential dumping
- Pass-the-Hash
- Lateral movement
- DCSync
- Attempted ransomware deployment

## Investigation Objectives

The investigation focused on answering the following questions:

- Identify the process that executed the initial Stage 1 payload.
- Determine how the attacker implanted the payload into another location.
- Identify how the implanted file was executed.
- Identify the persistence mechanism established by the attacker.
- Identify the C2 IP address and port.
- Identify the process used for UAC bypass.
- Identify the GitHub resource used to download the credential dumping tool.
- Identify credentials obtained through credential dumping.
- Identify the remote file accessed by the attacker.
- Identify the credentials used for lateral movement.
- Identify the hostname targeted during lateral movement.
- Identify the process responsible for executing the remotely issued command.
- Identify credentials dumped from the second compromised workstation.
- Identify the account targeted through DCSync.
- Identify the ransomware binary download URL.
- Reconstruct the complete attack chain.
- Map the observed behaviors to MITRE ATT&CK techniques.

## Environment

| Category | Details |
|---|---|
| Platform | TryHackMe |
| Room | Boogeyman |
| Part | 3 |
| Task | The Chaos Inside |
| Analysis Platform | Elastic Stack (ELK) |
| Target Organization | Quick Logistics LLC |
| Target User | Evan Hutchinson |
| Initial Attachment | `ProjectFinancialSummary_Q3.pdf` |
| Attachment Type | ISO containing HTML Application |
| Incident Period | August 29–30, 2023 |
| Primary Telemetry | Sysmon / Windows Event Logs |

# Initial Execution and Payload Implantation

## 1. Initial Stage 1 Payload Analysis

### Objective

The first step was to identify the process responsible for executing the initial malicious payload.

Because the attachment was named:

`ProjectFinancialSummary_Q3.pdf`

I searched Elastic for:

`ProjectFinancialSummary_Q3*`

The search returned an event associated with the initial payload execution.

The process identifier was:

`PID: 6392`

The process also had three child processes, which became useful for correlating the subsequent stages of execution.

### Finding

The initial Stage 1 payload was executed by the process with:

`PID 6392`

The presence of multiple child processes indicated that the initial payload spawned additional processes responsible for subsequent malicious activity.

---

## 2. Payload Implantation

The next objective was to determine how the Stage 1 payload attempted to copy or implant a file to another location.

I continued investigating the events associated with the initial payload and examined the process message and command-line information.

The following command was identified:

```text
C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
```
The command used 'xcopy.exe' to copy:
```text
D:\review.dat
```
to:
```text
C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
```
The `xcopy.exe` process was a child process of the initial payload and had:
PID: `3832`
Analysis
The use of xcopy.exe allowed the malicious script to move review.dat from the mounted attachment environment to a writable temporary directory on the victim machine.

This provided the attacker with a copy of the malicious file outside the original attachment location.

Finding
The full command line used to implant the file was:
```bash
C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
```
