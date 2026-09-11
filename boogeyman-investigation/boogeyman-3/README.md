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
