# Windows Security Monitoring & Threat Detection

> Hands-on analysis of Windows security telemetry using Windows Event Logs
> and Sysmon to investigate suspicious endpoint activity.

## Overview

This project focuses on analyzing Windows security telemetry to identify
and investigate suspicious endpoint activity.

The investigation covers authentication events, process execution,
PowerShell activity, persistence, and network-related endpoint events.

The objective is to understand how Windows telemetry can be used by
a SOC analyst to detect and investigate potentially malicious behavior.

---

## Objectives

- Analyze Windows Security Event Logs
- Understand relevant Windows Event IDs
- Analyze Sysmon telemetry
- Investigate authentication activity
- Investigate process execution
- Analyze PowerShell activity
- Identify suspicious parent-child processes
- Investigate persistence mechanisms
- Correlate endpoint events
- Map findings to MITRE ATT&CK

---

## Tools & Technologies

- Windows Event Logs
- Windows Event Viewer
- Sysmon
- PowerShell
- Splunk / SIEM
- MITRE ATT&CK

---

# Investigation Methodology

```text
Endpoint Event
      ↓
Event ID Analysis
      ↓
Process / User Investigation
      ↓
Event Correlation
      ↓
Behavior Analysis
      ↓
MITRE ATT&CK Mapping
      ↓
Detection Opportunity

1. Authentication Activity
Objective
Investigate suspicious authentication activity using Windows Security
Event Logs.

Relevant Event IDs
Event ID	Description
4624	Successful logon
4625	Failed logon
[Event ID]	[Description]

Analysis
[Explain what you investigated.]

Key Findings
[Finding]
[Finding]
[Finding]
Evidence
[Add sanitized screenshot.]

Detection Opportunity
[Explain how this activity could be detected by a SOC.]

2. Process Creation
Objective
Investigate suspicious process execution using Sysmon telemetry.

Relevant Event
Sysmon Event ID 1 — Process Creation

Analysis
[Explain the investigation.]

Key Fields
Field	Value
Process	[Process]
Parent Process	[Parent]
Command Line	[Command]
User	[User]
Timestamp	[Timestamp]
Hash	[Hash]

Findings
[Explain what made the process suspicious.]

MITRE ATT&CK
Technique	Evidence
Txxxx	[Evidence]

3. PowerShell Investigation
Objective
Investigate suspicious PowerShell activity using Windows telemetry.

Relevant Telemetry
Process creation
PowerShell Script Block Logging
Command-line arguments
Parent-child process relationships
Network connections
Analysis
[Explain what you investigated.]

Findings
[Finding]
[Finding]
[Finding]
Detection Opportunities
Monitor suspicious PowerShell execution.
Detect encoded or obfuscated PowerShell commands.
Monitor unusual PowerShell parent-child relationships.
Correlate PowerShell execution with outbound network connections.
MITRE ATT&CK
Technique	Evidence
T1059.001	PowerShell activity

4. Persistence Investigation
Objective
Identify potential persistence mechanisms on the Windows endpoint.

Areas Investigated
Registry Run Keys
Scheduled Tasks
Windows Services
Startup locations
Suspicious processes
Analysis
[Explain what you investigated.]

Findings
[Describe findings.]

MITRE ATT&CK
Technique	Evidence
Txxxx	[Evidence]

5. Network Activity
Objective
Investigate network connections initiated by suspicious processes.

Analysis
[Explain how endpoint and network telemetry were correlated.]

Key Findings
Field	Value
Source Process	[Process]
Destination IP	[IP]
Destination Port	[Port]
Protocol	[Protocol]
Timestamp	[Timestamp]

Investigation
[Explain why the connection was suspicious or benign.]

Investigation Timeline
Time	Event	Source
[TIME]	Authentication event	Security Log
[TIME]	Process execution	Sysmon
[TIME]	PowerShell activity	PowerShell Log
[TIME]	Network connection	Sysmon / Network
[TIME]	[Event]	[Source]

MITRE ATT&CK Mapping
Tactic	Technique	Evidence
Execution	T1059.001	PowerShell
Persistence	Txxxx	[Evidence]
Discovery	Txxxx	[Evidence]
Command & Control	Txxxx	[Evidence]

Detection Opportunities
Authentication
Monitor repeated failed authentication attempts.
Detect suspicious successful logons following multiple failures.
Investigate unusual logon locations or times.
Process Execution
Monitor suspicious process creation.
Detect unusual parent-child process relationships.
Monitor execution from temporary or user-writable directories.
PowerShell
Monitor encoded commands.
Detect suspicious PowerShell execution.
Correlate PowerShell with network activity.
Persistence
Monitor new scheduled tasks.
Monitor suspicious registry modifications.
Detect newly created services.
Network
Monitor unusual outbound connections.
Correlate network connections with suspicious processes.
Investigate connections to known malicious infrastructure.
Investigation Summary
This project demonstrates the use of Windows security telemetry to
investigate suspicious endpoint behavior.

By correlating authentication events, process creation, PowerShell activity,
persistence indicators, and network connections, individual log events
can be connected to form a broader understanding of potential attack activity.

Key Skills Demonstrated
Windows Event Log Analysis
Sysmon Analysis
PowerShell Investigation
Process Analysis
Authentication Analysis
Endpoint Threat Detection
Event Correlation
MITRE ATT&CK
Security Monitoring
Lessons Learned
Windows Event Logs provide valuable evidence during incident investigations.
Sysmon provides additional visibility into process and network activity.
Event correlation is essential when investigating endpoint incidents.
Understanding normal Windows behavior helps identify anomalous activity.
References
TryHackMe — Windows Logging for SOC
Microsoft Windows Security Auditing
MITRE ATT&CK
