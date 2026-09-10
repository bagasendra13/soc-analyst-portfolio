# SIEM Alert Triage & Incident Investigation (Not Ready Yet)

> Hands-on SOC alert investigation using Splunk and SPL
> in a simulated security monitoring environment.

## Overview

This project focuses on the investigation and triage of simulated
security alerts using Splunk.

The investigation demonstrates the workflow of a SOC analyst:
reviewing alerts, querying security logs, correlating events,
identifying indicators of compromise, and determining the appropriate
classification and response.

---

## Objectives

- Investigate security alerts using Splunk
- Develop and execute SPL queries
- Analyze security logs
- Correlate events across time and data sources
- Identify Indicators of Compromise (IOCs)
- Investigate suspicious activity
- Classify alerts
- Map findings to MITRE ATT&CK
- Recommend appropriate response actions

---

## Tools & Technologies

- Splunk
- SPL (Search Processing Language)
- Security Logs
- MITRE ATT&CK

---

# SOC Investigation Workflow

```text
Security Alert
      ↓
Initial Triage
      ↓
Log Investigation
      ↓
Event Correlation
      ↓
IOC Analysis
      ↓
MITRE ATT&CK Mapping
      ↓
Alert Classification
      ↓
Response Recommendation

Investigation 1 — [Scenario Name]
Alert Overview
Field	Value
Alert	[Alert name]
Severity	[Severity]
Host	[Host]
User	[User]
Timestamp	[Timestamp]
Source	[Source]

Investigation Objective
[Describe what you need to determine.]

Initial Triage
Alert Context
[Explain what triggered the alert and why it requires investigation.]

Initial Questions
What happened?
Which host was affected?
Which user was involved?
When did the activity occur?
Is the activity expected or suspicious?
SPL Investigation
Query 1
[YOUR SPL QUERY]

Purpose
[Explain what this query searches for.]

Result
[Describe the important result.]

Query 2
[YOUR SPL QUERY]

Purpose
[Explain what this query searches for.]

Result
[Describe the important result.]

Event Correlation
[Explain how multiple events were correlated.]

Example areas to investigate:

Timestamp
Source IP
Destination IP
Username
Hostname
Process
Parent process
Command line
Authentication activity
Indicators of Compromise
Type	Indicator	Context
IP	[IP]	[Context]
Domain	[Domain]	[Context]
Username	[Username]	[Context]
Process	[Process]	[Context]
Hash	[Hash]	[Context]

MITRE ATT&CK Mapping
Tactic	Technique	Evidence
[Tactic]	Txxxx	[Evidence]
[Tactic]	Txxxx	[Evidence]

Alert Classification
Classification: [TRUE POSITIVE / FALSE POSITIVE / SUSPICIOUS]

Severity: [LOW / MEDIUM / HIGH / CRITICAL]

Reasoning
[Explain why the alert received this classification.]

Recommended Response
[Containment action]
[Investigation action]
[Monitoring action]
[Escalation action]
Investigation 2 — [Scenario Name]
Repeat the same structure:

Alert Overview
Investigation Objective
Initial Triage
SPL Investigation
Event Correlation
IOC Analysis
MITRE ATT&CK
Alert Classification
Recommended Response
Investigation 3 — [Scenario Name]
Repeat the same structure.

Detection Opportunities
Based on the investigation, the following detection opportunities
could be implemented:

Authentication
Detect multiple failed authentication attempts.
Detect suspicious successful authentication following repeated failures.
Process Execution
Monitor suspicious parent-child process relationships.
Detect execution of unusual binaries from suspicious directories.
Network Activity
Monitor connections to known malicious infrastructure.
Investigate unusual outbound connections from endpoints.
PowerShell
Monitor encoded PowerShell commands.
Detect PowerShell execution followed by external network communication.
Key Skills Demonstrated
SIEM Investigation
Splunk
SPL
Alert Triage
Log Analysis
Event Correlation
IOC Investigation
Incident Classification
MITRE ATT&CK
Security Monitoring
Lessons Learned
[Lesson 1]
[Lesson 2]
[Lesson 3]
References
TryHackMe — Alert Triage With Splunk
MITRE ATT&CK
