# SIEM Alert Triage & Incident Investigation

## Overview

This write-up documents my investigation of the **SIEM Alert Triage & Incident Investigation** task.

The scenario simulates the work of a **Level 1 SOC Analyst at a Managed Security Service Provider (MSSP)**. The investigation focuses on analyzing security alerts using **Splunk**, validating suspicious activity, correlating relevant log events, and determining whether the observed activity should be considered malicious.

The investigation was divided into three separate alert scenarios:

1. **Initial Access Alert**
2. **Persistence Alert**
3. **Web Shell Alert**

For each alert, I used Splunk to search and correlate relevant telemetry from multiple sources, including:

- Linux authentication logs
- Windows Security Event Logs
- Web server access logs
- Process creation and command-line information
- Authentication events
- Discovery activity
- Web request telemetry

The objective was not only to answer the questions associated with each alert, but also to understand the attacker behavior represented by the available telemetry.

---

# Investigation Objectives

The investigation focused on answering the following questions:

### Initial Access Alert

- Determine the number of failed login attempts against `john.smith`.
- Determine the duration of the brute-force attack.
- Identify the account to which the attacker escalated privileges.
- Identify the user account created for persistence.

### Persistence Alert

- Identify the Process ID of the process that created the malicious scheduled task.
- Identify the parent process of the task-creation process.
- Determine which local group the attacker enumerated.
- Identify the workstation from which the attacker logged into the compromised host.

### Web Shell Alert

- Determine when the Hydra brute-force activity began.
- Identify the user agent used to interact with the web shell.
- Determine the number of requests made through the web shell.

---

# Environment

| Category | Details |
|---|---|
| Platform | TryHackMe |
| Task | SIEM Alert Triage & Incident Investigation |
| Analysis Platform | Splunk |
| Role | L1 SOC Analyst / MSSP |
| Primary Log Sources | Linux Secure Logs / Windows Security Logs / Web Logs |
| Investigation Method | SIEM Search and Event Correlation |
| Subtasks | Initial Access / Persistence / Web Shell |

---

# Investigation

# 1. Initial Access Alert

## Alert Scenario

The first alert was received shortly after starting a shift as a SOC analyst at an MSSP.

The alert indicated possible brute-force activity against a Linux host.

### Alert Details

| Field | Value |
|---|---|
| Alert Name | Brute Force Activity Detection |
| Time | 17/09/2025 9:00:21 AM |
| Target Host | `tryhackme-2404` |
| Source IP | `10.10.242.248` |

The objective was to investigate this activity and determine whether it should be considered suspicious.

---

## 1.1 Failed Login Attempts

### Objective

The first step was to determine how many failed login attempts were made against the user:

    john.smith

I searched Splunk using:

    index="linux-alert" sourcetype="linux_secure" 10.10.242.248
    | search "Failed password for" user="john.smith"

The search returned:

    500 events

### Analysis

The events showed repeated failed authentication attempts originating from:

    10.10.242.248

and targeting:

    john.smith

The large number of failed login attempts from a single source IP was consistent with brute-force authentication activity.

### Finding

The attacker made:

    500 failed login attempts

against the account:

    john.smith

---

## 1.2 Brute-Force Duration

### Objective

The next step was to determine how long the brute-force activity continued.

I used the same search and sorted the events chronologically:

    index="linux-alert" sourcetype="linux_secure" 10.10.242.248
    | search "Failed password for" user="john.smith"
    | sort time

The resulting events showed that the brute-force activity spanned approximately:

    5 minutes

### Analysis

The activity consisted of repeated authentication failures over a relatively short period.

The combination of:

- 500 failed login attempts
- A single source IP
- A single targeted account
- Activity concentrated within approximately five minutes

strongly supported the classification of the alert as suspicious brute-force activity.

### Finding

The brute-force attack lasted approximately:

    5 minutes

---

## 1.3 Privilege Escalation

### Objective

After identifying the brute-force activity, I investigated events occurring after the attack to determine whether the attacker successfully gained access and escalated privileges.

I searched Splunk using:

    index="linux-alert" sourcetype="linux_secure" "sudo:" OR "Command="

I then reviewed timestamps following the brute-force activity.

One relevant event contained:

    sudo: ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su

### Analysis

The event shows that the `ubuntu` account executed `su` through `sudo` and switched to:

    USER=root

This indicates that the attacker was able to obtain root-level privileges after the initial authentication activity.

The privilege escalation chain can therefore be represented as:

    Initial Access
          ↓
    john.smith
          ↓
    Post-compromise activity
          ↓
    sudo / su
          ↓
         root

### Finding

The attacker was able to privilege escalate to:

    root

---

## 1.4 Persistence Account Creation

### Objective

After identifying successful privilege escalation, I investigated whether the attacker created a new account for persistence.

I searched Splunk using:

    index="linux-alert" sourcetype="linux_secure" john.smith AND "COMMAND=*adduser"

The search returned one relevant event:

    root : TTY=pts/2 ; PWD=/home/john.smith ; USER=root ; COMMAND=/usr/sbin/adduser system-utm

The command used:

    /usr/sbin/adduser system-utm

### Analysis

The event demonstrates that the attacker, operating with root privileges, created a new local user account.

The newly created account was:

    system-utm

Creating an additional user account after obtaining root privileges can provide the attacker with an alternative means of maintaining access to the system.

### Finding

The persistence account created by the attacker was:

    system-utm

---

## 1.5 Initial Access Investigation Summary

The investigation reconstructed the following activity:

    Source IP
    10.10.242.248
          │
          ▼
    Brute-Force Attack
          │
          ▼
    500 Failed Login Attempts
          │
          ▼
    Target: john.smith
          │
          ▼
    Successful Access
          │
          ▼
    Privilege Escalation
          │
          ▼
         root
          │
          ▼
    Account Creation
          │
          ▼
      system-utm

### Finding

The alert was determined to be **suspicious** and consistent with a brute-force attack followed by privilege escalation and persistence.

---

# 2. Persistence Alert

## Alert Scenario

The second alert involved suspicious scheduled task creation on a Windows workstation.

### Alert Details

| Field | Value |
|---|---|
| Alert Name | Potential Task Scheduler Persistence Identified |
| Time | 30/08/2025 10:06:07 AM |
| Host | `WIN-H015` |
| User | `oliver.thompson` |
| Task Name | `AssessmentTaskOne` |

The objective was to investigate the scheduled task and determine whether the surrounding activity was suspicious.

---

## 2.1 Process ID of the Task-Creation Process

### Objective

The first step was to identify the process responsible for creating the scheduled task.

I searched Splunk using:

    index="win-alert" EventCode=4698

The search returned a relevant Windows Security Event Log:

    08/30/2025 10:06:07 AM
    LogName=Security
    EventCode=4698
    EventType=0
    ComputerName=WIN-H015
    ClientProcessId=5816
    ParentProcessId=4128
    host=WIN-H015
    source=WinEventLog:Security
    sourcetype=WinEventLog

Windows Event ID `4698` is associated with the creation of a scheduled task.

The event identified:

    ClientProcessId = 5816

### Finding

The Process ID responsible for creating the malicious scheduled task was:

    5816

---

## 2.2 Parent Process

### Objective

The next step was to identify the parent process associated with PID `5816`.

I searched using:

    index="win-alert" ParentProcessId=4128

The search returned multiple events, including the relevant parent command line:

    ParentCommandLine
    "C:\Windows\system32\cmd.exe"

### Analysis

The process hierarchy can therefore be represented as:

    cmd.exe
       │
       ▼
    PID 5816
       │
       ▼
    Scheduled Task Creation

This indicates that the task creation activity originated from a Windows Command Prompt process.

### Finding

The parent process was:

    cmd.exe

---

## 2.3 Local Group Enumeration

### Objective

I then investigated discovery activity associated with the compromised user:

    oliver.thompson

The objective was to determine which local group the attacker enumerated.

I searched using:

    index="win-alert" EventCode=4799 user_name="oliver.thompson"
    | table _time ComputerName user_name Group_Name

The resulting event showed:

    Group_Name = Administrator

### Analysis

Windows Event ID `4799` is associated with the enumeration of local group membership.

The attacker specifically enumerated the:

    Administrator

local group.

This behavior is consistent with local account and privilege discovery.

### Finding

The local group enumerated by the attacker was:

    Administrator

---

## 2.4 Source Workstation Identification

### Objective

The final step for this alert was to determine the workstation from which the threat actor logged into:

    WIN-H015

I searched Splunk using:

    index="win-alert" EventCode=4625 ComputerName=WIN-H015
    EventCode=4624 OR EventCode=4625
    | table _time ComputerName Account_Name Logon_Type
    Source_Network_Address Workstation_Name

The relevant event showed:

    Workstation_Name = DEV-QA-SERVER

### Analysis

The `Workstation_Name` field identifies the workstation associated with the authentication activity.

The evidence therefore indicates that the threat actor logged into:

    WIN-H015

from:

    DEV-QA-SERVER

### Finding

The source workstation was:

    DEV-QA-SERVER

---

## 2.5 Persistence Investigation Summary

The investigation reconstructed the following activity:

    Threat Actor
          │
          ▼
    DEV-QA-SERVER
          │
          ▼
    Authentication to WIN-H015
          │
          ▼
    oliver.thompson
          │
          ▼
    Local Group Enumeration
          │
          ▼
    Administrator
          │
          ▼
    cmd.exe
          │
          ▼
    PID 5816
          │
          ▼
    Scheduled Task Creation
          │
          ▼
    AssessmentTaskOne

### Finding

The scheduled task activity was considered suspicious because it was associated with a potentially malicious task creation event and additional discovery activity on the affected host.

# 3. Web Shell Alert

## Alert Scenario

The third alert involved suspicious web activity and a potential web shell upload.

### Alert Details

| Field | Value |
|---|---|
| Alert Name | Potential Web Shell Upload Detected |
| Time | 14/09/2025 09:31:51 AM |
| Resource | `http://web.trywinme.thm` |
| Suspicious IP | `171.251.232.40` |

The objective was to investigate the web traffic associated with the suspicious IP address and determine whether the activity should be considered suspicious.

---

## 3.1 Hydra Brute-Force Start Time

### Objective

The first step was to determine when the attacker began brute-forcing the web application using Hydra.

I searched Splunk using:

    index=web-alert 171.251.232.40 useragent="Mozilla/5.0 (Hydra)"
    | table _time clientip useragent uri_path method status
    | sort + _time

The earliest relevant event was:

    2025-09-14 21:20:27
    171.251.232.40
    Mozilla/5.0 (Hydra)
    /wp-login.php
    GET
    200

### Analysis

The user agent:

    Mozilla/5.0 (Hydra)

indicates that the requests were generated by Hydra, a tool commonly used for password brute-force attacks.

The earliest event identified in the search represents the beginning of the observed brute-force activity.

The attacker targeted:

    /wp-login.php

which is the WordPress login endpoint.

### Finding

The Hydra brute-force activity began at:

    2025-09-14 21:20:27

---

## 3.2 Web Shell User Agent

### Objective

After identifying the brute-force activity, I investigated how the attacker interacted with the suspected web shell.

I searched Splunk using:

    index=web-alert 171.251.232.40 b374k.php
    | table _time clientip useragent uri_path referer referer_domain method status
    | sort + _time

The events associated with:

    b374k.php

showed the following user agent:

    Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    AppleWebKit/537.36
    (KHTML, like Gecko)
    Chrome/138.0.0.0 Safari/537.36

### Analysis

The web shell was accessed using a browser-like Chrome user agent rather than the earlier Hydra user agent.

The change in user agent suggests a transition from automated brute-force activity to interactive web-shell usage.

The suspected web shell was:

    b374k.php

The presence of a PHP file associated with multiple requests from the suspicious IP provided additional context for the web shell alert.

### Finding

The user agent used to interact with the web shell was:

    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
    (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36

---

## 3.3 Number of Web Shell Requests

### Objective

The final objective was to determine how many requests the attacker made to the server through the web shell.

I searched Splunk using:

    index=web-alert 171.251.232.40 b374k.php method="POST"
    | table _time clientip useragent uri_path referer referer_domain method status
    | sort + _time

The search returned:

    4 events

### Analysis

The four POST requests associated with:

    b374k.php

indicate that the attacker interacted with the web shell four times.

POST requests are particularly relevant in this context because web shells commonly receive commands or parameters through HTTP requests.

### Finding

The attacker made:

    4 requests

through the web shell.

---

## 3.4 Web Shell Investigation Summary

The observed activity can be reconstructed as:

    Attacker
    171.251.232.40
          │
          ▼
    Hydra Brute Force
          │
          ▼
    /wp-login.php
          │
          ▼
    2025-09-14 21:20:27
          │
          ▼
    Web Application Access
          │
          ▼
    b374k.php
          │
          ▼
    Chrome User Agent
          │
          ▼
    4 POST Requests
          │
          ▼
    Web Shell Interaction

### Finding

The alert was considered suspicious due to the combination of automated brute-force activity, subsequent interaction with a suspected web shell, and multiple POST requests to the web-shell endpoint.

---

# Attack Timeline

## Initial Access Alert

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Brute-force activity detected | `10.10.242.248` | Suspicious authentication source |
| 2 | Failed authentication | `john.smith` | 500 failed attempts |
| 3 | Brute-force continued | ~5 minutes | High-volume authentication attempts |
| 4 | Privilege escalation | `USER=root` | Root access obtained |
| 5 | Persistence | `adduser system-utm` | New account created |

---

## Persistence Alert

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Scheduled task created | Event ID `4698` | Suspicious persistence activity |
| 2 | Process identified | PID `5816` | Task-creation process |
| 3 | Parent identified | `cmd.exe` | Parent of task-creation process |
| 4 | Discovery | `Administrator` | Local group enumeration |
| 5 | Remote login source | `DEV-QA-SERVER` | Source workstation |

---

## Web Shell Alert

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Hydra activity | `Mozilla/5.0 (Hydra)` | Automated brute-force |
| 2 | Initial web target | `/wp-login.php` | Web authentication endpoint |
| 3 | Brute-force begins | `2025-09-14 21:20:27` | Earliest observed event |
| 4 | Web shell accessed | `b374k.php` | Suspected web shell |
| 5 | Browser interaction | Chrome 138 User Agent | Interactive web-shell activity |
| 6 | POST requests | `4 events` | Requests through web shell |

---

# Indicators of Compromise

> The following indicators were identified during the investigation within the simulated environment.

| Type | Value | Description |
|---|---|---|
| Source IP | `10.10.242.248` | Source of Linux brute-force activity |
| Target Host | `tryhackme-2404` | Linux host targeted by brute force |
| Target User | `john.smith` | Account targeted by authentication attempts |
| Failed Logins | `500` | Number of failed login attempts |
| Duration | `~5 minutes` | Approximate brute-force duration |
| Privileged Account | `root` | Account reached after privilege escalation |
| Persistence Account | `system-utm` | Account created by attacker |
| Windows Host | `WIN-H015` | Host targeted by scheduled-task activity |
| Windows User | `oliver.thompson` | User associated with persistence alert |
| Scheduled Task | `AssessmentTaskOne` | Suspicious scheduled task |
| Process ID | `5816` | Process that created the task |
| Parent Process | `cmd.exe` | Parent process |
| Enumerated Group | `Administrator` | Local group enumerated |
| Source Workstation | `DEV-QA-SERVER` | Workstation associated with login |
| Web Source IP | `171.251.232.40` | Suspicious web attacker IP |
| Hydra User Agent | `Mozilla/5.0 (Hydra)` | User agent used for brute force |
| Web Target | `/wp-login.php` | Web authentication endpoint |
| Web Shell | `b374k.php` | Suspected web shell |
| Web Shell User Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36` | User agent used to interact with web shell |
| Web Shell Requests | `4` | POST requests through web shell |
| Resource | `http://web.trywinme.thm` | Target web resource |

---

# MITRE ATT&CK Mapping

> The following mappings are based on the behaviors observed in the available SIEM telemetry.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | 500 failed login attempts against `john.smith` |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | `sudo` followed by `su` to `root` |
| Persistence | Create Account | T1136 | `adduser system-utm` |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled task `AssessmentTaskOne` |
| Discovery | Permission Groups Discovery: Local Groups | T1069.001 | Enumeration of `Administrator` group |
| Initial Access | Valid Accounts | T1078 | Successful access following brute-force activity |
| Initial Access | Exploit Public-Facing Application | T1190 | Web shell-related compromise |
| Credential Access | Brute Force | T1110 | Hydra activity against `/wp-login.php` |
| Persistence | Server Software Component: Web Shell | T1505.003 | Interaction with `b374k.php` |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP communication with web application |

---

# Alert Classification

## Initial Access Alert

**Classification: Suspicious / True Positive**

The alert was supported by:

- 500 failed authentication attempts.
- A single suspicious source IP.
- Targeting of the `john.smith` account.
- Approximately five minutes of concentrated brute-force activity.
- Subsequent privilege escalation to `root`.
- Creation of the `system-utm` account.

The combination of these events strongly indicates malicious authentication activity rather than normal user behavior.

---

## Persistence Alert

**Classification: Suspicious / True Positive**

The alert was supported by:

- Scheduled Task creation.
- Windows Event ID `4698`.
- Process ID `5816`.
- `cmd.exe` as the parent process.
- Local Administrator group enumeration.
- Authentication activity associated with `DEV-QA-SERVER`.

The presence of scheduled-task creation combined with discovery and authentication activity increases confidence that the event represented malicious persistence.

---

## Web Shell Alert

**Classification: Suspicious / True Positive**

The alert was supported by:

- Hydra-based brute-force activity.
- Requests originating from `171.251.232.40`.
- Access to `/wp-login.php`.
- Subsequent interaction with `b374k.php`.
- Browser-based interaction with the suspected web shell.
- Four POST requests to the web-shell endpoint.

The sequence is consistent with an attacker progressing from web authentication brute force toward web-shell interaction.

# Overall Investigation Narrative

The three alert investigations demonstrate several attacker behaviors across Linux, Windows, and web environments.

The first scenario began with a brute-force attack against a Linux system. The attacker generated a large number of failed authentication attempts against the `john.smith` account from the source IP `10.10.242.248`.

The investigation identified:

    500 Failed Login Attempts
            │
            ▼
    Approximately 5 Minutes
            │
            ▼
    Target: john.smith
            │
            ▼
    Privilege Escalation
            │
            ▼
           root
            │
            ▼
    Account Creation
            │
            ▼
        system-utm

This demonstrates how an initial brute-force alert can lead to evidence of successful compromise, privilege escalation, and persistence.

The second scenario involved a suspicious scheduled task on the Windows host `WIN-H015`.

The investigation identified:

    Authentication Activity
            │
            ▼
    WIN-H015
            │
            ▼
    oliver.thompson
            │
            ▼
    Local Group Enumeration
            │
            ▼
       Administrator
            │
            ▼
         cmd.exe
            │
            ▼
       Process ID 5816
            │
            ▼
    AssessmentTaskOne

The presence of Windows Event ID `4698` provided evidence of scheduled task creation. Additional telemetry identified `cmd.exe` as the parent process and `Administrator` as the local group enumerated by the attacker.

The third scenario involved suspicious web activity from `171.251.232.40`.

The investigation identified:

    Attacker
    171.251.232.40
            │
            ▼
    Hydra Brute Force
            │
            ▼
    /wp-login.php
            │
            ▼
    2025-09-14 21:20:27
            │
            ▼
    b374k.php
            │
            ▼
    Chrome User Agent
            │
            ▼
    4 POST Requests
            │
            ▼
    Web Shell Interaction

The combination of automated Hydra activity followed by interaction with `b374k.php` strongly supported the classification of the alert as suspicious.

---

# Investigation Conclusion

The **SIEM Alert Triage & Incident Investigation** task demonstrated the process of investigating multiple security alerts using **Splunk**.

The investigation covered three different alert scenarios:

- Initial Access Alert
- Persistence Alert
- Web Shell Alert

The **Initial Access Alert** identified a brute-force attack against the `john.smith` account. A total of **500 failed login attempts** were observed over approximately **five minutes** from the source IP `10.10.242.248`.

Further investigation revealed that the attacker was able to escalate privileges to:

    root

The attacker then created a new account:

    system-utm

This account creation provided evidence of an attempt to establish persistence following successful compromise.

The **Persistence Alert** identified suspicious scheduled task creation on:

    WIN-H015

Windows Event ID `4698` showed that the scheduled task:

    AssessmentTaskOne

was created by the process with:

    PID 5816

The parent process was identified as:

    cmd.exe

Additional discovery activity showed that the attacker enumerated the:

    Administrator

local group.

Authentication telemetry also identified:

    DEV-QA-SERVER

as the workstation associated with the login activity.

The **Web Shell Alert** identified suspicious activity originating from:

    171.251.232.40

The attacker used Hydra to perform brute-force activity against:

    /wp-login.php

The earliest observed Hydra activity began at:

    2025-09-14 21:20:27

The attacker subsequently interacted with:

    b374k.php

using the following user agent:

    Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    AppleWebKit/537.36
    (KHTML, like Gecko)
    Chrome/138.0.0.0 Safari/537.36

A total of:

    4 POST requests

were observed against the suspected web shell.

Overall, the investigation demonstrated that effective SIEM alert triage requires more than simply identifying the event that triggered an alert.

A SOC analyst must correlate the alert with surrounding telemetry to determine:

    What happened?
          ↓
    Who performed the activity?
          ↓
    Which system was affected?
          ↓
    How did the attacker gain access?
          ↓
    What happened after initial access?
          ↓
    Was persistence established?
          ↓
    Did the attacker move or escalate privileges?
          ↓
    What evidence supports the incident classification?

The investigation therefore followed the general SOC workflow:

    Alert Detection
          ↓
    Alert Validation
          ↓
    SIEM Querying
          ↓
    Event Correlation
          ↓
    Threat Identification
          ↓
    Timeline Reconstruction
          ↓
    IOC Identification
          ↓
    MITRE ATT&CK Mapping
          ↓
    Incident Classification

---

# Recommended SOC Response Actions

Based on the observed activity, the following response actions would be appropriate in a real-world environment.

## Immediate Containment

- Isolate affected systems from the network.
- Block confirmed malicious source IP addresses.
- Disable or temporarily restrict compromised accounts.
- Terminate suspicious processes.
- Remove unauthorized persistence mechanisms.
- Block suspicious web-shell files and URLs.

## Credential Protection

- Reset credentials associated with compromised accounts.
- Investigate potential credential reuse.
- Review privileged accounts for unauthorized activity.
- Invalidate active sessions where applicable.

## Persistence Removal

For the Linux system:

- Investigate and remove the unauthorized `system-utm` account.
- Review `/etc/passwd` and `/etc/shadow`.
- Check SSH authorized keys.
- Review cron jobs and startup mechanisms.

For the Windows system:

- Investigate and remove `AssessmentTaskOne` if confirmed malicious.
- Review scheduled tasks for additional persistence.
- Investigate other processes spawned by `cmd.exe`.
- Review local group membership and account changes.

For the web server:

- Isolate the affected web application if necessary.
- Remove the suspected `b374k.php` web shell.
- Review other PHP files for unauthorized modifications.
- Reset affected web application credentials.
- Investigate the initial compromise vector.

## Further Investigation

- Search the SIEM for `10.10.242.248` across all indexes.
- Search the SIEM for `171.251.232.40` across all web telemetry.
- Search for `system-utm` across the Linux environment.
- Search for `AssessmentTaskOne` across Windows hosts.
- Search for `b374k.php` across web server logs.
- Investigate authentication activity before and after the alerts.
- Search for additional hosts associated with the suspicious source systems.
- Review historical logs for similar indicators.

## Monitoring

After containment, continued monitoring should be performed for:

- Repeated brute-force attempts.
- Reuse of compromised usernames.
- New unauthorized accounts.
- Suspicious scheduled tasks.
- Unauthorized web files.
- Repeated access to the web shell.
- Connections from known malicious IP addresses.
- Additional authentication anomalies.

---

# Skills Demonstrated

- SIEM Alert Triage
- Splunk Investigation
- Splunk Search Processing Language (SPL)
- Security Alert Validation
- True Positive / False Positive Analysis
- Linux Authentication Log Analysis
- Windows Security Event Log Analysis
- Web Server Log Analysis
- Brute-Force Detection
- Authentication Analysis
- Privilege Escalation Investigation
- Persistence Investigation
- Scheduled Task Investigation
- Local Group Enumeration Analysis
- Process ID Correlation
- Parent-Child Process Analysis
- Command-Line Analysis
- Web Shell Investigation
- Hydra Activity Analysis
- Web Request Analysis
- IOC Identification
- Timeline Reconstruction
- Attack Chain Reconstruction
- MITRE ATT&CK Mapping
- Incident Severity Assessment
- SOC Investigation Workflow

---

# Lessons Learned

- SIEM alerts should be treated as starting points for investigation rather than complete explanations of an incident.
- A high number of failed authentication attempts from a single source can be a strong indicator of brute-force activity.
- Authentication events should be correlated with subsequent activity to determine whether the attacker successfully gained access.
- Privilege escalation occurring after brute-force activity can provide additional evidence of successful compromise.
- Creating a new account after obtaining elevated privileges can indicate an attempt to establish persistence.
- Windows Event ID `4698` is useful for identifying scheduled task creation.
- Process IDs and parent process information can help reconstruct how suspicious activity was initiated.
- Windows group enumeration can provide insight into an attacker's discovery activities.
- Authentication events can help identify the workstation associated with suspicious login activity.
- Web access logs can reveal the transition from automated brute-force activity to interactive attacker behavior.
- User-agent analysis can help distinguish automated tools such as Hydra from browser-based interaction.
- Multiple POST requests to a suspected web shell can provide evidence of attacker interaction with the compromised web application.
- Correlating events across different log sources is essential for identifying the broader context of an incident.
- Searching for the same IOC across multiple indexes can help determine whether the activity affected additional systems.
- Splunk provides an effective platform for searching, filtering, correlating, and analyzing security telemetry during incident response.
- A strong SOC investigation should explain not only **why an alert fired**, but also **what happened before and after the alert**.

---

# Final Investigation Summary

    ┌─────────────────────────────────┐
    │          SIEM ALERTS            │
    └───────────────┬─────────────────┘
                    │
        ┌───────────┼───────────────┐
        │           │               │
        ▼           ▼               ▼
    Initial      Persistence     Web Shell
    Access         Alert           Alert
        │           │               │
        ▼           ▼               ▼
    Brute Force  Scheduled Task    Hydra
        │           │               │
        ▼           ▼               ▼
    500 Failed   AssessmentTaskOne  /wp-login.php
    Logins           │               │
        │            ▼               ▼
        ▼          cmd.exe        b374k.php
      root           │               │
        │            ▼               ▼
        ▼        PID 5816        Chrome UA
    system-utm      │               │
                     ▼               ▼
               Administrator    4 POST Requests
               Enumeration           │
                     │               ▼
                     ▼          Web Shell
                DEV-QA-SERVER     Interaction

---

# Final Findings

## Initial Access Alert

    Failed Login Attempts:
    500

    Brute-Force Duration:
    Approximately 5 minutes

    Privilege Escalation:
    root

    Persistence Account:
    system-utm

    Source IP:
    10.10.242.248

    Target Host:
    tryhackme-2404

    Target User:
    john.smith

---

## Persistence Alert

    Process ID:
    5816

    Parent Process:
    cmd.exe

    Scheduled Task:
    AssessmentTaskOne

    Host:
    WIN-H015

    User:
    oliver.thompson

    Enumerated Local Group:
    Administrator

    Source Workstation:
    DEV-QA-SERVER

---

## Web Shell Alert

    Suspicious IP:
    171.251.232.40

    Hydra Start Time:
    2025-09-14 21:20:27

    Initial Web Target:
    /wp-login.php

    Web Shell:
    b374k.php

    Web Shell User Agent:
    Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    AppleWebKit/537.36 (KHTML, like Gecko)
    Chrome/138.0.0.0 Safari/537.36

    Web Shell Requests:
    4 POST requests

---

# Final Conclusion

The investigation successfully demonstrated the use of **Splunk for SIEM alert triage and incident investigation** across Linux, Windows, and web environments.

The three scenarios showed different stages and techniques commonly encountered by SOC analysts:

    Brute Force
          ↓
    Successful Access
          ↓
    Privilege Escalation
          ↓
    Account Persistence

and:

    Suspicious Login
          ↓
    Discovery
          ↓
    Process Analysis
          ↓
    Scheduled Task Persistence

as well as:

    Web Brute Force
          ↓
    Successful Web Access
          ↓
    Web Shell Interaction
          ↓
    Remote Command Execution Potential

The investigation highlights the importance of using Splunk not only to locate the event associated with an alert, but also to correlate surrounding events and establish a complete understanding of the activity.

By combining authentication logs, Windows Security events, process information, and web server telemetry, it was possible to identify the suspicious source, affected accounts, affected systems, persistence mechanisms, and web-shell activity.

This investigation demonstrates a practical SOC workflow:

    Detect
      ↓
    Triage
      ↓
    Validate
      ↓
    Investigate
      ↓
    Correlate
      ↓
    Identify IOCs
      ↓
    Map to MITRE ATT&CK
      ↓
    Assess Severity
      ↓
    Contain
      ↓
    Remediate
      ↓
    Monitor
