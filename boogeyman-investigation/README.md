
Investigation
Boogeyman 1
1. Initial Access — Phishing
Objective
Identify the source of the phishing email and analyze its characteristics.

Analysis
The investigation started by analyzing dump.eml.

The email headers were reviewed to identify the sender, recipient,
mail infrastructure, and suspicious domains.

The phishing email used an unpaid invoice theme and targeted a finance
employee.

Key Findings
Phishing theme: Unpaid invoice
Target department: Finance
Victim: Julianne
Malicious attachment: Encrypted ZIP archive
Extracted file: Invoice_20230103.lnk
Mail relay: Elastic Email
Sender infrastructure: Suspicious external infrastructure
Evidence
Add screenshot here.

screenshots/boogeyman-1-email-header.png

MITRE ATT&CK
T1566.001 — Phishing: Spearphishing Attachment
T1204.002 — User Execution: Malicious File
2. Execution — Malicious LNK
Objective
Analyze the malicious LNK file and identify the payload executed
when the victim opened the attachment.

Analysis
The encrypted ZIP archive was extracted and the contained LNK file
was analyzed using LNKParse3.

The LNK command-line arguments contained an encoded PowerShell payload.

Key Findings
File: Invoice_20230103.lnk
File type: Windows Shortcut
Payload: PowerShell
Encoding: Base64
Execution method: PowerShell
Analysis Method
LNKParse3 was used to extract metadata and command-line arguments
from the malicious shortcut.

The encoded PowerShell command was then decoded using CyberChef
or the Linux base64 utility.

Example Workflow
lnkparse Invoice_20230103.lnk

Decode Base64:

echo "<BASE64_PAYLOAD>" | base64 -d

Evidence
Add screenshot here.

screenshots/boogeyman-1-lnkparse.png
screenshots/boogeyman-1-powershell-decode.png

MITRE ATT&CK
T1204.002 — User Execution: Malicious File
T1059.001 — Command and Scripting Interpreter: PowerShell
T1027 — Obfuscated/Compressed Files and Information
3. PowerShell Activity
Objective
Investigate PowerShell activity following execution of the malicious LNK.

Analysis
PowerShell logs were analyzed to identify:

Commands executed by the attacker
External network connections
Downloaded payloads
Endpoint discovery activity
Additional attacker tooling
Command-line tools such as jq, grep, and sed were used to filter
the available logs.

Key Findings
The attacker used PowerShell to download additional payloads from
attacker-controlled infrastructure.

Observed infrastructure included:

cdn.bpakcaging.xyz
files.bpakcaging.xyz

The attacker also downloaded Seatbelt for endpoint enumeration.

Evidence
Add screenshot here.

screenshots/boogeyman-1-powershell.png

MITRE ATT&CK
T1059.001 — Command and Scripting Interpreter: PowerShell
T1105 — Ingress Tool Transfer
T1027 — Obfuscated/Compressed Files and Information
4. Discovery & Enumeration
Objective
Identify information gathered by the attacker after gaining access
to the workstation.

Analysis
PowerShell logs were searched for enumeration commands and downloaded
utilities.

The investigation identified Seatbelt being downloaded and executed.

The attacker also used sq3.exe to interact with a SQLite database
associated with Microsoft Sticky Notes.

Key Findings
Enumeration tool: Seatbelt
SQLite utility: sq3.exe
Database: plum.sqlite
Associated application: Microsoft Sticky Notes
Database location:

C:\Users\j.westcott\AppData\Local\Packages\
Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\
LocalState\plum.sqlite

Evidence
Add screenshot here.

screenshots/boogeyman-1-discovery.png

MITRE ATT&CK
T1083 — File and Directory Discovery
T1012 — Query Registry
T1105 — Ingress Tool Transfer
Only map techniques that are directly supported by the available
evidence.

5. Collection — Sensitive Data
Objective
Identify sensitive information accessed by the attacker.

Analysis
The investigation revealed that the attacker accessed a KeePass
database containing sensitive information.

Key Findings
protected_data.kdbx

File type:

KeePass Database

The file was targeted for subsequent exfiltration.

Sensitive contents are intentionally excluded from this report.

Evidence
Add sanitized screenshot here.

screenshots/boogeyman-1-keepass.png

MITRE ATT&CK
T1005 — Data from Local System
6. Command & Control
Objective
Identify attacker-controlled infrastructure and the communication
protocol used for C2.

Analysis
Network traffic was analyzed using Wireshark.

HTTP traffic revealed communication between the compromised workstation
and attacker-controlled infrastructure.

Key Findings
Attribute	Finding
C2 Domain	cdn.bpakcaging.xyz
File Server	files.bpakcaging.xyz
Protocol	HTTP
HTTP Method	POST
Server Software	Python

Evidence
Add Wireshark screenshot here.

screenshots/boogeyman-1-c2.png

MITRE ATT&CK
T1071.001 — Application Layer Protocol: Web Protocols
T1105 — Ingress Tool Transfer
7. Data Exfiltration — DNS
Objective
Determine how sensitive data was exfiltrated from the compromised
workstation.

Analysis
The investigation identified DNS-based data exfiltration.

The sensitive file was converted into hexadecimal data, split into
smaller chunks, and transmitted through DNS queries.

The attacker used nslookup as part of the exfiltration mechanism.

Key Findings
Attribute	Finding
Exfiltrated File	protected_data.kdbx
Encoding	Hexadecimal
Protocol	DNS
Tool	nslookup

Analysis
Wireshark and Tshark were used to identify suspicious DNS queries
and reconstruct the transferred data.

Example filtering:

tshark -r capture.pcapng -Y "dns"

Evidence
Add Wireshark/Tshark screenshot here.

screenshots/boogeyman-1-dns-exfiltration.png

MITRE ATT&CK
T1048.003 — Exfiltration Over Alternative Protocol
T1071.004 — Application Layer Protocol: DNS
Boogeyman 2
1. Initial Access — Malicious Resume
Objective
Identify the initial access vector used in the second incident.

Analysis
The attacker sent a phishing email containing a malicious resume
targeting an HR employee.

Key Findings
Target: Maxine
Department: Human Resources
Sender: westaylor23@outlook.com
Attachment: Resume_WesleyTaylor.doc
File hash:

52c4384a0b9e248b95804352ebec6c5b

Evidence
Add screenshot here.

screenshots/boogeyman-2-email.png

MITRE ATT&CK
T1566.001 — Phishing: Spearphishing Attachment
T1204.002 — User Execution: Malicious File
2. Execution — VBA Macro
Objective
Determine how the malicious Word document downloaded the next-stage
payload.

Analysis
The Word document was analyzed using olevba.

The embedded VBA macro downloaded a JavaScript payload from attacker-
controlled infrastructure.

The downloaded file was saved as:

C:\ProgramData\update.js

The JavaScript payload was executed through:

wscript.exe

Key Findings
Word Document
      ↓
VBA Macro
      ↓
Download update.js
      ↓
wscript.exe
      ↓
Next Stage

Evidence
Add OleVBA screenshot here.

screenshots/boogeyman-2-olevba.png

MITRE ATT&CK
T1204.002 — User Execution: Malicious File
T1059.007 — Command and Scripting Interpreter: JavaScript
T1105 — Ingress Tool Transfer
3. Memory Forensics
Objective
Use memory forensics to reconstruct the process execution chain.

Analysis
Volatility 3 was used to investigate the provided memory dump.

The process tree revealed the relationship between Microsoft Word,
wscript.exe, and the next-stage payload.

Process Chain
WINWORD.EXE
    ↓
wscript.exe
    ↓
updater.exe

Key Findings
Artifact	Finding
Script	C:\ProgramData\update.js
Script Host	wscript.exe
Payload	updater.exe
Script PID	4260
Parent PID	1124

Example Analysis
python3 vol.py -f memory.dmp windows.pstree

Network connections:

python3 vol.py -f memory.dmp windows.netscan

Evidence
screenshots/boogeyman-2-pstree.png
screenshots/boogeyman-2-netscan.png

MITRE ATT&CK
T1059.007 — JavaScript
T1105 — Ingress Tool Transfer
4. Malware Download & C2
Objective
Identify the final payload and C2 infrastructure.

Key Findings
The JavaScript stage downloaded:

update.exe

The payload was stored as:

C:\Windows\Tasks\updater.exe

The malicious process established a connection to:

128.199.95.189:8080

Attack Chain
Resume_WesleyTaylor.doc
          ↓
       VBA Macro
          ↓
       update.js
          ↓
      wscript.exe
          ↓
      updater.exe
          ↓
   128.199.95.189:8080

MITRE ATT&CK
T1105 — Ingress Tool Transfer
T1071.001 — Application Layer Protocol: Web Protocols
5. Persistence — Scheduled Task
Objective
Identify how the attacker maintained persistence.

Analysis
The attacker created a scheduled task named:

Updater

The task was configured to execute PowerShell on a daily schedule.

Key Finding
Updater

Persistence mechanism:

Scheduled Task
        ↓
    PowerShell
        ↓
Encoded Payload

Evidence
screenshots/boogeyman-2-persistence.png

MITRE ATT&CK
T1053.005 — Scheduled Task/Job: Scheduled Task
T1059.001 — PowerShell
T1027 — Obfuscated/Compressed Files and Information
Boogeyman 3
1. Initial Access — Spearphishing
Objective
Identify the initial access vector used in the third incident.

Analysis
The attacker delivered a phishing attachment disguised as a
financial PDF.

The file appeared as:

ProjectFinancialSummary_Q3.pdf

Further investigation revealed that the attachment contained an
HTA payload.

Key Finding
The malicious HTA content was executed using:

mshta.exe

Attack Chain
Phishing Email
      ↓
ISO Attachment
      ↓
HTA Payload
      ↓
mshta.exe

MITRE ATT&CK
T1566.001 — Phishing: Spearphishing Attachment
T1204.002 — User Execution: Malicious File
T1218.005 — System Binary Proxy Execution: Mshta
2. Stage 1 Payload & Persistence
Objective
Determine what the first-stage payload did after execution.

Analysis
The stage 1 payload performed several actions:

mshta.exe
    ↓
Stage 1 Payload
    ↓
xcopy
    ↓
review.dat
    ↓
rundll32.exe
    ↓
Scheduled Task

The attacker used legitimate Windows utilities as part of the execution
and persistence chain.

Key Findings
mshta.exe
xcopy
review.dat
rundll32.exe
Scheduled Task
PowerShell
MITRE ATT&CK
T1218.005 — Mshta
T1218.011 — Rundll32
T1053.005 — Scheduled Task/Job
T1059.001 — PowerShell
3. Command & Control
Objective
Identify the C2 infrastructure used by the attacker.

Analysis
Sysmon Event ID 3 was investigated to identify outbound network
connections from the compromised workstation.

Key Findings
C2 Domain:
cdn.bananapeelparty.net

C2 IP:
165.232.170.151

Port:
80

Evidence
Add Kibana screenshot here.

screenshots/boogeyman-3-c2.png

MITRE ATT&CK
T1071.001 — Application Layer Protocol: Web Protocols
T1105 — Ingress Tool Transfer
4. Privilege Escalation — UAC Bypass
Objective
Determine how the attacker bypassed User Account Control.

Analysis
The attacker abused the Windows fodhelper.exe binary to execute
commands with elevated privileges.

Key Finding
fodhelper.exe

MITRE ATT&CK
T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control
5. Credential Dumping
Objective
Identify the credential dumping technique used by the attacker.

Analysis
The attacker downloaded and executed Mimikatz.

The tool was used to obtain credential material from the compromised
workstation.

Key Findings
Tool:

Mimikatz

Credential artifact:

itadmin:<REDACTED_NTLM_HASH>

Credential material is intentionally redacted from this public report.

MITRE ATT&CK
T1003.001 — OS Credential Dumping: LSASS Memory
T1550.002 — Use Alternate Authentication Material: Pass the Hash
6. Internal Discovery — Network Shares
Objective
Identify network resources discovered by the attacker.

Analysis
The attacker downloaded and executed PowerView.

The Invoke-ShareFinder functionality was used to enumerate
accessible network shares.

A PowerShell automation script was discovered:

IT_Automation.ps1

The script contained credentials that were later used for lateral
movement.

Key Findings
Tool: PowerView
Command: Invoke-ShareFinder
Sensitive file: IT_Automation.ps1
MITRE ATT&CK
T1135 — Network Share Discovery
T1018 — Remote System Discovery
T1087 — Account Discovery
7. Lateral Movement
Objective
Determine how the attacker moved from the initial workstation
to another endpoint.

Analysis
The attacker obtained credentials associated with:

QUICKLOGISTICS\allan.smith

The credentials were then used to access:

WKSTN-1327

PowerShell Remoting was observed through:

wsmprovhost.exe

Attack Chain
WKSTN-0051
     ↓
Credential Discovery
     ↓
allan.smith
     ↓
PowerShell Remoting
     ↓
WKSTN-1327

MITRE ATT&CK
T1021.006 — Remote Services: Windows Remote Management
T1059.001 — PowerShell
T1550.002 — Pass the Hash
8. Credential Dumping — Second Host
Objective
Determine what happened after the attacker compromised the second
workstation.

Analysis
Mimikatz was executed again on:

WKSTN-1327

The attacker obtained local administrator credential material.

Key Finding
administrator:<REDACTED_NTLM_HASH>

MITRE ATT&CK
T1003.001 — OS Credential Dumping: LSASS Memory
T1550.002 — Use Alternate Authentication Material: Pass the Hash
9. Domain Controller Access
Objective
Determine how the attacker progressed toward domain-level compromise.

Analysis
The attacker used compromised administrative credentials to access:

DC01

The investigation identified DCSync activity against the domain.

Key Findings
Target: DC01
Technique: DCSync
Target account: backupda
MITRE ATT&CK
T1003.006 — OS Credential Dumping: DCSync
T1078 — Valid Accounts
T1550.002 — Pass the Hash
10. Ransomware Deployment
Objective
Identify the final payload and determine the impact of the attack.

Analysis
After obtaining privileged credentials, the attacker downloaded and
executed a ransomware payload.

Key Findings
Payload:

ransomboogey.exe

Download source:

http://ff.sillytechninja.io/ransomboogey.exe

The ransomware was observed executing against compromised systems.

Attack Chain
Credential Theft
       ↓
Pass the Hash
       ↓
Domain Controller
       ↓
DCSync
       ↓
Privileged Access
       ↓
Ransomware
       ↓
Data Encrypted for Impact

MITRE ATT&CK
T1105 — Ingress Tool Transfer
T1486 — Data Encrypted for Impact
Attack Timeline
Boogeyman 1
Phase	Event	Evidence
Initial Access	Phishing email received	dump.eml
Execution	Malicious LNK opened	Invoice_20230103.lnk
Execution	Encoded PowerShell executed	LNK command line
Execution	Payload downloaded	PowerShell logs
Discovery	Seatbelt downloaded	PowerShell logs
Collection	Sticky Notes database accessed	plum.sqlite
Collection	KeePass database targeted	protected_data.kdbx
C2	HTTP communication	PCAP
Exfiltration	DNS data exfiltration	Wireshark/Tshark

Boogeyman 2
Phase	Event	Evidence
Initial Access	Malicious resume received	Email
Execution	Word document opened	Memory dump
Execution	VBA macro executed	OleVBA
Payload	update.js downloaded	VBA macro
Execution	wscript.exe executed	Memory
Payload	updater.exe downloaded	Memory
C2	128.199.95.189:8080 contacted	Netscan
Persistence	Scheduled Task created	Memory

Boogeyman 3
Phase	Event	Evidence
Initial Access	Spearphishing attachment	Email/endpoint
Execution	HTA executed	Sysmon
Execution	mshta.exe executed	Sysmon
Persistence	Scheduled Task created	Event logs
C2	External C2 connection	Sysmon Event ID 3
Privilege Escalation	UAC bypass	fodhelper.exe
Credential Access	Mimikatz executed	Sysmon
Discovery	Network shares enumerated	PowerView
Collection	IT_Automation.ps1 accessed	PowerShell
Lateral Movement	WKSTN-1327 accessed	WinRM
Credential Access	Administrator credentials dumped	Mimikatz
Lateral Movement	DC01 accessed	Windows telemetry
Credential Access	DCSync performed	Sysmon
Impact	Ransomware executed	Sysmon

Attack Chain
                         BOOGEYMAN 1
                              |
                              v
                      Phishing Email
                              |
                              v
                       Malicious LNK
                              |
                              v
                    PowerShell Execution
                              |
                              v
                     Payload Download
                              |
                              v
                  Endpoint Enumeration
                              |
                              v
                  Sensitive Data Access
                              |
                              v
                   HTTP C2 Communication
                              |
                              v
                    DNS Data Exfiltration
                              |
                              |
                              v
                         BOOGEYMAN 2
                              |
                              v
                      Phishing Email
                              |
                              v
                    Malicious Word DOC
                              |
                              v
                         VBA Macro
                              |
                              v
                        wscript.exe
                              |
                              v
                         update.js
                              |
                              v
                        updater.exe
                              |
                              v
                             C2
                              |
                              v
                      Scheduled Task
                              |
                              |
                              v
                         BOOGEYMAN 3
                              |
                              v
                    Spearphishing Email
                              |
                              v
                      ISO / HTA Payload
                              |
                              v
                         mshta.exe
                              |
                              v
                       Stage 1 Payload
                              |
                              v
                      Persistence + C2
                              |
                              v
                       UAC Bypass
                              |
                              v
                          Mimikatz
                              |
                              v
                       Pass-the-Hash
                              |
                              v
                  Network Share Discovery
                              |
                              v
                    Credential Discovery
                              |
                              v
                     Lateral Movement
                              |
                              v
                        WKSTN-1327
                              |
                              v
                    Credential Dumping
                              |
                              v
                           DC01
                              |
                              v
                          DCSync
                              |
                              v
                       Domain Access
                              |
                              v
                      Ransomware Payload

MITRE ATT&CK Mapping
Tactic	Technique	Evidence
Initial Access	T1566.001 — Spearphishing Attachment	Phishing emails
Execution	T1204.002 — Malicious File	LNK/DOC/ISO
Execution	T1059.001 — PowerShell	PowerShell activity
Execution	T1059.007 — JavaScript	update.js
Execution	T1218.005 — Mshta	HTA payload
Execution	T1218.011 — Rundll32	rundll32.exe
Persistence	T1053.005 — Scheduled Task	Updater task
Privilege Escalation	T1548.002 — UAC Bypass	fodhelper.exe
Credential Access	T1003.001 — LSASS Memory	Mimikatz
Credential Access	T1003.006 — DCSync	Domain Controller
Credential Access	T1550.002 — Pass the Hash	NTLM credential reuse
Discovery	T1018 — Remote System Discovery	Remote host discovery
Discovery	T1135 — Network Share Discovery	PowerView
Discovery	T1083 — File and Directory Discovery	Endpoint enumeration
Collection	T1005 — Data from Local System	KeePass database
Command & Control	T1071.001 — Web Protocols	HTTP communication
Command & Control	T1071.004 — DNS	DNS communication
Lateral Movement	T1021.006 — Windows Remote Management	PowerShell Remoting
Exfiltration	T1048.003 — Unencrypted Non-C2 Protocol	DNS exfiltration
Impact	T1486 — Data Encrypted for Impact	Ransomware

Indicators of Compromise
Boogeyman 1
Type	Indicator	Description
Domain	cdn.bpakcaging.xyz	C2 infrastructure
Domain	files.bpakcaging.xyz	Payload hosting
File	Invoice_20230103.lnk	Malicious LNK
File	protected_data.kdbx	Sensitive database
Tool	Seatbelt	Endpoint enumeration
Tool	sq3.exe	SQLite database access
Tool	nslookup	DNS exfiltration

Boogeyman 2
Type	Indicator	Description
Domain	files.boogeymanisback.lol	Payload hosting
IP	128.199.95.189	C2 infrastructure
File	Resume_WesleyTaylor.doc	Malicious document
File	update.js	Stage 2 payload
File	updater.exe	Malicious binary
Process	wscript.exe	Script execution
Task	Updater	Persistence

Boogeyman 3
Type	Indicator	Description
Host	WKSTN-0051	Initial compromised workstation
Host	WKSTN-1327	Lateral movement target
Host	DC01	Domain Controller
Domain	cdn.bananapeelparty.net	C2 infrastructure
IP	165.232.170.151	C2 infrastructure
File	ProjectFinancialSummary_Q3.pdf	Disguised malicious attachment
File	review.dat	Implanted payload
Tool	Mimikatz	Credential dumping
Tool	PowerView	Network discovery
File	IT_Automation.ps1	Credential-containing script
File	ransomboogey.exe	Ransomware

Detection Opportunities
Phishing
Monitor suspicious sender domains.
Detect invoice-themed phishing emails.
Monitor suspicious external senders targeting finance and HR.
Detect password-protected ZIP attachments.
Detect LNK attachments delivered through email.
Detect ISO attachments containing HTA files.
Monitor suspicious PDF files that contain scripts or executable content.
PowerShell
Enable PowerShell Script Block Logging.
Detect encoded PowerShell commands.
Monitor PowerShell spawning network utilities.
Detect PowerShell downloading executable files.
Monitor PowerShell making unexpected outbound connections.
Office Applications
Detect Microsoft Word spawning wscript.exe.
Detect Office applications spawning PowerShell.
Monitor VBA macros making network connections.
Detect Office documents downloading external payloads.
Endpoint
Monitor suspicious execution of:

mshta.exe
rundll32.exe
fodhelper.exe
wscript.exe
schtasks.exe

Additional detection opportunities:

Monitor suspicious parent-child process relationships.
Detect binaries executing from unusual directories.
Monitor execution from C:\ProgramData.
Monitor execution from C:\Windows\Tasks.
Credential Access
Monitor Mimikatz indicators.
Detect suspicious LSASS access.
Monitor credential dumping activity.
Detect Pass-the-Hash behavior.
Correlate credential dumping with subsequent authentication events.
Lateral Movement
Monitor PowerShell Remoting.
Detect unusual wsmprovhost.exe activity.
Monitor remote administrative logons.
Detect Pass-the-Hash activity.
Correlate remote authentication with process creation.
Network Share Discovery
Detect Invoke-ShareFinder.
Monitor unusual access to administrative shares.
Detect unexpected access to sensitive scripts.
Monitor plaintext credentials stored in PowerShell scripts.
Command & Control
Monitor outbound HTTP connections to suspicious infrastructure.
Detect unusual HTTP POST requests.
Monitor newly observed external domains.
Correlate process creation with outbound network connections.
DNS Exfiltration
Monitor unusually long DNS queries.
Detect high-frequency DNS requests.
Detect hexadecimal-looking DNS labels.
Monitor abnormal DNS query patterns.
Identify large volumes of requests to a single suspicious domain.
Domain Controller
Monitor DCSync activity.
Detect replication requests originating from unexpected hosts.
Monitor privileged account usage.
Correlate credential dumping with Domain Controller access.
Ransomware
Monitor downloads of unknown executable files.
Detect execution of newly downloaded binaries.
Monitor rapid process execution across multiple hosts.
Detect mass file modification/encryption behavior.
Correlate ransomware activity with preceding credential theft
and lateral movement.
Investigation Summary
The Boogeyman series demonstrates the progression of a targeted intrusion
from initial phishing to full domain compromise.

Boogeyman 1
The attack started with a phishing email containing a malicious LNK file.

The LNK executed an encoded PowerShell command, downloaded additional
payloads, performed endpoint discovery, accessed sensitive information,
communicated with attacker infrastructure, and used DNS as a data
exfiltration channel.

Boogeyman 2
The attacker changed the initial payload to a malicious Word document.

A VBA macro downloaded a JavaScript payload, which was executed through
wscript.exe.

Memory forensics revealed the next-stage executable, C2 communication,
and persistence through a Scheduled Task.

Boogeyman 3
The attack became significantly more advanced.

The attacker used a disguised ISO/HTA payload, established persistence,
bypassed UAC, dumped credentials using Mimikatz, discovered network shares,
obtained additional credentials, moved laterally, accessed the Domain
Controller, performed DCSync, and finally deployed ransomware.

The complete progression can be summarized as:

Phishing
   ↓
Initial Execution
   ↓
Payload Download
   ↓
Persistence
   ↓
Discovery
   ↓
Credential Access
   ↓
Privilege Escalation
   ↓
Lateral Movement
   ↓
Domain Compromise
   ↓
Data Exfiltration / Impact
   ↓
Ransomware

Lessons Learned
Phishing investigations require analysis of both email content and headers.
Malicious LNK files can be used to launch obfuscated PowerShell.
Office macros can act as payload downloaders.
Memory forensics can reveal process relationships and payloads.
PowerShell logging provides valuable evidence of attacker behavior.
Process parent-child relationships are important for identifying
suspicious execution.
Scheduled Tasks are commonly abused for persistence.
Legitimate Windows binaries can be abused for privilege escalation.
Credential dumping can turn a single-host compromise into a
domain-wide incident.
Network share discovery can expose sensitive files and credentials.
PowerShell Remoting can facilitate lateral movement.
DNS can be abused as a covert data exfiltration channel.
DCSync represents a critical escalation point in a Windows domain.
Detection becomes stronger when email, endpoint, identity, and network
telemetry are correlated.
Repository Structure
boogeyman-1-3/
│
├── README.md
│
├── boogeyman-1/
│   ├── README.md
│   ├── screenshots/
│   ├── evidence/
│   └── notes/
│
├── boogeyman-2/
│   ├── README.md
│   ├── screenshots/
│   ├── evidence/
│   └── notes/
│
├── boogeyman-3/
│   ├── README.md
│   ├── screenshots/
│   ├── evidence/
│   └── notes/
│
└── references/
    └── mitre-attack.md

Evidence Handling
Original TryHackMe artifacts are not included in this repository.

Screenshots should be sanitized before publication.

Do not upload:

Passwords
Authentication tokens
Personal information
Credit card information
Private keys
VPN credentials
TryHackMe account information
Unredacted memory dumps
Sensitive database contents
Credentials obtained during the lab
Screenshots containing credentials or sensitive information should be
redacted before being committed.

References
TryHackMe — Boogeyman 1
TryHackMe — Boogeyman 2
TryHackMe — Boogeyman 3
MITRE ATT&CK
Wireshark
Volatility
OleTools
LNKParse3
Disclaimer
This project is intended for educational and defensive security
research purposes.

All analysis was performed against intentionally vulnerable or
simulated TryHackMe environments
