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
