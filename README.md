# Threat_Detection_Rules
A collection of detection rules based on the Sigma format that I have created and tested.


# Sigma Rule – PowerShell Spawned from CMD

## Overview
This rule detects when `powershell.exe` is spawned by `cmd.exe`. This pattern is common in attack chains involving script-based malware, LOLBins, or privilege escalation.

## Rule Metadata
- MITRE ATT&CK: T1059.001 – PowerShell
- Log Source: Windows Process Creation (Sysmon or Security logs)
- Rule Level: Medium

## Detection Logic
Matches:
- `ParentImage`: ends with `cmd.exe`
- `Image`: ends with `powershell.exe`

## Use Cases
- Detecting malicious use of PowerShell
- Investigating post-exploitation behavior
- Building behavioral baselines

## False Positives
- Admin scripts using batch files to launch PowerShell
- Certain software installations

## Author
Gavin Wood – 2025/07/28
