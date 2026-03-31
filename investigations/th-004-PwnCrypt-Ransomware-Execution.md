# Threat Hunt Report: PwnCrypt Ransomware Execution Investigation

## Scenario

A newly identified ransomware strain known as PwnCrypt has been reported, leveraging a PowerShell-based payload to encrypt files on infected systems. The malware targets directories such as C:\Users\Public\Desktop and appends a .pwncrypt extension to affected files.

Due to limited user security awareness and an immature security posture, there is concern that this ransomware may have been executed within the corporate environment.

The objective of this investigation is to determine whether PwnCrypt has been executed on a corporate device and identify its execution method and impact.

---

## Hypothesis

PwnCrypt ransomware may have executed on a corporate endpoint, resulting in file encryption using a PowerShell-based script, identifiable by the presence of .pwncrypt file extensions.

---

## Data Sources
* DeviceFileEvents – to identify file creation, renaming, and encryption activity
* DeviceProcessEvents – to identify execution of processes related to ransomware activity

---

## Data Analysis

Initial analysis focused on identifying known indicators of compromise (IoCs), specifically files containing the .pwncrypt extension.
```
DeviceFileEvents
| where DeviceName == "windows-target-"
| where FileName contains "pwncrypt"
| order by Timestamp desc
```
<img width="2285" height="697" alt="image" src="https://github.com/user-attachments/assets/3d68e806-769f-487f-8a54-d43fb68a5a19" />


This query revealed multiple file creation and renaming events involving .pwncrypt files, including:
* ProjectList_pwncrypt.csv
* CompanyFinancials_pwncrypt.csv
* EmployeeRecords_pwncrypt.csv

Additionally, a suspicious script was identified:
* C:\ProgramData\pwncrypt.ps1

This strongly indicated that ransomware activity had occurred on the device.

---

## Investigation

To determine the execution method, process activity was analyzed around the time the ransomware script was created.

```
let specificTime = datetime(2026-03-25T08:12:50.7404972Z);
let VMName = "windows-target-";
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```

<img width="2182" height="734" alt="image" src="https://github.com/user-attachments/assets/ff5add34-158d-47e7-bdf3-1a6a97b1c7cb" />

The results showed multiple executions of:

* powershell.exe
* cmd.exe
* conhost.exe

This sequence indicates command-line activity where PowerShell was likely launched via Command Prompt.

Although direct command-line evidence referencing pwncrypt.ps1 was not observed, further investigation confirmed no explicit references in ProcessCommandLine:

```
let VMName = "windows-target-";
let specificTime = datetime(2026-03-25T08:12:50.7404972Z);
DeviceProcessEvents
| where DeviceName == VMName
| where ProcessCommandLine contains "pwncrypt"
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```
Despite this, strong temporal correlation was observed between:

* PowerShell execution
* Presence of the ransomware script (pwncrypt.ps1)
* Rapid file encryption activity

---

## Timeline of Events
1. cmd.exe executed on the endpoint
2. powershell.exe launched shortly after
3. pwncrypt.ps1 script present in C:\ProgramData
4. Multiple files created and renamed with .pwncrypt extension

This sequence confirms that the ransomware was executed using PowerShell, likely initiated through command-line activity.

---

## MITRE ATT&CK Mapping

* T1059.001 – Command and Scripting Interpreter: PowerShell
* T1059 – Command and Scripting Interpreter
* T1486 – Data Encrypted for Impact
* T1204 – User Execution
* T1562 – Impair Defenses (Execution Policy Bypass likely used)

---

## Assessment

The investigation confirmed that PwnCrypt ransomware successfully executed on the windows-target- device.

The attacker leveraged PowerShell to execute a malicious script (pwncrypt.ps1), resulting in the encryption of multiple files within user-accessible directories.

Although the exact command-line invocation was not captured, sufficient evidence supports successful ransomware execution and impact.

---

## Response
* Isolate the affected endpoint from the network
* Terminate any active malicious processes
* Remove the malicious script (pwncrypt.ps1) from C:\ProgramData
* Restore encrypted files from backups if available
* Conduct a full antivirus and EDR scan on the system

---

## Hardening Recommendations
* Restrict PowerShell usage and enforce constrained language mode
* Block or alert on ExecutionPolicy Bypass usage
* Monitor and restrict script execution from C:\ProgramData
* Implement application control (e.g., AppLocker or WDAC)
* Improve user awareness to reduce phishing-based delivery risks

---

## Detection Improvements
* Create alerts for file creation containing .pwncrypt
* Monitor for PowerShell execution followed by high-volume file modifications
* Detect script file creation in suspicious directories such as ProgramData
* Correlate PowerShell activity with file encryption behaviour

---

## Lessons Learned
* Ransomware activity can be identified through file system patterns even when command-line evidence is limited
* Correlating process activity with file events is critical in detecting execution chains
* PowerShell remains a high-risk vector for script-based attacks

---

## Conclusion

This investigation confirmed the presence and execution of PwnCrypt ransomware within the environment. By correlating file system activity with process execution, it was possible to reconstruct the attack chain and identify PowerShell as the primary execution method.

The findings highlight the importance of monitoring scripting activity and implementing stronger controls around PowerShell usage to prevent similar attacks in the future.

