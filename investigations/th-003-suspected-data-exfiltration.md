# Threat Hunt Report: Suspected Data Exfiltration

<img width="1000" height="500" alt="image" src="https://github.com/user-attachments/assets/a2a78e90-87b1-4655-b2d1-0032f3ab6540" />

## Scenario Overview

An employee named John Doe, working in a sensitive department, was placed on a performance improvement plan (PIP). Following a negative reaction, management raised concerns that the employee may attempt to exfiltrate proprietary company data before leaving the organisation.

The objective of this investigation was to analyse activity on the user’s corporate device windows-target- using Microsoft Defender for Endpoint (MDE) to identify any signs of data staging or exfiltration.

---

## Hypothesis

The user may attempt to:

Archive or compress sensitive company data
Stage data locally prior to exfiltration
Use scripting (e.g., PowerShell) to automate the process

---

## Data Sources

The following tables were used:

- DeviceFileEvents
- DeviceProcessEvents
- DeviceNetworkEvents

---

## Data Analysis
Identifying Archive Creation Activity
```
DeviceFileEvents
| where DeviceName contains "windows-target"
| where FileName endswith ".zip"
| order by Timestamp desc
```
<img width="2023" height="645" alt="image" src="https://github.com/user-attachments/assets/4ba748c0-1130-4a41-85e3-b7255f622db5" />


Finding:

- Multiple .zip files were created on the device
- Files were being moved into a directory resembling a "backup" folder
- Activity suggests potential data staging behaviour

---

## Investigation
Correlating Process Activity
```
let specificTime = datetime(2026-03-07T16:04:59.9206413Z);
let VMName = "windows-target-";
DeviceFileEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
<img width="2307" height="717" alt="image" src="https://github.com/user-attachments/assets/213216c1-cb42-460e-9f5a-cc4bc0a4b1a5" />


Finding:

- A PowerShell script executed around the same time as archive creation
- The script silently installed 7-Zip
- 7-Zip was then used to compress employee-related data into archive files
- Activity appears automated and deliberate

---

## Network Activity Review

```
let specificTime = datetime(2026-03-07T16:04:59.9206413Z);
let VMName = "windows-target-";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

Finding:

- No evidence of outbound data transfer or exfiltration observed
- No suspicious external connections detected during the timeframe

---

User / Entity Attribution
- User: John Doe
- Device: windows-target-

Assessment:
- Activity is highly suspicious and consistent with data staging behaviour
- No confirmed exfiltration, but clear preparation for potential data theft

---

## MITRE ATT&CK Mapping
```
- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1105 – Ingress Tool Transfer
- T1560.001 – Archive Collected Data: Archive via Utility
- T1074.001 – Data Staged: Local Data Staging
- T1027 – Obfuscated/Compressed Files and Information
- T1041 – Exfiltration Over C2 Channel (Potential / Not Observed)
- T1036 – Masquerading
```

---

## Assessment

The investigation identified:
- Automated archiving of files using PowerShell and 7-Zip
- Silent installation of tooling to support data compression
- Storage of archives in a directory designed to appear legitimate

This behaviour is consistent with data staging prior to exfiltration.

Although no data exfiltration was observed, the activity presents a high risk of insider threat.

---

## Response

Containment
- Monitor or restrict user activity on windows-target-
- Consider temporary isolation if risk escalates

Account Actions
- Review John Doe’s account activity
- Enforce least privilege where applicable
- Consider session monitoring or restrictions

Endpoint Remediation
- Remove unauthorised tools (e.g., 7-Zip if not approved)
- Investigate and remove scripts used for automation
- Perform endpoint security scan

Investigation Expansion
- Identify all archived files and review contents
- Check for similar activity across other endpoints
- Continue monitoring for delayed exfiltration attempts

---

## Hardening Recommendations

- Restrict installation of unauthorised software
- Monitor and control PowerShell usage:
- Enable Script Block Logging
- Use constrained execution policies
- Implement Data Loss Prevention (DLP) controls
- Apply least privilege access to sensitive data

---

## Detection Improvements

Create detections for:
- Archive file creation in unusual directories
- Silent installation of compression tools
- PowerShell scripts invoking archiving utilities
- High-volume file compression activity

Enhance visibility with:
- PowerShell logging
- Behaviour-based detection rules

---

## Lessons Learned

What Worked Well
- File event analysis quickly identified suspicious archiving activity
- Time-based correlation across tables confirmed automation
- Structured pivoting provided clear investigative direction

Improvements
- Earlier detection could be achieved with:
- Alerts on bulk file compression
- Monitoring for tool installation via PowerShell
- Hunting efficiency could improve with:
- Prebuilt queries for data staging patterns
- Automated alerting on suspicious directories (e.g., fake backup folders)

---

## Conclusion

This investigation uncovered clear evidence of data staging activity involving the automated compression of files using PowerShell and 7-Zip.

While no exfiltration was observed, the behaviour strongly indicates preparation for potential data theft, aligning with insider threat patterns.

Continued monitoring and preventative controls are required to mitigate the risk of future exfiltration attempts.
