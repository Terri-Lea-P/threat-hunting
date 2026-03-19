# Threat Hunt Report: Sudden Network Slowdowns

<img width="750" height="500" alt="image" src="https://github.com/user-attachments/assets/6f197093-754a-4686-9184-f41e61777b14" />




## Scenario Overview

The server team reported significant network performance degradation across legacy devices within the 10.0.0.0/16 network.
After ruling out external DDoS activity, the hypothesis was that abnormal internal activity may be responsible, such as:

- Internal port scanning

- Excessive connection attempts

- Potential lateral movement

- Abuse of unrestricted PowerShell execution

## Hypothesis

An internal host may be:

- Performing port scanning across the network

- Generating excessive failed connections

- Potentially preparing for lateral movement

## Data Sources

The following Microsoft Defender tables were used:

- DeviceNetworkEvents

- DeviceProcessEvents

- DeviceFileEvents

--- 

## Data Analysis

Detecting Excessive Failed Connections
```
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, LocalIP
```
Finding:

Host tp--tp--tp generated a high volume of failed connection attempts from source IP 10.1.0.116.

<img width="1446" height="274" alt="image" src="https://github.com/user-attachments/assets/367c25cf-1a8c-40af-a1b6-d519385ce258" />

---

Identifying Port Scanning Behaviour
```
let IPInQuestion = "10.1.0.116";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
Finding:

Sequential connection attempts across multiple ports were observed, indicating automated port scanning behaviour.

<img width="2735" height="1475" alt="image" src="https://github.com/user-attachments/assets/0f476341-60d1-42d9-8179-212718e57cde" />

---

Investigation

Process Correlation
```
let VMName = "tp--tp--tp";
let specificTime = datetime(2026-03-17T10:45:24.3317787Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
Finding:

A PowerShell script named portscan.ps1 was executed at 2026-03-17T10:40:24Z, aligning with the observed spike in failed network connections.

<img width="2250" height="543" alt="image" src="https://github.com/user-attachments/assets/7e457bcd-c791-43e5-ac98-adab31b2f0bd" />

---

User Attribution

The script execution was initiated by user account test-v1.

This raises the possibility of either legitimate administrative activity or a compromised account performing reconnaissance.

---

## MITRE ATT&CK Mapping
```
- T1046 – Network Service Discovery
- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1078 – Valid Accounts
- T1595 – Active Scanning
```

---

## Assessment

The investigation confirms:

- Automated internal port scanning activity
- Execution via PowerShell script
- Activity originating from a legitimate internal host
- Direct correlation with network performance degradation

This behaviour is consistent with reconnaissance activity and may indicate early-stage attacker behaviour or misuse of administrative access.

---

## Response

Containment
- Isolate host tp--tp--tp from the network
- Restrict internal outbound connections temporarily

Account Security
- Investigate account test-v1
- Reset credentials and enforce MFA
- Review authentication logs for anomalies

Endpoint Remediation
- Terminate the PowerShell process running portscan.ps1
- Perform a full endpoint scan using Microsoft Defender for Endpoint
- Review additional processes executed around the same timeframe

Investigation Expansion
- Identify all hosts targeted during the scan
- Check for successful connections following the scan
- Hunt for similar PowerShell-based scanning activity across the environment

---

## Hardening Recommendations

- Implement account lockout policies on legacy systems
- Restrict or monitor PowerShell usage:
- Enable Script Block Logging
- Apply Constrained Language Mode
- Implement network segmentation to reduce internal attack surface

---

## Detection Improvements

Create detection rules for:
- High volumes of failed connection attempts
- Sequential port access patterns
- Execution of suspicious PowerShell scripts

Enable:
- PowerShell logging
- Advanced hunting queries for behavioural detection

---

## Lessons Learned

What Worked Well
- Correlation of network and process telemetry quickly identified the root cause
- Time-based pivoting provided strong investigative context
- KQL enabled efficient pattern detection

Improvements
- Earlier detection could be achieved through:
- Predefined port scanning alerts
- Monitoring PowerShell execution more closely

Hunting efficiency could be improved with:
- Saved queries and detection rules
- Automated anomaly detection

---

## Conclusion

This investigation identified internal PowerShell-based port scanning as the root cause of network degradation.
The activity highlights the risks associated with unrestricted internal traffic and scripting capabilities, reinforcing the need for improved monitoring, access control, and behavioural detection strategies.


