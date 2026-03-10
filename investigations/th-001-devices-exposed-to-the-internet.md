# Threat Hunt Report: Internet-Exposed VM & Potential Brute Force Attempts

## Overview

During routine maintenance, the security team investigated whether any virtual machines in the **shared services cluster** (DNS, Domain Services, DHCP, etc.) had been mistakenly exposed to the public internet.

The objective of this hunt was to:

- Identify any VMs exposed to the internet
- Detect potential brute-force login attempts
- Determine whether any unauthorized access occurred
- Map observed activity to the MITRE ATT&CK framework
- Implement mitigation steps if required

---

# 1. Preparation

## Hypothesis

Some VMs in the shared services cluster may have been **unintentionally exposed to the public internet**. Because some legacy systems **do not have account lockout policies configured**, it is possible that an attacker could have successfully **brute-forced credentials** and gained unauthorized access.

Potential attacker objective:

- Gain **initial access via exposed remote services**
- Attempt **password brute force attacks**
- Compromise valid accounts to access internal services

---

# 2. Data Collection

Relevant log sources were confirmed to contain recent telemetry.

### Investigated Tables

- `DeviceInfo`
- `DeviceLogonEvents`

These tables provide:

- Device exposure status
- Authentication activity
- Source IP addresses
- Account usage patterns

---

# 3. Data Analysis

## Internet Exposure Detection

The following query identified VMs exposed to the public internet.

```kql
DeviceInfo
| where DeviceName startswith "windows-target"
| where IsInternetFacing == true
| order by Timestamp desc
```

Result

windows-target-1 had been internet-facing for several days.
```
Last observed internet-facing timestamp
2026-03-10T11:19:29.0253191Z
```
Failed Login Attempts

Authentication logs were analyzed to identify potential brute force attempts.
```
DeviceLogonEvents
| where DeviceName contains "windows-target"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
Findings

Multiple external IP addresses attempted repeated failed logins, indicating clear brute-force activity against the exposed system.

Screenshot evidence:
<img width="1323" height="410" alt="image" src="https://github.com/user-attachments/assets/25e5630c-e3f1-4381-8232-ccc690bb293a" />








Checking for Successful Compromise

The top attacking IP addresses were checked for any successful authentication events.
```
let RemoteIPsInQuestion = dynamic(["149.50.101.27","162.254.3.130", "94.26.68.20", "111.11.4.120", "94.26.88.47"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
Result

No successful logins were observed from these IP addresses.

Screenshot evidence:
<img width="1393" height="364" alt="image" src="https://github.com/user-attachments/assets/fb823eb4-2cfc-4eb6-b77e-e1b79a679745" />




Successful Login Analysis

Successful remote network logins over the previous 30 days were analyzed.
```
DeviceLogonEvents
| where DeviceName contains "windows-target"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName contains "labuser"
| summarize count()
```
Result

21 successful logins

All associated with the legitimate account labuser

Brute Force Against labuser

To determine if attackers attempted to brute force this account:
```
DeviceLogonEvents
| where DeviceName contains "windows-target"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName contains "labuser"
| summarize count()
```
Result
0 failed login attempts

This indicates:

Attackers did not target the labuser account
A successful password guess is highly unlikely
Source IP Analysis for Legitimate Logins

All successful login IP addresses for labuser were reviewed.
```
DeviceLogonEvents
| where DeviceName contains "windows-target"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName contains "labuser"
| summarize LoginCount = count()by DeviceName, ActionType, AccountName, RemoteIP
```
Result

All login IP addresses appeared consistent with expected activity and did not originate from suspicious or unknown locations.

Screenshot evidence:
<img width="1397" height="442" alt="image" src="https://github.com/user-attachments/assets/474fa1f8-1f45-4256-9722-756173ed416a" />


# 4. Investigation
Key Findings

The VM windows-target-1 was exposed to the internet
Multiple external IP addresses performed brute-force login attempts
No attackers successfully authenticated
No suspicious activity occurred after successful logins

All successful access belonged to the legitimate labuser account

## 5. MITRE ATT&CK Mapping

Observed activity mapped to the following ATT&CK techniques:
```
Tactic	Technique	Description
Initial Access	T1133 – External Remote Services	Internet-facing system exposed to attackers
Credential Access	T1110 – Brute Force	Multiple failed login attempts
Credential Access	T1110.003 – Password Spraying (Possible)	Repeated login attempts from external sources
Defense Evasion / Persistence	T1078 – Valid Accounts (Ruled Out)	No evidence of account compromise
```
# 6. Response

Although no compromise occurred, the exposed VM represented a significant security risk.
The following remediation steps were implemented:

## Network Security

Hardened the Network Security Group (NSG)

Restricted RDP access to specific trusted endpoints

Removed public internet access

Identity Security

Implemented account lockout policies to prevent brute force attacks

Enabled Multi-Factor Authentication (MFA)

# 7. Documentation

This investigation confirmed that:

Internet exposure led to immediate brute-force activity

Proper authentication controls prevented compromise

Additional hardening was necessary to prevent future risk

This hunt demonstrates the importance of:

Continuous monitoring of internet-exposed assets

Authentication telemetry analysis

Rapid mitigation of misconfigurations

# 8. Improvement Opportunities

Several preventative measures could reduce future risk.

## Security Improvements

Implement default account lockout policies

Enforce MFA on all remote access

Restrict RDP exposure via NSG rules

Implement continuous monitoring for exposed assets

## Hunting Improvements

Future hunts could incorporate:

Automated alerts for internet-facing internal VMs

Detection rules for brute-force login thresholds

Monitoring of unusual authentication source IPs

## Conclusion

The investigation identified a misconfigured internet-facing VM that attracted multiple brute-force login attempts from external attackers.

However:

No unauthorized access occurred

No accounts were compromised

Security controls prevented successful intrusion

Following remediation actions, the system is now properly secured and protected from further exposure.


