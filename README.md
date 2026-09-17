\# SOC Monitoring \& Threat Detection Lab



A hands-on Security Operations Center (SOC) lab focused on security event monitoring, threat detection, log analysis, and incident investigation using Splunk, Sysmon, Windows Event Logs, PowerShell, and Kali Linux.



\## Objectives



\- Centralize Windows Security, Sysmon, and PowerShell logs in Splunk.

\- Monitor security events from an isolated lab environment.

\- Detect indicators of brute-force activity and network reconnaissance.

\- Monitor PowerShell activity for security investigation.

\- Create SPL-based detection queries and scheduled alerts.

\- Build a SOC monitoring dashboard for security-event visibility.

\- Map selected detection use cases to the MITRE ATT\&CK framework.



\## Lab Environment



| Component | Purpose |

|---|---|

| Splunk Enterprise | SIEM and security-event analysis |

| Splunk Universal Forwarder | Log collection from Windows |

| Windows 10 | Monitored endpoint |

| Sysmon | Detailed Windows system and network telemetry |

| Kali Linux | Security testing and reconnaissance |

| Nmap | Network reconnaissance testing |



\## Detection Use Cases



\### 1. Brute-Force Activity



Windows Security Event ID `4625` was used to identify failed login attempts.



Example SPL:



```spl

index=main EventCode=4625 Security

| bucket \_time span=5m

| stats count by \_time

| where count >= 5

### 2. Network Reconnaissance / Port Scan

Nmap was used from the Kali Linux machine to generate network reconnaissance activity against the Windows endpoint.

The detection identifies multiple destination ports contacted by the same source IP.

Example SPL:

```spl
index=main "192.168.56.105"
| rex "DestinationPort[^0-9]*(?<port>[0-9]+)"
| stats dc(port) as unique_ports
| where unique_ports >= 3

### 3. PowerShell Activity Monitoring

PowerShell Operational logs were collected from the Windows endpoint and forwarded to Splunk for security monitoring and investigation.

Example SPL:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| stats count

## SOC Monitoring Dashboard

A Splunk Dashboard Studio dashboard was created to provide a centralized view of security activity.

The dashboard includes:

- Total Security Events
- Failed Login Attempts
- Possible Brute-Force Activity
- Network Reconnaissance
- Failed Logins Over Time
- PowerShell Activity
- Security Events Over Time

The dashboard provides a consolidated view of detected security activity to support SOC monitoring and investigation.

## Scheduled Alerts

Scheduled Splunk searches were configured to monitor security activity and generate alerts when detection conditions were met.

Configured alerts include:

- Possible Brute Force Detected
- Possible Port Scan Detected
- PowerShell Activity Detected

## MITRE ATT&CK Mapping

Selected detection use cases were mapped to the MITRE ATT&CK framework:

| Detection Use Case | MITRE ATT&CK Technique |
|---|---|
| Failed login / brute-force activity | T1110 - Brute Force |
| Network reconnaissance using Nmap | T1046 - Network Service Scanning |
| PowerShell activity | T1059.001 - PowerShell |

