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

