# Detection-Lab

Production grade Detection as Code portfolio focused on:
- Threat Hunting
- Detection Engineering
- Atomic Red Team validation
- Behavioral correlation
- Incident generation
- Multi telemetry security analytics

---

# Core Detection Domains

## Endpoint Telemetry
- Windows Security Event ID 4688
- PowerShell execution
- Parent child process relationships
- Command line analytics

## Identity Telemetry
- Windows Security Event ID 4624
- Windows Security Event ID 4625
- Failed authentication tracking
- Brute force detection
- User behavioral correlation

## Network Telemetry
- Sysmon Event ID 3
- Source and destination IP analysis
- Port based anomaly detection
- Process to network linkage
---

# Active Detection Pipelines

## DET-T1059-FAILEDLOGON-v1
Detects:
- Suspicious PowerShell
- Failed logon clustering
- User based brute force attempts

## DET-T1059-FAILEDLOGON-NETWORK-v2
Detects:
- Failed logon to execution chain
- PowerShell execution
- Network connections
- Multi source behavioral anomalies

---

# ATT&CK Coverage

- T1059.001 PowerShell
- T1110 Brute Force
- T1071 Application Layer Protocol

---

# Repository Structure

```text
Detection-Lab/
├── Detections/
├── Pipeline/
├── telemetry/
├── reports/
├── attack_runs/
├── sigma/
├── kql/
├── spl/
├── playbooks/
├── screenshots/
└── README.md
