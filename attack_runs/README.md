# Atomic Red Team — Execution Framework

This directory documents all adversary simulations executed against the lab environment.
Each subdirectory corresponds to a MITRE ATT&CK technique and contains:

- `execution_log.md` — what was run, when, and the exact PowerShell invocation
- `raw_telemetry.json` — captured Sysmon and Windows Security event output
- `detection_result.md` — whether the pipeline fired, timestamp delta, and validation notes

---

## Lab Environment Requirements

| Component | Requirement |
|---|---|
| OS | Windows 10/11 or Windows Server 2019+ |
| PowerShell | 5.1 or 7.x |
| Sysmon | Installed with SwiftOnSecurity config |
| Windows Auditing | Process creation auditing enabled (4688 with command line) |
| PowerShell logging | Module, ScriptBlock, and Operational logging enabled |
| Atomic Red Team | Invoke-AtomicRedTeam module installed |

---

## Atomic Red Team Setup

```powershell
# Install execution framework
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
Import-Module invoke-atomicredteam

# Install atomics folder (technique test definitions)
Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing)

# Verify installation
Invoke-AtomicTest T1059.001 -ShowDetails
```

---

## Windows Audit Policy — Required Settings

Run as Administrator before any simulation:

```powershell
# Enable process creation auditing with command line
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

# Enable PowerShell ScriptBlock logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

---

## Telemetry Capture

After each Atomic execution, export relevant events using:

```powershell
# Capture Sysmon events (last 30 minutes)
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.TimeCreated -gt $since } |
    Select-Object Id, TimeCreated, @{N="Computer";E={$_.MachineName}},
                  @{N="Message";E={$_.Message}} |
    ConvertTo-Json -Depth 5 |
    Out-File "attack_runs\T1059.001\raw_telemetry.json" -Encoding UTF8

# Capture Windows Security events (4688, 4624, 4625)
Get-WinEvent -LogName Security |
    Where-Object { $_.Id -in @(4688,4624,4625) -and $_.TimeCreated -gt $since } |
    Select-Object Id, TimeCreated, @{N="Computer";E={$_.MachineName}},
                  @{N="Message";E={$_.Message}} |
    ConvertTo-Json -Depth 5 |
    Out-File "attack_runs\T1059.001\winsec_events.json" -Encoding UTF8
```

---

## Simulations Executed

| Technique | Test Name | Atomic ID | Execution Date | Detection Result |
|---|---|---|---|---|
| T1059.001 | Encoded PowerShell | T1059.001-4 | 2025-03-15 | ✅ True Positive |
| T1110.001 | Brute Force - Password Spraying | T1110.001-1 | 2025-03-15 | ✅ True Positive |
| T1218.011 | rundll32 LOLBin | T1218.011-1 | 2025-03-15 | ✅ True Positive |

---

## Clean Baseline Run

Before each adversary simulation, a clean baseline capture is taken to establish:
- Normal process creation patterns for the test user
- Normal authentication patterns (single failed logon is acceptable noise)
- Zero alert count against all active detections

Clean baseline telemetry is stored in `telemetry/raw/clean_baseline.json`.
