# Analyst Playbook — ENCODED_PS_LOLBIN_CHAIN

**Detection ID:** DET-CHAIN-T1059.001-T1218.011-v1
**Alert Type:** ENCODED_PS_LOLBIN_CHAIN
**Severity:** High
**MITRE:** T1059.001, T1218.011

---

## Triage Checklist

Work through these steps in sequence. Document findings at each step.

### Step 1 — Decode the PowerShell command

Extract the Base64 payload from the `command_line` field:

```powershell
# Decode in PowerShell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<base64_value>'))
```

```python
# Decode in Python
import base64
decoded = base64.b64decode('<base64_value>').decode('utf-16-le')
print(decoded)
```

**Assess:** Is the decoded command benign (string handling, deployment task) or
does it contain network calls, file drops, credential harvesting, or further
execution staging?

---

### Step 2 — Examine the LOLBin invocation

Review the `lb_cmd` / `command_line` for the rundll32 (or other LOLBin) event:

- Does it reference a DLL in a user-writable path (`%TEMP%`, `%APPDATA%`)?
- Does it reference an unusual export function name?
- Is the DLL path consistent with known software?

**Suspicious indicators:**
- DLL in `C:\Users\<user>\AppData\Local\Temp\`
- Generic export names: `DllMain`, `Run`, `Execute`, `Start`
- Unsigned or recently created DLL (check file creation time vs execution time)

---

### Step 3 — Establish execution context

From the alert's `user` and `host` fields:

- Is this a standard user or a service account?
- Is the host an endpoint, server, or privileged workstation?
- Was there a recent logon event (EID 4624) for this user before the alert?

**KQL — logon context for alert user:**
```kql
SecurityEvent
| where EventID == 4624
| where SubjectUserName == "<user_from_alert>"
| where Computer == "<host_from_alert>"
| where TimeGenerated between (datetime(<alert_time_start>) - 30m) .. datetime(<alert_time_start>)
| project TimeGenerated, LogonType, IpAddress, WorkstationName
```

---

### Step 4 — Check for network activity

Correlate with Sysmon EID 3 (network connections) within 5 minutes post-alert:

```kql
let alert_time = datetime(<alert_time_start>);
WindowsEvent
| where TimeGenerated between (alert_time .. alert_time + 5m)
| where EventID == 3
| where Computer == "<host_from_alert>"
| extend Image = tostring(EventData.Image),
         DestIp = tostring(EventData.DestinationIp),
         DestPort = tostring(EventData.DestinationPort)
| where Image has_any ("powershell", "rundll32", "regsvr32", "mshta")
| project TimeGenerated, Image, DestIp, DestPort
```

---

### Step 5 — Persistence check

Check for scheduled tasks or run key modifications post-execution:

```kql
SecurityEvent
| where EventID in (4698, 4702)
| where Computer == "<host_from_alert>"
| where TimeGenerated between (datetime(<alert_time_start>) .. datetime(<alert_time_start>) + 30m)
```

---

## Escalation Criteria

Escalate to Incident Response if any of the following are true:

- Decoded PowerShell contains a download cradle, shellcode, or credential access
- LOLBin is loading a DLL from a user-writable path
- Network connections to external IPs observed within 5 minutes post-execution
- Scheduled task or run key created post-execution
- Same behaviour observed on multiple hosts within 24 hours

---

## Containment Actions (if escalating)

1. Isolate the host from the network
2. Preserve volatile memory if available (run `winpmem` or equivalent)
3. Export full Sysmon and Security event logs for the host (last 24 hours)
4. Revoke active logon sessions for the affected user
5. Submit decoded payload and DLL to sandboxed analysis

---

## False Positive Disposition

If the alert is determined to be a false positive:

1. Document the legitimate process parent chain and command line
2. Add the parent process to the suppression allowlist in `Pipeline/detect.py`
3. Re-run `Pipeline/replay_harness.py --suite endpoint` to confirm no regression
4. Commit the suppression with a comment referencing this playbook
