# Attack Run — T1059.001 Encoded PowerShell

**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Atomic Test:** T1059.001-4 — PowerShell Base64 Encoded Command
**Execution Date:** 2025-03-15
**Lab Host:** DESKTOP-LAB01
**Operator:** Bobby Okafor

---

## Objective

Simulate encoded PowerShell execution followed by LOLBin invocation to validate
`DET-CHAIN-T1059.001-T1218.011-v1` fires correctly and within the expected
correlation window.

---

## Execution

```powershell
# Step 1 — Run Atomic test for encoded PowerShell
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1059.001 -TestNumbers 4

# Step 2 — Manually simulate LOLBin follow-on (rundll32)
# This creates the chained behaviour the detection targets
Start-Process rundll32.exe -ArgumentList "C:\Users\bobby\AppData\Local\Temp\payload.dll,DllMain"
```

**Exact command observed in telemetry:**
```
powershell.exe -EncodedCommand JABjAG8AbQBtAGEAbgBkACAAPQAgACcAbgBlAHQAIAB1AHMAZQByACAAaABhAGMAawBlAHIAJwA=
```

Decoded: `$command = 'net user hacker'`

---

## Telemetry Captured

| Event | Event ID | Timestamp (UTC) | Process |
|---|---|---|---|
| PowerShell execution | 4688 | 2025-03-15T14:22:10.441Z | powershell.exe |
| rundll32 execution | 4688 | 2025-03-15T14:22:37.882Z | rundll32.exe |

**Time delta between events:** 27.44 seconds

Raw telemetry stored at: `telemetry/raw/T1059.001_encoded_ps.json`

---

## Pipeline Validation Result

```bash
python Pipeline/run_pipeline.py \
  --input telemetry/raw/T1059.001_encoded_ps.json \
  --output reports/T1059.001_validation.json \
  --window 60
```

**Output:**
```
[+] Ingested 2 raw events
[+] Normalised 2 events
[SCHEMA] total=2 valid=2 rejected=0 pass_rate=100.0%
[+] Detections fired: 1
```

**Alert fired:** `DET-CHAIN-T1059.001-T1218.011-v1`
**Severity:** high
**Delta captured:** 27.44 seconds (within 60s window)
**Result:** ✅ True Positive

---

## False Positive Baseline

Clean baseline replay against `telemetry/raw/clean_baseline.json`:

```
[+] Detections fired: 0
```

**Result:** ✅ Zero false positives on clean baseline

---

## Detection Validation Summary

| Metric | Value |
|---|---|
| True positives | 1 |
| False positives (clean baseline) | 0 |
| Time delta (attack execution → alert) | 27.44s |
| Schema validation pass rate | 100% |
| Correlation window used | 60s |
