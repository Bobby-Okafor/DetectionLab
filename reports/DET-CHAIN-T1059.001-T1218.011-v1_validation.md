# Validation Report — DET-CHAIN-T1059.001-T1218.011-v1

**Detection ID:** DET-CHAIN-T1059.001-T1218.011-v1
**Detection Name:** Encoded PowerShell → LOLBin Execution Chain
**Validation Date:** 2025-03-15
**Pipeline Version:** 1.0.0
**Status:** ✅ Validated

---

## Detection Summary

Stateful correlation detection identifying encoded PowerShell execution followed
by a LOLBin process within a 60-second window on the same host and user context.
Targets adversary use of Base64-encoded commands to obfuscate execution intent
before handing off to a signed Windows binary for payload delivery.

**Techniques:** T1059.001, T1218.011
**Data sources:** Windows Security EID 4688, Sysmon EID 1

---

## Atomic Red Team Test Executed

| Field | Value |
|---|---|
| Atomic Test | T1059.001-4 — PowerShell Base64 Encoded Command |
| Lab Host | DESKTOP-LAB01 |
| Operator | Bobby Okafor |
| Execution Time | 2025-03-15T14:22:10Z |
| Follow-on | Manual rundll32 invocation 27s post-execution |

---

## True Positive Evidence

**Pipeline command:**
```bash
python Pipeline/run_pipeline.py \
  --input telemetry/raw/T1059.001_encoded_ps.json \
  --output reports/T1059.001_validation.json \
  --window 60
```

**Alert fired:**

```json
{
  "detection_id": "DET-CHAIN-T1059.001-T1218.011-v1",
  "severity": "high",
  "confidence": "high",
  "alert_type": "ENCODED_PS_LOLBIN_CHAIN",
  "reason": "Encoded PowerShell followed by rundll32.exe within 27.44s",
  "time_start": "2025-03-15T14:22:10.441000+00:00",
  "time_end": "2025-03-15T14:22:37.882000+00:00",
  "delta_seconds": 27.44,
  "user": "bobby",
  "host": "DESKTOP-LAB01",
  "mitre_techniques": ["T1059.001", "T1218.011"]
}
```

---

## False Positive Baseline

**Test:** Clean environment replay (normal user activity, no attack simulation)
**Telemetry:** `telemetry/raw/clean_baseline.json`
**Alerts fired:** 0

No false positives observed on clean baseline telemetry.

---

## Validation Metrics

| Metric | Value |
|---|---|
| True positive count | 1 |
| False positive count (baseline) | 0 |
| Schema validation pass rate | 100% |
| Time delta (PS execution → rundll32) | 27.44s |
| Detection window | 60s |
| Events processed | 2 |
| Events rejected by schema | 0 |

---

## Known Limitations and Tuning Notes

Legitimate false positive sources for this detection:

- Administrative scripts that use encoded commands for string handling and then
  invoke rundll32 for COM object registration (e.g. during software deployment)
- SCCM/Intune agent activity on managed endpoints

**Recommended suppression:** Allowlist known deployment tool parent processes
(e.g. `ccmexec.exe`) in the detection logic when deploying to production.

---

## Sigma and KQL Artefacts

| Format | File |
|---|---|
| Sigma | `sigma/DET-CHAIN-T1059.001-T1218.011-v1.yml` |
| KQL (Sentinel) | `kql/DET-CHAIN-T1059.001-T1218.011-v1.kql` |
| Python rule | `Pipeline/detect.py — detect_encoded_ps_lolbin_chain()` |
