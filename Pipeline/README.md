# Pipeline — Detection Engineering Core

This directory contains the complete Python detection pipeline: ingestion,
normalisation, schema validation, stateful detection, and replay-based
regression testing.

---

## Module Architecture

```
ingest.py           Multi-encoding JSON ingestion. Handles UTF-8, UTF-16,
                    UTF-8-BOM, and Latin-1. Normalises list and dict root
                    structures. Returns a flat list of raw event dicts.

normalize.py        Field extraction per event type (4688, 4624, 4625, Sysmon 3).
                    Timestamp normalisation across FILETIME, epoch_ms, epoch_s,
                    and ISO 8601. Enriches events with host, parse quality flags.

schema_validator.py Contract assertion layer. Required field checks, type
                    validation, and schema drift detection. Returns (valid, rejected)
                    tuple. Rejected events include violation details.

detect.py           Stateful correlation engine. Windowed multi-event detections.
                    Deduplication with time-bucket keying per user context.
                    All alerts built through alert_schema.py for field consistency.

alert_schema.py     Structured alert output model. Stable field schema for SIEM
                    ingest (Sentinel DCR, flat file, webhook). Includes detection ID,
                    MITRE mapping, evidence references, and pipeline version.

replay_harness.py   Regression test runner. Replays known Atomic Red Team telemetry
                    samples and asserts expected detection outcomes. Supports suite
                    and individual test execution. Returns non-zero exit code on failure.

run_pipeline.py     CLI entry point. Wires ingest → normalise → validate → detect
                    → output. Accepts --input, --output, --window, --brute-threshold,
                    --strict-schema, --drift-check, --quiet flags.
```

---

## Active Detections

| Detection ID | Function | Techniques | Window |
|---|---|---|---|
| DET-CHAIN-T1059.001-T1218.011-v1 | `detect_encoded_ps_lolbin_chain` | T1059.001, T1218.011 | 60s |
| DET-IDENTITY-T1110.001-BruteForce-v1 | `detect_brute_force` | T1110.001 | 60s |
| DET-IDENTITY-T1078-PrivLogon-v1 | `detect_priv_logon_anomaly` | T1078.002 | single-event |

---

## Running the Pipeline

```bash
# Full pipeline run against Atomic telemetry sample
python Pipeline/run_pipeline.py \
  --input telemetry/raw/T1059.001_encoded_ps.json \
  --output reports/run_output.json \
  --window 60

# Run with schema drift analysis
python Pipeline/run_pipeline.py \
  --input telemetry/raw/T1059.001_encoded_ps.json \
  --drift-check

# Run regression suite
python Pipeline/replay_harness.py --suite all --verbose

# Run single regression test
python Pipeline/replay_harness.py --test T1059.001_encoded_ps_chain
```

---

## Adding a New Detection

1. Add the detection function to `detect.py` following the existing pattern
2. Register it in `run_all_detections()`
3. Add a `ReplayTestCase` entry to `replay_harness.py` with expected telemetry
4. Add the telemetry sample to `telemetry/raw/`
5. Run `replay_harness.py --suite all` to confirm no regressions
6. Add the detection to the ATT&CK coverage matrix in the root `README.md`
7. Create the corresponding KQL in `kql/` and Sigma rule in `sigma/`
8. Document the validation result in `reports/`

---

## Schema Contracts

Expected fields per event type after normalisation:

**EID 4688 (Process Creation)**
- Required: `event_id`, `time`, `process_name`
- Optional (warn): `parent_process`, `command_line`, `user`, `host`

**EID 4624 / 4625 (Logon)**
- Required: `event_id`, `time`, `user`, `logon_type` (4624 only)
- Optional (warn): `src_ip`, `host`, `domain`

**Sysmon EID 3 (Network)**
- Required: `event_id`, `time`, `process_name`, `dst_ip`
- Optional (warn): `dst_port`, `src_ip`, `user`, `host`
