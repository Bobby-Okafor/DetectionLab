# Detection-Lab

**Detection as Code portfolio** — validated detections built across endpoint, identity, and network telemetry using Atomic Red Team adversary simulation, Python normalization pipelines, and KQL-based detection logic deployed against Microsoft Sentinel-compatible schemas.

Every detection in this repository was developed against controlled telemetry, validated through replay-based testing, and documented with true positive evidence before being committed.

---

## Repository Philosophy

Detections are treated as measurable systems, not isolated rules. Each detection has:

- A hypothesis grounded in a specific adversary behaviour
- A mapped data source with field-level schema requirements
- Validation evidence from Atomic Red Team execution
- A false positive baseline from clean environment replay
- A versioned detection ID traceable through the pipeline

---

## ATT&CK Coverage Matrix

| Detection ID | Technique | Sub-Technique | Behaviour | Data Source | Status |
|---|---|---|---|---|---|
| DET-ENDPOINT-T1059.001-EncodedPS-v1 | T1059 | T1059.001 | Encoded PowerShell execution | Sysmon EID 1, WinSec 4688 | ✅ Validated |
| DET-ENDPOINT-T1218.011-LOLBin-v1 | T1218 | T1218.011 | rundll32 LOLBin execution | Sysmon EID 1, WinSec 4688 | ✅ Validated |
| DET-CHAIN-T1059.001-T1218.011-v1 | T1059 + T1218 | .001 + .011 | Encoded PS → rundll32 chain | Sysmon EID 1, WinSec 4688 | ✅ Validated |
| DET-IDENTITY-T1110.001-BruteForce-v1 | T1110 | T1110.001 | Failed logon burst, single source | WinSec 4625 | ✅ Validated |
| DET-IDENTITY-T1078-PrivLogon-v1 | T1078 | T1078.002 | Privileged account logon anomaly | WinSec 4624 | ✅ Validated |
| DET-NETWORK-T1071.001-C2Beacon-v1 | T1071 | T1071.001 | Process-to-network C2 pattern | Sysmon EID 3 | 🔄 In Progress |
| DET-PERSIST-T1053.005-SchedTask-v1 | T1053 | T1053.005 | Scheduled task created via PS | WinSec 4698, Sysmon EID 1 | 🔄 In Progress |
| DET-PERSIST-T1547.001-RunKey-v1 | T1547 | T1547.001 | Registry Run Key persistence | Sysmon EID 13 | 📋 Planned |

**Coverage:** 5 validated · 2 in progress · 1 planned

---

## Repository Structure

```text
Detection-Lab/
│
├── Detections/                         # Detection rule definitions (Python + metadata)
│   ├── DET-ENDPOINT-T1059.001-EncodedPS-v1/
│   ├── DET-ENDPOINT-T1218.011-LOLBin-v1/
│   ├── DET-CHAIN-T1059.001-T1218.011-v1/
│   ├── DET-IDENTITY-T1110.001-BruteForce-v1/
│   └── DET-IDENTITY-T1078-PrivLogon-v1/
│
├── Pipeline/                           # Normalisation, validation, and alert engine
│   ├── ingest.py                       # Multi-encoding log ingestion
│   ├── normalize.py                    # Field extraction and schema enforcement
│   ├── schema_validator.py             # Schema contract assertions
│   ├── detect.py                       # Stateful detection engine
│   ├── alert_schema.py                 # Structured alert output model
│   ├── replay_harness.py               # Regression test runner
│   └── run_pipeline.py                 # CLI entry point
│
├── telemetry/                          # Raw and normalised log samples
│   ├── raw/                            # Unprocessed Sysmon + WinSec JSON
│   └── normalised/                     # Post-pipeline schema-aligned output
│
├── attack_runs/                        # Atomic Red Team execution records
│   ├── T1059.001/
│   ├── T1110.001/
│   └── T1218.011/
│
├── reports/                            # Validation reports per detection
│
├── sigma/                              # Sigma rule definitions
│
├── kql/                                # KQL queries for Microsoft Sentinel
│
├── spl/                                # SPL equivalents for Splunk portability
│
├── playbooks/                          # Analyst response playbooks
│
└── .github/
    └── workflows/
        └── validate_pipeline.yml       # CI validation on push
```

---

## Pipeline Architecture

```
Raw Log (JSON)
      │
      ▼
 [ ingest.py ]  ←── multi-encoding, list/dict normalisation
      │
      ▼
[ normalize.py ] ←── field extraction, timestamp unification, host enrichment
      │
      ▼
[ schema_validator.py ] ←── required field assertions, drift detection
      │
      ▼
[ detect.py ]  ←── stateful correlation engine, windowed chain detection
      │
      ▼
[ alert_schema.py ] ←── structured alert with detection ID, MITRE mapping, evidence
      │
      ▼
   Alerts JSON  ──► replay_harness.py (regression validation)
                ──► reports/ (validation documentation)
                ──► Sentinel DCR / SIEM ingest (production path)
```

---

## Atomic Red Team Validation Methodology

Each detection follows this validation cycle before being marked as validated:

1. **Simulation** — Execute the relevant Atomic Red Team test against the lab endpoint
2. **Telemetry capture** — Collect raw Sysmon and Windows Security event JSON
3. **Pipeline replay** — Feed raw logs through the normalisation and detection pipeline
4. **True positive assertion** — Confirm the expected alert fires with correct fields
5. **False positive baseline** — Replay clean environment logs and confirm zero alerts
6. **Documentation** — Record all results in `reports/` with timestamp delta and evidence

---

## Detection Naming Convention

```
DET-{SCOPE}-{TECHNIQUE}.{SUBTECHNIQUE}-{BEHAVIOUR}-v{VERSION}

DET-ENDPOINT-T1059.001-EncodedPS-v1
│    │          │          │       │
│    │          │          │       └─ Version
│    │          │          └───────── Short behaviour label
│    │          └──────────────────── MITRE technique + sub-technique
│    └─────────────────────────────── Telemetry scope
└──────────────────────────────────── Detection prefix
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Bobby-Okafor/Detection-Lab.git
cd Detection-Lab

# Install dependencies
pip install -r requirements.txt

# Run pipeline against a telemetry sample
python Pipeline/run_pipeline.py \
  --input telemetry/raw/sample_4688_sysmon.json \
  --output reports/pipeline_run_output.json \
  --window 60

# Run regression validation
python Pipeline/replay_harness.py --suite all
```

---

## Tools and Data Sources

| Layer | Tool / Source |
|---|---|
| Adversary simulation | Atomic Red Team (Invoke-AtomicRedTeam) |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config), Windows Security Auditing |
| SIEM / detection language | Microsoft Sentinel, KQL |
| Normalisation pipeline | Python 3.11+ |
| Detection format | Python rules + Sigma |
| Version control | Git, GitHub Actions CI |

---

## Author

**Bobby Okafor**
Detection Engineer — endpoint, identity, and network telemetry
[GitHub](https://github.com/Bobby-Okafor) · [LinkedIn](https://www.linkedin.com/in/bobby-okafor-40a521380)
