"""
replay_harness.py — Detection regression test runner

Replays known Atomic Red Team telemetry samples through the full pipeline
and asserts expected detection outcomes. Each test case specifies:
  - input telemetry file
  - expected alert count
  - expected detection IDs
  - expected alert fields for spot-checking

Used to:
  1. Validate new detections against known-good telemetry
  2. Regression-test normalisation changes against existing detections
  3. Measure false positive rate against clean baseline telemetry

Run:
    python Pipeline/replay_harness.py --suite all
    python Pipeline/replay_harness.py --suite endpoint
    python Pipeline/replay_harness.py --test T1059.001_encoded_ps_chain
"""

import argparse
import json
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Pipeline imports
sys.path.insert(0, str(Path(__file__).parent))
from ingest import load_json
from normalize import normalize_events
from schema_validator import validate_events
from detect import run_all_detections


# ---------------------------------------------------------------------------
# Test case definitions
# ---------------------------------------------------------------------------

@dataclass
class ReplayTestCase:
    name:               str
    suite:              str
    telemetry_file:     str
    expected_alerts:    int
    expected_detection_ids: list[str] = field(default_factory=list)
    expected_fields:    dict          = field(default_factory=dict)
    description:        str           = ""
    clean_baseline:     bool          = False  # True = expect zero alerts


TEST_CASES: list[ReplayTestCase] = [
    ReplayTestCase(
        name="T1059.001_encoded_ps_chain",
        suite="endpoint",
        telemetry_file="telemetry/raw/T1059.001_encoded_ps.json",
        expected_alerts=1,
        expected_detection_ids=["DET-CHAIN-T1059.001-T1218.011-v1"],
        expected_fields={"severity": "high", "mitre_techniques": ["T1059.001", "T1218.011"]},
        description="Encoded PowerShell followed by rundll32 within 60s correlation window",
    ),
    ReplayTestCase(
        name="T1110.001_brute_force",
        suite="identity",
        telemetry_file="telemetry/raw/T1110.001_brute_force.json",
        expected_alerts=1,
        expected_detection_ids=["DET-IDENTITY-T1110.001-BruteForce-v1"],
        expected_fields={"severity": "medium"},
        description="Five or more failed logons for the same user within 60s",
    ),
    ReplayTestCase(
        name="T1078_priv_logon",
        suite="identity",
        telemetry_file="telemetry/raw/T1078_priv_logon.json",
        expected_alerts=1,
        expected_detection_ids=["DET-IDENTITY-T1078-PrivLogon-v1"],
        expected_fields={"severity": "medium"},
        description="Administrator account logon via network logon type 3",
    ),
    ReplayTestCase(
        name="clean_baseline_no_alerts",
        suite="baseline",
        telemetry_file="telemetry/raw/clean_baseline.json",
        expected_alerts=0,
        description="Clean environment — expect zero alerts across all detections",
        clean_baseline=True,
    ),
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    name:    str
    passed:  bool
    message: str
    alerts:  list[dict] = field(default_factory=list)


def run_test(tc: ReplayTestCase, verbose: bool = False) -> TestResult:
    telemetry_path = Path(tc.telemetry_file)

    if not telemetry_path.exists():
        return TestResult(
            name=tc.name,
            passed=False,
            message=f"SKIP — telemetry file not found: {tc.telemetry_file}",
        )

    try:
        raw_events      = load_json(telemetry_path)
        normalised      = normalize_events(raw_events)
        valid, rejected = validate_events(normalised)
        alerts          = run_all_detections(valid)
    except Exception as e:
        return TestResult(
            name=tc.name,
            passed=False,
            message=f"PIPELINE ERROR — {type(e).__name__}: {e}\n{traceback.format_exc()}",
        )

    failures: list[str] = []

    # Assert alert count
    if len(alerts) != tc.expected_alerts:
        failures.append(
            f"alert_count: expected={tc.expected_alerts} got={len(alerts)}"
        )

    # Assert detection IDs present
    fired_ids = {a["detection_id"] for a in alerts}
    for expected_id in tc.expected_detection_ids:
        if expected_id not in fired_ids:
            failures.append(f"missing_detection_id: {expected_id}")

    # Spot-check expected fields on first alert
    if alerts and tc.expected_fields:
        first_alert = alerts[0]
        for field_name, expected_val in tc.expected_fields.items():
            actual_val = first_alert.get(field_name)
            if actual_val != expected_val:
                failures.append(
                    f"field_mismatch:{field_name} "
                    f"expected={expected_val} got={actual_val}"
                )

    if failures:
        return TestResult(
            name=tc.name,
            passed=False,
            message=f"FAIL — {'; '.join(failures)}",
            alerts=alerts,
        )

    return TestResult(
        name=tc.name,
        passed=True,
        message=f"PASS — {tc.expected_alerts} alert(s) as expected",
        alerts=alerts,
    )


def run_suite(suite_name: str, verbose: bool = False) -> int:
    """Run all test cases matching the suite name. Returns exit code."""
    if suite_name == "all":
        cases = TEST_CASES
    else:
        cases = [tc for tc in TEST_CASES if tc.suite == suite_name]

    if not cases:
        print(f"[ERROR] No test cases found for suite '{suite_name}'", file=sys.stderr)
        return 1

    results: list[TestResult] = []

    print(f"\n{'─' * 60}")
    print(f"  Detection Replay Harness — suite: {suite_name}")
    print(f"{'─' * 60}\n")

    for tc in cases:
        result = run_test(tc, verbose=verbose)
        results.append(result)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"  {status}  {tc.name}")
        print(f"         {result.message}")
        if verbose and result.alerts:
            for a in result.alerts:
                print(f"         → {a.get('detection_id')} | {a.get('reason')}")
        print()

    passed  = sum(1 for r in results if r.passed)
    failed  = sum(1 for r in results if not r.passed)
    skipped = sum(1 for r in results if "SKIP" in r.message)

    print(f"{'─' * 60}")
    print(f"  Results: {passed} passed · {failed} failed · {skipped} skipped")
    print(f"{'─' * 60}\n")

    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Replay detection pipeline against known telemetry samples"
    )
    parser.add_argument(
        "--suite",
        default="all",
        choices=["all", "endpoint", "identity", "network", "baseline"],
        help="Test suite to run (default: all)",
    )
    parser.add_argument(
        "--test",
        default=None,
        help="Run a single named test case",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print alert details for each test",
    )
    args = parser.parse_args()

    if args.test:
        tc = next((t for t in TEST_CASES if t.name == args.test), None)
        if not tc:
            print(f"[ERROR] Test case '{args.test}' not found.", file=sys.stderr)
            sys.exit(1)
        result = run_test(tc, verbose=args.verbose)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"\n{status}  {tc.name}: {result.message}\n")
        sys.exit(0 if result.passed else 1)
    else:
        exit_code = run_suite(args.suite, verbose=args.verbose)
        sys.exit(exit_code)
