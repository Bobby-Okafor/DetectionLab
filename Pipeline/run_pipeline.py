"""
run_pipeline.py — Detection pipeline CLI entry point

Executes the full pipeline:
    ingest → normalise → validate schema → detect → output alerts

Usage:
    python Pipeline/run_pipeline.py \
        --input telemetry/raw/sample_4688_sysmon.json \
        --output reports/pipeline_run_output.json \
        --window 60 \
        --brute-threshold 5 \
        --strict-schema
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root or Pipeline/ directory
sys.path.insert(0, str(Path(__file__).parent))

from ingest import load_json
from normalize import normalize_events
from schema_validator import validate_events, validate_schema_drift
from detect import run_all_detections


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detection-Lab pipeline runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to raw log JSON file",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write alerts JSON (default: stdout)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Correlation window in seconds for stateful detections (default: 60)",
    )
    parser.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        help="Failed logon count threshold for brute force detection (default: 5)",
    )
    parser.add_argument(
        "--strict-schema",
        action="store_true",
        help="Reject events with warn-only schema violations (default: False)",
    )
    parser.add_argument(
        "--drift-check",
        action="store_true",
        help="Run schema drift analysis against expected field baseline",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress pipeline diagnostic output (stderr)",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------
    try:
        raw_events = load_json(args.input)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] Ingest failed: {e}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[+] Ingested {len(raw_events)} raw events from {args.input}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Normalise
    # ------------------------------------------------------------------
    normalised = normalize_events(raw_events)

    if not args.quiet:
        print(f"[+] Normalised {len(normalised)} events", file=sys.stderr)

    # ------------------------------------------------------------------
    # Schema validation
    # ------------------------------------------------------------------
    valid_events, rejected_events = validate_events(
        normalised, strict=args.strict_schema
    )

    if rejected_events and not args.quiet:
        print(
            f"[WARN] {len(rejected_events)} events rejected by schema validation",
            file=sys.stderr,
        )

    # ------------------------------------------------------------------
    # Optional schema drift analysis
    # ------------------------------------------------------------------
    if args.drift_check:
        drift = validate_schema_drift(normalised)
        if drift:
            print(f"[WARN] Schema drift detected across {len(drift)} event type(s)", file=sys.stderr)

    # ------------------------------------------------------------------
    # Detect
    # ------------------------------------------------------------------
    alerts = run_all_detections(
        valid_events,
        window_seconds=args.window,
        brute_force_threshold=args.brute_threshold,
    )

    if not args.quiet:
        print(f"[+] Detections fired: {len(alerts)}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    run_metadata = {
        "_pipeline_run": {
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "input_file":      args.input,
            "raw_event_count": len(raw_events),
            "normalised_count": len(normalised),
            "rejected_count":  len(rejected_events),
            "alert_count":     len(alerts),
            "window_seconds":  args.window,
        }
    }

    output_payload = {**run_metadata, "alerts": alerts}

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2)
        if not args.quiet:
            print(f"[+] Alerts written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output_payload, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
