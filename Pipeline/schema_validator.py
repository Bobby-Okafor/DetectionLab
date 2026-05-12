"""
schema_validator.py — Schema contract enforcement layer

Asserts that normalised events conform to the expected field contracts
before they enter the detection engine. Schema drift (missing or
type-mismatched fields) is surfaced explicitly rather than causing
silent detection failures downstream.
"""

import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Schema contracts per event type
# ---------------------------------------------------------------------------

# Each contract defines:
#   required  — fields that must be present and non-None for the event to be valid
#   typed     — fields that must be a specific Python type if present
#   warn_only — fields whose absence triggers a warning but not a rejection

SCHEMA_CONTRACTS: dict[int, dict] = {
    4688: {
        "required":  ["event_id", "time", "process_name"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["parent_process", "command_line", "user", "host"],
    },
    4624: {
        "required":  ["event_id", "time", "user", "logon_type"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["src_ip", "host", "domain"],
    },
    4625: {
        "required":  ["event_id", "time", "user"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["src_ip", "host", "domain", "failure_reason"],
    },
    3: {
        "required":  ["event_id", "time", "process_name", "dst_ip"],
        "typed":     {"event_id": int, "time": str},
        "warn_only": ["dst_port", "src_ip", "user", "host"],
    },
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_events(
    events: list[dict],
    strict: bool = False,
) -> tuple[list[dict], list[dict]]:
    """
    Validate a list of normalised events against their schema contracts.

    Args:
        events: List of normalised event dicts from normalize.py
        strict: If True, events with warn_only violations are also rejected

    Returns:
        (valid_events, rejected_events)
        Rejected events include a 'schema_violations' field listing failures.
    """
    valid = []
    rejected = []

    for event in events:
        violations, warnings = _check_event(event)

        if violations:
            event["schema_violations"] = violations
            event["schema_warnings"]   = warnings
            rejected.append(event)
            print(
                f"[SCHEMA REJECT] event_id={event.get('event_id')} "
                f"time={event.get('time')} "
                f"violations={violations}",
                file=sys.stderr,
            )
        elif warnings:
            event["schema_warnings"] = warnings
            print(
                f"[SCHEMA WARN] event_id={event.get('event_id')} "
                f"time={event.get('time')} "
                f"warnings={warnings}",
                file=sys.stderr,
            )
            if strict:
                event["schema_violations"] = warnings
                rejected.append(event)
            else:
                valid.append(event)
        else:
            valid.append(event)

    _print_summary(len(events), len(valid), len(rejected))
    return valid, rejected


def validate_schema_drift(
    events: list[dict],
    baseline_fields: Optional[dict[int, set]] = None,
) -> dict[int, set]:
    """
    Detect schema drift by comparing observed fields to a known baseline.

    Returns a dict of {event_id: set_of_missing_fields}.
    If no baseline is provided, uses the required fields from SCHEMA_CONTRACTS.
    """
    drift_report: dict[int, set] = {}

    for event in events:
        eid = event.get("event_id")
        if eid not in SCHEMA_CONTRACTS:
            continue

        contract = SCHEMA_CONTRACTS[eid]
        expected = set(baseline_fields.get(eid, [])) if baseline_fields else set(
            contract["required"] + contract.get("warn_only", [])
        )
        present = {k for k, v in event.items() if v is not None}
        missing = expected - present

        if missing:
            if eid not in drift_report:
                drift_report[eid] = set()
            drift_report[eid].update(missing)

    if drift_report:
        for eid, fields in drift_report.items():
            print(
                f"[SCHEMA DRIFT] event_id={eid} missing_fields={sorted(fields)}",
                file=sys.stderr,
            )

    return drift_report


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------

def _check_event(event: dict) -> tuple[list[str], list[str]]:
    eid = event.get("event_id")
    violations: list[str] = []
    warnings:   list[str] = []

    if eid not in SCHEMA_CONTRACTS:
        return violations, warnings

    contract = SCHEMA_CONTRACTS[eid]

    # Required field presence
    for field in contract["required"]:
        if event.get(field) is None:
            violations.append(f"missing_required:{field}")

    # Type assertions
    for field, expected_type in contract.get("typed", {}).items():
        value = event.get(field)
        if value is not None and not isinstance(value, expected_type):
            violations.append(
                f"type_mismatch:{field} expected={expected_type.__name__} "
                f"got={type(value).__name__}"
            )

    # Warn-only fields
    for field in contract.get("warn_only", []):
        if event.get(field) is None:
            warnings.append(f"missing_optional:{field}")

    return violations, warnings


def _print_summary(total: int, valid: int, rejected: int) -> None:
    print(
        f"[SCHEMA] total={total} valid={valid} rejected={rejected} "
        f"pass_rate={round(valid / total * 100, 1) if total else 0}%",
        file=sys.stderr,
    )
