"""
alert_schema.py — Structured alert output model

Produces consistent, SIEM-ingestible alert dicts with stable field names,
MITRE technique mapping, evidence references, and pipeline traceability.
All alerts emitted by detect.py are built through this module.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional


PIPELINE_VERSION = "1.0.0"


def build_alert(
    detection_id: str,
    techniques: list[str],
    severity: str,
    confidence: str,
    alert_type: str,
    reason: str,
    e1: dict,
    e2: Optional[dict],
    delta_seconds: Optional[float],
    extra: Optional[dict] = None,
) -> dict:
    """
    Build a structured alert dict from detection context.

    Args:
        detection_id:   Canonical detection identifier (e.g. DET-CHAIN-T1059.001-T1218.011-v1)
        techniques:     List of MITRE ATT&CK technique IDs
        severity:       'critical' | 'high' | 'medium' | 'low'
        confidence:     'high' | 'medium' | 'low'
        alert_type:     Short machine-readable alert type label
        reason:         Human-readable description of why this alert fired
        e1:             First (anchor) event in the correlation
        e2:             Second event (None for single-event detections)
        delta_seconds:  Time delta between e1 and e2 (None for single-event)
        extra:          Detection-specific additional fields

    Returns:
        Structured alert dict with stable schema
    """
    now_utc = datetime.now(timezone.utc).isoformat()

    alert = {
        # Identity
        "alert_id":          str(uuid.uuid4()),
        "detection_id":      detection_id,
        "pipeline_version":  PIPELINE_VERSION,

        # Classification
        "alert_type":        alert_type,
        "severity":          _validate_severity(severity),
        "confidence":        _validate_confidence(confidence),
        "mitre_techniques":  techniques,

        # Description
        "reason":            reason,

        # Timeline
        "time_start":        e1.get("time"),
        "time_end":          e2.get("time") if e2 else e1.get("time"),
        "delta_seconds":     delta_seconds,
        "generated_at":      now_utc,

        # Host and identity context
        "host":              e1.get("host") or (e2.get("host") if e2 else None),
        "user":              e1.get("user") or (e2.get("user") if e2 else None),

        # Data sources
        "data_sources": _collect_data_sources(e1, e2),

        # Evidence — inline event references for replay traceability
        "evidence": {
            "event_1": _event_summary(e1),
            "event_2": _event_summary(e2) if e2 else None,
        },
    }

    # Merge detection-specific fields
    if extra:
        alert["detail"] = extra

    return alert


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_severity(severity: str) -> str:
    valid = {"critical", "high", "medium", "low", "informational"}
    if severity.lower() not in valid:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of {valid}.")
    return severity.lower()


def _validate_confidence(confidence: str) -> str:
    valid = {"high", "medium", "low"}
    if confidence.lower() not in valid:
        raise ValueError(f"Invalid confidence '{confidence}'. Must be one of {valid}.")
    return confidence.lower()


def _collect_data_sources(e1: dict, e2: Optional[dict]) -> list[str]:
    sources = set()
    for e in (e1, e2):
        if e and e.get("data_source"):
            sources.add(e["data_source"])
    return sorted(sources)


def _event_summary(event: Optional[dict]) -> Optional[dict]:
    if not event:
        return None
    return {
        "event_id":     event.get("event_id"),
        "time":         event.get("time"),
        "host":         event.get("host"),
        "user":         event.get("user"),
        "process_name": event.get("process_name"),
        "command_line": event.get("command_line"),
        "src_ip":       event.get("src_ip"),
        "dst_ip":       event.get("dst_ip"),
    }
