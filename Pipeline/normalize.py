"""
normalize.py — Telemetry normalisation layer

Extracts structured fields from raw Windows Security and Sysmon events.
Enforces UTC timestamp normalisation across FILETIME, epoch_ms, epoch_s,
and ISO 8601 input formats. Enriches events with parse quality metadata.
"""

import re
import sys
from datetime import datetime, timezone
from typing import Optional

# Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01)
WINDOWS_EPOCH_OFFSET = 11_644_473_600

# Field labels present in Windows Security 4688 message text
FIELD_4688_MAP = {
    "New Process Name:":      "process_name",
    "Creator Process Name:":  "parent_process",
    "Process Command Line:":  "command_line",
    "Security ID:":           "security_id",
    "Logon ID:":              "logon_id",
    "Token Elevation Type:":  "elevation_type",
}

# Field labels present in Windows Security 4625 / 4624 message text
FIELD_4624_MAP = {
    "Account Name:":          "user",
    "Account Domain:":        "domain",
    "Logon Type:":            "logon_type",
    "Workstation Name:":      "workstation",
    "Source Network Address:":"src_ip",
    "Source Port:":           "src_port",
    "Logon Process:":         "logon_process",
    "Authentication Package:":"auth_package",
    "Failure Reason:":        "failure_reason",
}

# Field labels present in Sysmon EID 3 (NetworkConnect) message text
FIELD_SYSMON3_MAP = {
    "Image:":                 "process_name",
    "DestinationIp:":         "dst_ip",
    "DestinationPort:":       "dst_port",
    "SourceIp:":              "src_ip",
    "SourcePort:":            "src_port",
    "User:":                  "user",
    "Protocol:":              "protocol",
    "Initiated:":             "initiated",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalize_events(events: list[dict]) -> list[dict]:
    """
    Normalise a list of raw event dicts.
    Returns a sorted list of normalised events with parse quality metadata.
    Events that cannot be normalised are included with a parse_error field
    rather than silently dropped.
    """
    normalised = []

    for raw in events:
        event_id = raw.get("Id") or raw.get("EventID") or raw.get("event_id")

        try:
            event_id_int = int(event_id) if event_id is not None else None
        except (ValueError, TypeError):
            event_id_int = None

        if event_id_int == 4688:
            record = _normalise_4688(raw)
        elif event_id_int in (4624, 4625):
            record = _normalise_logon(raw, event_id_int)
        elif event_id_int == 3:
            record = _normalise_sysmon3(raw)
        else:
            # Preserve unknown events with minimal normalisation
            record = {
                "event_id":    event_id_int,
                "time":        _safe_extract_time(raw),
                "parse_note":  f"event_id {event_id_int} has no normalisation handler",
                "_raw":        raw,
            }

        normalised.append(record)

    # Sort ascending by time; events with no timestamp sort to the front
    normalised.sort(key=lambda x: _to_epoch(x.get("time")))
    return normalised


# ---------------------------------------------------------------------------
# Per-event-type normalisers
# ---------------------------------------------------------------------------

def _normalise_4688(raw: dict) -> dict:
    fields = _extract_message_fields(raw.get("Message", ""), FIELD_4688_MAP)

    # Sysmon EID 1 stores fields directly on the event rather than in Message
    if not fields.get("process_name"):
        fields["process_name"] = raw.get("Image") or raw.get("NewProcessName")
    if not fields.get("parent_process"):
        fields["parent_process"] = raw.get("ParentImage") or raw.get("ParentProcessName")
    if not fields.get("command_line"):
        fields["command_line"] = raw.get("CommandLine")
    if not fields.get("user"):
        fields["user"] = raw.get("User") or raw.get("SubjectUserName")

    record = {
        "event_id":      4688,
        "data_source":   "Windows Security 4688 / Sysmon EID 1",
        "time":          _safe_extract_time(raw),
        "host":          _extract_host(raw),
        "process_name":  _clean(fields.get("process_name")),
        "parent_process": _clean(fields.get("parent_process")),
        "command_line":  fields.get("command_line"),
        "user":          _clean(fields.get("user")),
        "security_id":   fields.get("security_id"),
        "logon_id":      fields.get("logon_id"),
        "elevation_type": fields.get("elevation_type"),
    }

    record["_parse_complete"] = all([
        record["process_name"],
        record["time"],
    ])

    if not record["_parse_complete"]:
        record["parse_warning"] = "One or more required fields missing after normalisation"

    return record


def _normalise_logon(raw: dict, event_id: int) -> dict:
    fields = _extract_message_fields(raw.get("Message", ""), FIELD_4624_MAP)

    record = {
        "event_id":       event_id,
        "data_source":    f"Windows Security {event_id}",
        "time":           _safe_extract_time(raw),
        "host":           _extract_host(raw),
        "user":           _clean(fields.get("user")),
        "domain":         _clean(fields.get("domain")),
        "logon_type":     fields.get("logon_type"),
        "src_ip":         _clean(fields.get("src_ip")),
        "src_port":       fields.get("src_port"),
        "workstation":    _clean(fields.get("workstation")),
        "logon_process":  fields.get("logon_process"),
        "auth_package":   fields.get("auth_package"),
        "failure_reason": fields.get("failure_reason"),
        "outcome":        "success" if event_id == 4624 else "failure",
    }

    record["_parse_complete"] = all([record["user"], record["time"]])
    return record


def _normalise_sysmon3(raw: dict) -> dict:
    fields = _extract_message_fields(raw.get("Message", ""), FIELD_SYSMON3_MAP)

    record = {
        "event_id":     3,
        "data_source":  "Sysmon EID 3",
        "time":         _safe_extract_time(raw),
        "host":         _extract_host(raw),
        "process_name": _clean(fields.get("process_name") or raw.get("Image")),
        "dst_ip":       _clean(fields.get("dst_ip") or raw.get("DestinationIp")),
        "dst_port":     fields.get("dst_port") or raw.get("DestinationPort"),
        "src_ip":       _clean(fields.get("src_ip") or raw.get("SourceIp")),
        "src_port":     fields.get("src_port") or raw.get("SourcePort"),
        "user":         _clean(fields.get("user") or raw.get("User")),
        "protocol":     fields.get("protocol"),
        "initiated":    fields.get("initiated"),
    }

    record["_parse_complete"] = all([record["process_name"], record["time"]])
    return record


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_message_fields(message: str, field_map: dict) -> dict:
    """
    Extract labelled fields from Windows event Message text.
    Uses prefix-aware slicing to preserve colons in values (e.g. paths, URLs).
    Does not overwrite the first non-empty value if a label appears twice.
    """
    result = {}
    lines = message.splitlines()

    for line in lines:
        stripped = line.strip()
        for label, key in field_map.items():
            if stripped.startswith(label):
                value = stripped[len(label):].strip()
                if value and value != "-" and key not in result:
                    result[key] = value
                break

    return result


def _safe_extract_time(event: dict) -> Optional[str]:
    """
    Extract and normalise timestamp from multiple possible event structures.
    Returns UTC ISO 8601 string or None with a stderr warning.
    """
    raw_time = (
        event.get("TimeCreated", {}).get("SystemTime")
        if isinstance(event.get("TimeCreated"), dict)
        else event.get("TimeCreated")
           or event.get("SystemTime")
           or event.get("timestamp")
           or event.get("time")
    )

    result = _convert_time(raw_time)

    if result is None and raw_time is not None:
        print(
            f"[WARN] normalize: could not parse timestamp value: {repr(raw_time)}",
            file=sys.stderr,
        )

    return result


def _convert_time(raw_time) -> Optional[str]:
    if raw_time is None:
        return None

    # Already ISO 8601
    if isinstance(raw_time, str) and re.match(r"\d{4}-\d{2}-\d{2}T", raw_time):
        try:
            dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

    # Extract numeric component
    try:
        val = int(re.search(r"\d+", str(raw_time)).group())
    except (AttributeError, ValueError, TypeError):
        return None

    # Determine epoch type by magnitude
    if val > 1_000_000_000_000_000:
        # Windows FILETIME: 100ns intervals since 1601-01-01
        epoch_sec = (val / 10_000_000) - WINDOWS_EPOCH_OFFSET
    elif val > 1_000_000_000_000:
        # Unix epoch milliseconds (13 digits)
        epoch_sec = val / 1_000
    else:
        # Unix epoch seconds (10 digits)
        epoch_sec = float(val)

    try:
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _extract_host(event: dict) -> Optional[str]:
    return (
        event.get("Computer")
        or event.get("hostname")
        or event.get("host")
        or event.get("MachineName")
    )


def _clean(value: Optional[str]) -> Optional[str]:
    """Strip placeholder values that Windows logs emit for unpopulated fields."""
    if not value:
        return None
    placeholders = {"-", "N/A", "n/a", "NULL", "null", "SYSTEM", ""}
    return None if value.strip() in placeholders else value.strip()


# ---------------------------------------------------------------------------
# Time utility (used by detect.py)
# ---------------------------------------------------------------------------

def to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return 0.0
    try:
        return datetime.fromisoformat(ts).timestamp()
    except (ValueError, TypeError):
        return 0.0
