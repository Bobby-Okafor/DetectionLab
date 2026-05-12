"""
ingest.py — Log ingestion layer

Handles multi-encoding file reads and input structure normalisation.
Supports UTF-8, UTF-8-BOM, UTF-16, and Latin-1 encoded JSON files.
Returns a flat list of event dicts regardless of input shape.
"""

import json
import sys
from pathlib import Path
from typing import Any


SUPPORTED_ENCODINGS = ["utf-8-sig", "utf-16", "utf-8", "latin-1"]


def load_json(filepath: str | Path) -> list[dict]:
    """
    Load a JSON file and return a flat list of event dicts.
    Tries multiple encodings before failing.
    Accepts either a JSON list or a single JSON object at root.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {filepath}")

    raw = _read_with_encoding_fallback(path)
    return _normalise_structure(raw, source=str(filepath))


def _read_with_encoding_fallback(path: Path) -> Any:
    last_error = None

    for encoding in SUPPORTED_ENCODINGS:
        try:
            with open(path, "r", encoding=encoding) as f:
                return json.load(f)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except json.JSONDecodeError as e:
            last_error = e
            continue

    raise ValueError(
        f"Failed to parse {path.name} as valid JSON. "
        f"Tried encodings: {SUPPORTED_ENCODINGS}. "
        f"Last JSON error: {last_error}"
    )


def _normalise_structure(data: Any, source: str) -> list[dict]:
    """
    Coerce root-level JSON structure into a flat list of event dicts.
    Logs a warning for unexpected shapes rather than silently failing.
    """
    if isinstance(data, list):
        valid = [e for e in data if isinstance(e, dict)]
        dropped = len(data) - len(valid)
        if dropped:
            print(
                f"[WARN] ingest: dropped {dropped} non-dict entries from {source}",
                file=sys.stderr,
            )
        return valid

    if isinstance(data, dict):
        # Some exporters wrap events under a key like "Events" or "Records"
        for wrapper_key in ("Events", "Records", "events", "records", "value"):
            if wrapper_key in data and isinstance(data[wrapper_key], list):
                print(
                    f"[INFO] ingest: unwrapped '{wrapper_key}' key in {source}",
                    file=sys.stderr,
                )
                return _normalise_structure(data[wrapper_key], source)

        # Single event object — wrap it
        return [data]

    raise ValueError(
        f"Unexpected JSON root type '{type(data).__name__}' in {source}. "
        "Expected a list of events or a single event object."
    )
