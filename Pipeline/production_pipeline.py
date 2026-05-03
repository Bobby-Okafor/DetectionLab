
import json
import re
from datetime import datetime, timezone


# ----------------------------
# INGESTION
# ----------------------------

def load_json(file):
    for enc in ["utf-8-sig", "utf-16", "utf-8"]:
        try:
            with open(file, "r", encoding=enc) as f:
                return json.load(f)
        except Exception:
            continue
    raise ValueError("Unable to decode file")


# ----------------------------
# NORMALIZATION
# ----------------------------

def parse_4688(message):
    fields = {}
    for line in message.split("\n"):
        if "New Process Name:" in line:
            fields["process_name"] = line.split(":", 1)[1].strip()
        elif "Creator Process Name:" in line:
            fields["parent_process"] = line.split(":", 1)[1].strip()
        elif "Process Command Line:" in line:
            fields["command_line"] = line.split(":", 1)[1].strip()
        elif "Account Name:" in line:
            fields["user"] = line.split(":", 1)[1].strip()
    return fields


def extract_time(event):
    tc = event.get("TimeCreated")
    if isinstance(tc, dict):
        return tc.get("SystemTime") or tc.get("DateTime")
    return tc


def convert_time(raw_time):
    if not raw_time:
        return None

    match = re.search(r"\d+", str(raw_time))
    if not match:
        return raw_time

    timestamp_ms = int(match.group())
    timestamp_sec = timestamp_ms / 1000

    return datetime.fromtimestamp(timestamp_sec, tz=timezone.utc).isoformat()


def normalize_events(events):
    normalized = []

    for e in events:
        if e.get("Id") == 4688:
            parsed = parse_4688(e.get("Message", ""))

            parsed["event_id"] = 4688
            parsed["time"] = convert_time(extract_time(e))

            normalized.append(parsed)

    return sorted(normalized, key=lambda x: to_epoch(x.get("time")))


# ----------------------------
# TIME UTILS
# ----------------------------

def to_epoch(ts):
    if not ts:
        return 0
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0


# ----------------------------
# DETECTION ENGINE
# ----------------------------

def detect_stateful(events, window_seconds=60):
    alerts = []
    seen = set()

    for i in range(len(events)):
        e1 = events[i]

        t1 = to_epoch(e1.get("time"))
        process1 = e1.get("process_name", "").lower()
        cmd1 = e1.get("command_line", "").lower()

        is_encoded_ps = (
            "powershell" in process1 and
            ("-enc" in cmd1 or "encodedcommand" in cmd1)
        )

        if not is_encoded_ps:
            continue

        for j in range(i + 1, len(events)):
            e2 = events[j]
            t2 = to_epoch(e2.get("time"))

            if t2 - t1 > window_seconds:
                break

            process2 = e2.get("process_name", "").lower()

            if "rundll32.exe" in process2:
                key = (process1, process2, cmd1)

                if key not in seen:
                    seen.add(key)

                    alerts.append({
                        "type": "STATEFUL_LOLBIN_CHAIN",
                        "severity": "high",
                        "reason": f"Encoded PowerShell → rundll32 within {round(t2 - t1, 2)}s",
                        "t_start": e1.get("time"),
                        "t_end": e2.get("time"),
                        "process_1": process1,
                        "process_2": process2,
                        "command_line": cmd1,
                    })

                break

    return alerts


# ----------------------------
# EXECUTION
# ----------------------------

if __name__ == "__main__":
    data = load_json("pipeline/sample_logs.json")
    events = data if isinstance(data, list) else [data]

    normalized = normalize_events(events)
    alerts = detect_stateful(normalized)

    print(f"[+] Alerts found: {len(alerts)}")

    for a in alerts:
        print(a)
