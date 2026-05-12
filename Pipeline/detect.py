"""
detect.py — Stateful detection engine

Implements windowed, multi-event correlation detections.
Each detection function receives the full normalised event list,
a correlation window in seconds, and returns a list of alert dicts
built via alert_schema.py.

Detection inventory:
    detect_encoded_ps_lolbin_chain  — T1059.001 → T1218.011
    detect_brute_force              — T1110.001
    detect_priv_logon_anomaly       — T1078.002
"""

import math
from typing import Optional

from alert_schema import build_alert
from normalize import to_epoch


# ---------------------------------------------------------------------------
# Detection: Encoded PowerShell → LOLBin chain
# DET-CHAIN-T1059.001-T1218.011-v1
# ---------------------------------------------------------------------------

LOLBINS = {
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
}

ENCODED_PS_INDICATORS = ("-enc", "-encodedcommand", "-e ")


def detect_encoded_ps_lolbin_chain(
    events: list[dict],
    window_seconds: int = 60,
) -> list[dict]:
    """
    Detects encoded PowerShell execution followed by a LOLBin process
    spawning within the correlation window.

    Deduplication: per user, per command_line, per LOLBin, per 5-minute bucket.
    """
    alerts = []
    seen: set = set()
    proc_events = [e for e in events if e.get("event_id") == 4688]

    for i, e1 in enumerate(proc_events):
        t1 = to_epoch(e1.get("time"))
        proc1 = (e1.get("process_name") or "").lower()
        cmd1  = (e1.get("command_line") or "").lower()

        is_encoded_ps = (
            "powershell" in proc1
            and any(ind in cmd1 for ind in ENCODED_PS_INDICATORS)
        )

        if not is_encoded_ps:
            continue

        for e2 in proc_events[i + 1:]:
            t2 = to_epoch(e2.get("time"))
            delta = t2 - t1

            if delta > window_seconds:
                break

            proc2 = (e2.get("process_name") or "").lower()
            lolbin_matched = next(
                (lb for lb in LOLBINS if lb in proc2), None
            )

            if not lolbin_matched:
                continue

            dedup_key = (
                e1.get("user") or "",
                proc1,
                lolbin_matched,
                cmd1[:120],                            # truncate for key stability
                math.floor(t1 / 300),                  # 5-minute bucket
            )

            if dedup_key in seen:
                continue

            seen.add(dedup_key)
            alerts.append(
                build_alert(
                    detection_id="DET-CHAIN-T1059.001-T1218.011-v1",
                    techniques=["T1059.001", "T1218.011"],
                    severity="high",
                    confidence="high",
                    alert_type="ENCODED_PS_LOLBIN_CHAIN",
                    reason=(
                        f"Encoded PowerShell followed by {lolbin_matched} "
                        f"within {round(delta, 2)}s"
                    ),
                    e1=e1,
                    e2=e2,
                    delta_seconds=round(delta, 2),
                    extra={
                        "lolbin":      lolbin_matched,
                        "command_line": e1.get("command_line"),
                        "parent_chain": f"{proc1} → {proc2}",
                    },
                )
            )
            break

    return alerts


# ---------------------------------------------------------------------------
# Detection: Brute force — failed logon burst
# DET-IDENTITY-T1110.001-BruteForce-v1
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: list[dict],
    window_seconds: int = 60,
    threshold: int = 5,
) -> list[dict]:
    """
    Detects a burst of failed logon events (EID 4625) for the same user
    within the correlation window.

    Alert fires when threshold is reached; does not re-alert within the
    same window for the same user.
    """
    alerts = []
    seen: set = set()

    failed_logons = [
        e for e in events
        if e.get("event_id") == 4625 and e.get("user")
    ]

    for i, anchor in enumerate(failed_logons):
        user      = anchor.get("user")
        t_anchor  = to_epoch(anchor.get("time"))
        bucket    = math.floor(t_anchor / window_seconds)
        dedup_key = (user, bucket)

        if dedup_key in seen:
            continue

        # Collect all failures for this user within the window
        window_events = [
            e for e in failed_logons
            if e.get("user") == user
            and 0 <= to_epoch(e.get("time")) - t_anchor <= window_seconds
        ]

        if len(window_events) < threshold:
            continue

        seen.add(dedup_key)

        src_ips = list({e.get("src_ip") for e in window_events if e.get("src_ip")})
        hosts   = list({e.get("host") for e in window_events if e.get("host")})

        alerts.append(
            build_alert(
                detection_id="DET-IDENTITY-T1110.001-BruteForce-v1",
                techniques=["T1110.001"],
                severity="medium",
                confidence="high",
                alert_type="BRUTE_FORCE_FAILED_LOGON",
                reason=(
                    f"{len(window_events)} failed logons for '{user}' "
                    f"within {window_seconds}s (threshold={threshold})"
                ),
                e1=anchor,
                e2=window_events[-1],
                delta_seconds=round(
                    to_epoch(window_events[-1].get("time")) - t_anchor, 2
                ),
                extra={
                    "user":         user,
                    "failure_count": len(window_events),
                    "src_ips":      src_ips,
                    "hosts":        hosts,
                    "failure_reason": anchor.get("failure_reason"),
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Detection: Privileged account logon anomaly
# DET-IDENTITY-T1078-PrivLogon-v1
# ---------------------------------------------------------------------------

PRIVILEGED_ACCOUNTS = {
    "administrator",
    "admin",
    "sysadmin",
    "sa",
    "root",
}

SUSPICIOUS_LOGON_TYPES = {
    "3",   # Network
    "10",  # RemoteInteractive (RDP)
}


def detect_priv_logon_anomaly(
    events: list[dict],
) -> list[dict]:
    """
    Detects successful logon (EID 4624) by a known privileged account
    using a suspicious logon type (Network or RemoteInteractive).

    This detection does not require a correlation window — each event
    is evaluated independently against the privilege and logon type criteria.
    """
    alerts = []

    logon_events = [
        e for e in events
        if e.get("event_id") == 4624 and e.get("outcome") == "success"
    ]

    for e in logon_events:
        user       = (e.get("user") or "").lower()
        logon_type = str(e.get("logon_type") or "").strip()

        if user not in PRIVILEGED_ACCOUNTS:
            continue

        if logon_type not in SUSPICIOUS_LOGON_TYPES:
            continue

        alerts.append(
            build_alert(
                detection_id="DET-IDENTITY-T1078-PrivLogon-v1",
                techniques=["T1078.002"],
                severity="medium",
                confidence="medium",
                alert_type="PRIV_ACCOUNT_SUSPICIOUS_LOGON",
                reason=(
                    f"Privileged account '{user}' logged on via "
                    f"logon type {logon_type} from {e.get('src_ip', 'unknown')}"
                ),
                e1=e,
                e2=None,
                delta_seconds=None,
                extra={
                    "user":       user,
                    "logon_type": logon_type,
                    "src_ip":     e.get("src_ip"),
                    "host":       e.get("host"),
                    "domain":     e.get("domain"),
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Dispatcher — run all detections
# ---------------------------------------------------------------------------

def run_all_detections(
    events: list[dict],
    window_seconds: int = 60,
    brute_force_threshold: int = 5,
) -> list[dict]:
    """
    Run all registered detections against a normalised event list.
    Returns a combined, time-sorted alert list.
    """
    alerts: list[dict] = []

    alerts += detect_encoded_ps_lolbin_chain(events, window_seconds)
    alerts += detect_brute_force(events, window_seconds, brute_force_threshold)
    alerts += detect_priv_logon_anomaly(events)

    alerts.sort(key=lambda a: a.get("time_start") or "")
    return alerts
