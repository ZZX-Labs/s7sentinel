from __future__ import annotations

import csv
from collections import defaultdict, deque
from datetime import datetime, time, timedelta
from pathlib import Path


def _truth(v: str) -> bool:
    return (v or "").strip().lower() in {"yes", "true", "1", "y"}


def _parse_ts(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_hhmm(value: str | None) -> time | None:
    if not value:
        return None
    h, m = value.split(":", 1)
    return time(int(h), int(m))


def _in_window(t: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= t <= end
    return t >= start or t <= end


def analyze_csv(path: str, *, scan_threshold: int = 4, scan_window_seconds: int = 300,
                maintenance_start: str | None = None, maintenance_end: str | None = None) -> dict:
    p = Path(path)
    start = _parse_hhmm(maintenance_start)
    end = _parse_hhmm(maintenance_end)
    if (start is None) != (end is None):
        raise ValueError("maintenance start and end must be supplied together")

    events = []
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"timestamp", "src_ip", "dst_ip", "dst_port", "operation", "authorized_source", "change_ticket"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError("S7 event CSV missing required columns: " + ", ".join(missing))
        for i, row in enumerate(reader, start=2):
            ts = _parse_ts(row.get("timestamp", ""))
            if ts is None:
                raise ValueError(f"invalid or missing timestamp at line {i}")
            try:
                port = int((row.get("dst_port") or "0").strip() or 0)
            except ValueError as exc:
                raise ValueError(f"invalid dst_port at line {i}") from exc
            events.append({
                "line": i,
                "timestamp": ts,
                "timestamp_raw": row.get("timestamp", ""),
                "src_ip": (row.get("src_ip") or "").strip(),
                "dst_ip": (row.get("dst_ip") or "").strip(),
                "dst_port": port,
                "operation": (row.get("operation") or "").strip(),
                "authorized_source": (row.get("authorized_source") or "").strip(),
                "change_ticket": (row.get("change_ticket") or "").strip(),
            })

    findings = []
    for e in events:
        if e["dst_port"] != 102:
            continue
        if e["authorized_source"] and not _truth(e["authorized_source"]):
            findings.append({
                "severity": "HIGH", "code": "UNAUTHORIZED_S7_SOURCE", "line": e["line"],
                "detail": f"S7comm traffic from unapproved source {e['src_ip']} to {e['dst_ip']}.",
                "attack_ids": ["T0834", "T0893"], "d3fend_ids": ["D3-PM", "D3-NTA"],
            })
        op = e["operation"].lower()
        if any(x in op for x in ("write", "put", "modify", "download")) and not e["change_ticket"]:
            findings.append({
                "severity": "HIGH", "code": "S7_WRITE_WITHOUT_CHANGE_TICKET", "line": e["line"],
                "detail": f"Potential write/change operation '{e['operation']}' has no change ticket.",
                "attack_ids": ["T0821"], "d3fend_ids": ["D3-PM", "D3-NTA"],
            })
        if start and end and e["timestamp"] and not _in_window(e["timestamp"].timetz().replace(tzinfo=None), start, end):
            findings.append({
                "severity": "MEDIUM", "code": "S7_OUTSIDE_MAINTENANCE_WINDOW", "line": e["line"],
                "detail": f"S7comm activity occurred at {e['timestamp_raw']} outside the supplied maintenance window.",
                "d3fend_ids": ["D3-PM", "D3-NTA"],
            })

    by_source = defaultdict(list)
    for e in events:
        if e["dst_port"] == 102 and e["src_ip"] and e["dst_ip"] and e["timestamp"]:
            by_source[e["src_ip"]].append(e)
    window = timedelta(seconds=max(1, scan_window_seconds))
    for src, rows in by_source.items():
        rows.sort(key=lambda x: x["timestamp"])
        q = deque()
        flagged = False
        for e in rows:
            q.append(e)
            while q and e["timestamp"] - q[0]["timestamp"] > window:
                q.popleft()
            unique_dsts = {x["dst_ip"] for x in q}
            if len(unique_dsts) >= scan_threshold:
                findings.append({
                    "severity": "HIGH", "code": "SEQUENTIAL_S7_SCAN_PATTERN",
                    "detail": f"Source {src} contacted {len(unique_dsts)} distinct TCP/102 destinations within {scan_window_seconds} seconds.",
                    "attack_ids": ["T1596.005"], "d3fend_ids": ["D3-NTA"],
                })
                flagged = True
                break
        if flagged:
            continue

    return {
        "source_file": str(p.resolve()),
        "events": len(events),
        "findings": findings,
    }
