from __future__ import annotations

import csv
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

TRUTHY = {"1", "true", "yes", "y", "approved", "authorized"}
TEXT_EXTENSIONS = {".txt", ".md", ".json", ".yaml", ".yml", ".log", ".csv", ".py", ".js", ".ts"}
WORKSPACE_NAMES = {".hermes", ".openclaw"}
SERVER_SIDE_EXTENSIONS = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi", ".war"}
RESEARCH_MARKERS = (
    "learning cycle",
    "posterior probability",
    "attack wave",
    "after-action report",
    "sub-agent",
    "bayesian prioritization",
)


def _truth(value: str) -> bool:
    return (value or "").strip().lower() in TRUTHY


def _parse_ts(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _status_ok(value: str) -> bool:
    try:
        n = int((value or "").strip())
        return 200 <= n < 400
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def bayesian_priority(prior: float, likelihood_ratios: list[float]) -> float:
    """Return a defensive evidence-priority posterior.

    This is deliberately a triage score, not a claim that compromise occurred.
    """
    prior = min(max(prior, 1e-6), 1 - 1e-6)
    odds = prior / (1 - prior)
    for lr in likelihood_ratios:
        odds *= max(1e-6, float(lr))
    posterior = odds / (1 + odds)
    return round(posterior, 6)


def scan_agent_workspaces(roots: list[str], *, max_files: int = 25000, hash_matches: bool = False) -> dict:
    findings: list[dict] = []
    scanned_files = 0
    truncated = False

    for root_s in roots:
        root = Path(root_s).expanduser().resolve()
        if not root.exists():
            findings.append({
                "severity": "INFO",
                "code": "ROOT_NOT_FOUND",
                "path": str(root),
                "detail": "Requested inspection root does not exist.",
            })
            continue

        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if path.is_dir():
                if path.name.lower() in WORKSPACE_NAMES:
                    findings.append({
                        "severity": "MEDIUM",
                        "code": "AGENTIC_WORKSPACE_DIRECTORY",
                        "path": str(path),
                        "detail": "Directory name matches an agent workspace identifier described in the supplied Dream Research Labs report.",
                        "disposition": "Confirm the directory is expected and authorized. Presence alone is not proof of malicious activity.",
                        "evidence_lr": 3.0,
                    })
                continue

            if not path.is_file():
                continue
            scanned_files += 1
            if scanned_files > max_files:
                truncated = True
                break

            reasons: list[str] = []
            lowered = path.name.lower()
            if any(name in lowered for name in ("hermes", "openclaw")):
                reasons.append("filename references Hermes/OpenClaw")

            if path.suffix.lower() in TEXT_EXTENSIONS:
                try:
                    if path.stat().st_size <= 2 * 1024 * 1024:
                        text = path.read_text(encoding="utf-8", errors="ignore").lower()
                        marker_hits = [m for m in RESEARCH_MARKERS if m in text]
                        if len(marker_hits) >= 2:
                            reasons.append("multiple agentic-operation planning/report markers")
                except OSError:
                    pass

            if reasons:
                item = {
                    "severity": "MEDIUM",
                    "code": "AGENTIC_FILE_ARTIFACT",
                    "path": str(path),
                    "detail": "; ".join(reasons),
                    "disposition": "Validate owner, provenance, execution history, and whether the file is expected on this system. Do not treat this indicator alone as proof of compromise.",
                    "evidence_lr": 3.0,
                }
                if hash_matches:
                    try:
                        item["sha256"] = _sha256(path)
                    except OSError as exc:
                        item["hash_error"] = str(exc)
                findings.append(item)

        if truncated:
            break

    lrs = [float(f.get("evidence_lr", 1.0)) for f in findings if f.get("evidence_lr")]
    return {
        "profile": "dream-agentic-2026",
        "scanned_files": min(scanned_files, max_files),
        "truncated": truncated,
        "findings": findings,
        "defensive_priority": bayesian_priority(0.05, lrs) if lrs else 0.0,
        "score_note": "Defensive-priority posterior based on local evidence strength; it is not a probability that compromise occurred.",
    }


def _require_columns(fieldnames: list[str] | None, required: set[str]) -> None:
    present = set(fieldnames or [])
    missing = sorted(required - present)
    if missing:
        raise ValueError("agentic event CSV missing required columns: " + ", ".join(missing))


def analyze_agentic_csv(
    path: str,
    *,
    spray_users: int = 8,
    spray_window_seconds: int = 900,
    recon_endpoints: int = 25,
    recon_window_seconds: int = 300,
    sso_systems: int = 3,
    sso_window_seconds: int = 900,
    burst_events: int = 150,
    burst_window_seconds: int = 60,
    exfil_bytes: int = 10 * 1024 * 1024,
) -> dict:
    """Analyze normalized identity/web/API telemetry for defensive agentic-intrusion patterns.

    Required columns: timestamp, src_ip, event. Other documented columns are optional.
    """
    p = Path(path)
    events: list[dict] = []
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        _require_columns(reader.fieldnames, {"timestamp", "src_ip", "event"})
        for line, row in enumerate(reader, start=2):
            ts = _parse_ts(row.get("timestamp", ""))
            if ts is None:
                raise ValueError(f"invalid or missing timestamp at line {line}")
            try:
                bytes_out = int((row.get("bytes_out") or "0").strip() or 0)
            except ValueError:
                raise ValueError(f"invalid bytes_out at line {line}")
            events.append({
                "line": line,
                "timestamp": ts,
                "timestamp_raw": row.get("timestamp", ""),
                "src_ip": (row.get("src_ip") or "").strip(),
                "user": (row.get("user") or "").strip(),
                "system": (row.get("system") or "").strip(),
                "event": (row.get("event") or "").strip(),
                "endpoint": (row.get("endpoint") or "").strip(),
                "status": (row.get("status") or "").strip(),
                "auth_result": (row.get("auth_result") or "").strip(),
                "auth_method": (row.get("auth_method") or "").strip(),
                "jwt_alg": (row.get("jwt_alg") or "").strip(),
                "bytes_out": bytes_out,
                "file_name": (row.get("file_name") or "").strip(),
                "user_agent": (row.get("user_agent") or "").strip(),
                "authorized": (row.get("authorized") or "").strip(),
                "sensitive": (row.get("sensitive") or "").strip(),
                "change_ticket": (row.get("change_ticket") or "").strip(),
            })

    events.sort(key=lambda e: e["timestamp"])
    findings: list[dict] = []

    # Direct event-level detections.
    for e in events:
        event_l = e["event"].lower()
        auth_method_l = e["auth_method"].lower()
        auth_result_l = e["auth_result"].lower()

        if e["jwt_alg"].lower() == "none":
            accepted = _status_ok(e["status"]) or auth_result_l in {"success", "accepted", "allow"}
            findings.append({
                "severity": "CRITICAL" if accepted else "MEDIUM",
                "code": "JWT_NONE_ALGORITHM_OBSERVED",
                "line": e["line"],
                "src_ip": e["src_ip"],
                "detail": "A JWT using algorithm 'none' was observed" + (" and appears to have been accepted." if accepted else "."),
                "remediation": "Reject unsigned JWTs, enforce an explicit algorithm allowlist, verify signatures server-side, rotate exposed signing material where appropriate, and review affected sessions.",
                "evidence_lr": 12.0 if accepted else 4.0,
            })

        if _truth(e["sensitive"]) and _status_ok(e["status"]) and auth_method_l in {"", "none", "unauthenticated", "anonymous"}:
            findings.append({
                "severity": "CRITICAL",
                "code": "UNAUTHENTICATED_SENSITIVE_API_SUCCESS",
                "line": e["line"],
                "src_ip": e["src_ip"],
                "detail": f"Sensitive endpoint {e['endpoint'] or '(unspecified)'} returned a successful response without an authenticated method.",
                "remediation": "Require authentication and authorization on the endpoint, review prior access, invalidate exposed secrets/data where necessary, and add regression tests at the gateway/application layer.",
                "evidence_lr": 10.0,
            })

        if "upload" in event_l and _status_ok(e["status"]) and e["file_name"]:
            ext = Path(e["file_name"]).suffix.lower()
            if ext in SERVER_SIDE_EXTENSIONS:
                findings.append({
                    "severity": "HIGH",
                    "code": "SERVER_SIDE_FILE_UPLOAD",
                    "line": e["line"],
                    "src_ip": e["src_ip"],
                    "detail": f"Successful upload of server-executable file type '{ext}' was logged.",
                    "remediation": "Quarantine and review the uploaded object, enforce extension/content-type allowlists, store uploads outside executable paths, and inspect the account/session that performed the upload.",
                    "evidence_lr": 8.0,
                })

        if e["bytes_out"] >= exfil_bytes and (_truth(e["sensitive"]) or any(k in event_l for k in ("export", "download", "query"))):
            findings.append({
                "severity": "HIGH",
                "code": "LARGE_SENSITIVE_RESPONSE",
                "line": e["line"],
                "src_ip": e["src_ip"],
                "detail": f"Single event transferred {e['bytes_out']} bytes from a sensitive or export-like operation.",
                "remediation": "Validate the request against business purpose and change records, inspect adjacent requests, and apply rate/volume controls to sensitive bulk-access APIs.",
                "evidence_lr": 6.0,
            })

    # Windowed password spraying: many distinct users from one source with failures.
    by_src_fail: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        failed = e["auth_result"].lower() in {"fail", "failed", "failure", "denied", "invalid"}
        auth_event = any(k in e["event"].lower() for k in ("login", "auth", "signin", "sso"))
        if e["src_ip"] and e["user"] and failed and auth_event:
            by_src_fail[e["src_ip"]].append(e)
    for src, rows in by_src_fail.items():
        q: deque[dict] = deque()
        span = timedelta(seconds=max(1, spray_window_seconds))
        for e in rows:
            q.append(e)
            while q and e["timestamp"] - q[0]["timestamp"] > span:
                q.popleft()
            users = {x["user"] for x in q}
            if len(users) >= max(2, spray_users):
                findings.append({
                    "severity": "HIGH",
                    "code": "PASSWORD_SPRAY_PATTERN",
                    "src_ip": src,
                    "detail": f"Source attempted failed authentication against {len(users)} distinct users within {spray_window_seconds} seconds.",
                    "remediation": "Throttle and block the source as appropriate, enforce MFA, investigate targeted accounts, review successful logins around the window, and rotate credentials when compromise is suspected.",
                    "attack_ids": ["T1110.003"],
                    "evidence_lr": 8.0,
                })
                break

    # Parallel reconnaissance: many distinct endpoints in a short window.
    by_src: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["src_ip"]:
            by_src[e["src_ip"]].append(e)
    for src, rows in by_src.items():
        q: deque[dict] = deque()
        span = timedelta(seconds=max(1, recon_window_seconds))
        for e in rows:
            q.append(e)
            while q and e["timestamp"] - q[0]["timestamp"] > span:
                q.popleft()
            endpoints = {(x["system"], x["endpoint"]) for x in q if x["endpoint"]}
            if len(endpoints) >= max(3, recon_endpoints):
                findings.append({
                    "severity": "HIGH",
                    "code": "PARALLEL_ENDPOINT_RECON",
                    "src_ip": src,
                    "detail": f"Source touched {len(endpoints)} distinct system/endpoint pairs within {recon_window_seconds} seconds.",
                    "remediation": "Correlate with approved scanners and maintenance activity; if unapproved, contain the source, review gateway/WAF logs, and enumerate accessed endpoints and returned data.",
                    "attack_ids": ["T1595.002"],
                    "evidence_lr": 6.0,
                })
                break

        # High event velocity can indicate automation even without endpoint diversity.
        q = deque()
        span = timedelta(seconds=max(1, burst_window_seconds))
        for e in rows:
            q.append(e)
            while q and e["timestamp"] - q[0]["timestamp"] > span:
                q.popleft()
            if len(q) >= max(10, burst_events):
                findings.append({
                    "severity": "MEDIUM",
                    "code": "AUTOMATED_ACTIVITY_BURST",
                    "src_ip": src,
                    "detail": f"Source generated at least {len(q)} normalized security events within {burst_window_seconds} seconds.",
                    "remediation": "Determine whether the source is an approved scanner/integration. If not, inspect session history, endpoint breadth, authentication behavior, and downstream effects.",
                    "evidence_lr": 3.0,
                })
                break

    # SSO lateral movement: same user/source succeeds across many systems in a short window.
    by_identity: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        success = e["auth_result"].lower() in {"success", "accepted", "allow", "ok"} or (
            "login" in e["event"].lower() and _status_ok(e["status"])
        )
        if e["src_ip"] and e["user"] and e["system"] and success:
            by_identity[(e["src_ip"], e["user"])].append(e)
    for (src, user), rows in by_identity.items():
        q: deque[dict] = deque()
        span = timedelta(seconds=max(1, sso_window_seconds))
        for e in rows:
            q.append(e)
            while q and e["timestamp"] - q[0]["timestamp"] > span:
                q.popleft()
            systems = {x["system"] for x in q if x["system"]}
            if len(systems) >= max(2, sso_systems):
                findings.append({
                    "severity": "HIGH",
                    "code": "CROSS_SYSTEM_SSO_PIVOT_PATTERN",
                    "src_ip": src,
                    "user": user,
                    "detail": f"Identity authenticated successfully to {len(systems)} distinct systems within {sso_window_seconds} seconds.",
                    "remediation": "Verify this behavior against approved SSO workflows. Review session/token issuance, MFA state, source reputation, and whether access breadth matches the user's role.",
                    "attack_ids": ["T1078"],
                    "evidence_lr": 6.0,
                })
                break

    # Defensive evidence aggregation by source. It intentionally ranks review priority, not attack success.
    source_lrs: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        src = f.get("src_ip")
        if src and f.get("evidence_lr"):
            source_lrs[src].append(float(f["evidence_lr"]))
    source_scores = [
        {
            "src_ip": src,
            "defensive_priority": bayesian_priority(0.02, lrs),
            "evidence_count": len(lrs),
        }
        for src, lrs in sorted(source_lrs.items())
    ]

    severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    findings.sort(key=lambda f: (-severity_rank.get(f.get("severity", "INFO"), 0), f.get("line", 0)))

    return {
        "profile": "dream-agentic-2026",
        "source_file": str(p.resolve()),
        "events": len(events),
        "findings": findings,
        "source_scores": source_scores,
        "score_note": "Bayesian values rank defensive review priority from correlated evidence. They are not probabilities of compromise and must not replace incident-response validation.",
    }
