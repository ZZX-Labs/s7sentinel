#!/usr/bin/env python3
"""
GitHub Actions wrapper for S7Sentinel.

This wrapper intentionally exposes only offline/read-only analysis modes:

    inventory
    s7log
    agentlog
    hostcheck
    agentcheck

It does NOT expose S7Sentinel's active PLC network scanning path.

Expected environment variables are populated by action.yml:

    INPUT_MODE
    INPUT_SOURCE
    INPUT_OUTPUT_DIR
    INPUT_FAIL_ON_FINDINGS
    INPUT_HASH_MATCHES
    INPUT_MAINTENANCE_START
    INPUT_MAINTENANCE_END

GitHub-provided variables used when available:

    GITHUB_WORKSPACE
    GITHUB_OUTPUT
    GITHUB_STEP_SUMMARY

Exit policy:
    Native S7Sentinel exit 0 -> wrapper exit 0
    Native S7Sentinel exit 1 -> wrapper exit 0 unless fail-on-findings=true
    Native S7Sentinel exit >=2 -> wrapper exits with that code
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


VALID_MODES = {
    "inventory",
    "s7log",
    "agentlog",
    "hostcheck",
    "agentcheck",
}

SEVERITY_ORDER = {
    "NONE": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


class ActionError(RuntimeError):
    """Raised for invalid or unsafe Action input."""


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def parse_bool(value: str, *, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ActionError(f"{name} must be true or false, got: {value!r}")


def workspace_path() -> Path:
    raw = env("GITHUB_WORKSPACE")
    if raw:
        return Path(raw).expanduser().resolve()
    return Path.cwd().resolve()


def ensure_within_workspace(path: Path, workspace: Path) -> Path:
    """
    Resolve a path and require it to remain inside GITHUB_WORKSPACE.

    This prevents Action inputs from turning hostcheck/agentcheck into
    arbitrary GitHub-hosted runner filesystem traversal.
    """
    resolved = path.expanduser().resolve()

    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ActionError(
            f"path escapes GITHUB_WORKSPACE and is refused: {resolved}"
        ) from exc

    return resolved


def resolve_input_path(raw: str, workspace: Path) -> Path:
    if not raw:
        raise ActionError("source path is required")

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate

    return ensure_within_workspace(candidate, workspace)


def resolve_source_roots(raw: str, workspace: Path) -> list[Path]:
    """
    Resolve comma-separated roots used by hostcheck/agentcheck.

    Empty members are ignored; at least one valid path is required.
    """
    roots: list[Path] = []

    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        roots.append(resolve_input_path(item, workspace))

    if not roots:
        raise ActionError("at least one source root is required")

    return roots


def resolve_output_dir(raw: str, workspace: Path) -> Path:
    raw = raw or "s7sentinel-results"
    output_dir = resolve_input_path(raw, workspace)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def validate_source_exists(path: Path) -> None:
    if not path.exists():
        raise ActionError(f"source does not exist: {path}")


def validate_hhmm(value: str, *, name: str) -> None:
    if not value:
        return

    parts = value.split(":")
    if len(parts) != 2:
        raise ActionError(f"{name} must use HH:MM")

    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        raise ActionError(f"{name} must use HH:MM") from exc

    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ActionError(f"{name} must use a valid 24-hour HH:MM value")


def github_output(name: str, value: str) -> None:
    path = env("GITHUB_OUTPUT")
    if not path:
        return

    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def github_summary(lines: Iterable[str]) -> None:
    path = env("GITHUB_STEP_SUMMARY")
    if not path:
        return

    with open(path, "a", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line)
            if not line.endswith("\n"):
                fh.write("\n")


def find_s7sentinel_command() -> list[str]:
    executable = shutil.which("s7sentinel")
    if executable:
        return [executable]

    # Fallback for environments where the console script is not on PATH.
    return [sys.executable, "-m", "s7sentinel"]


def run_command(argv: list[str], *, cwd: Path) -> int:
    printable = " ".join(shlex.quote(arg) for arg in argv)
    print(f"::group::S7Sentinel command")
    print(printable)
    print("::endgroup::")

    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        check=False,
    )
    return int(completed.returncode)


def normalize_severity(value: Any) -> str:
    if value is None:
        return "NONE"
    text = str(value).strip().upper()
    return text if text in SEVERITY_ORDER else "INFO"


def iter_findings(obj: Any) -> Iterable[dict[str, Any]]:
    """
    Recursively yield dicts that look like finding records.

    This is intentionally schema-tolerant so the Action remains useful if
    S7Sentinel report structure evolves without changing the security model.
    """
    if isinstance(obj, dict):
        looks_like_finding = any(
            key in obj
            for key in (
                "severity",
                "finding_id",
                "rule_id",
                "detection",
                "title",
            )
        )

        if looks_like_finding and "severity" in obj:
            yield obj

        for value in obj.values():
            yield from iter_findings(value)

    elif isinstance(obj, list):
        for item in obj:
            yield from iter_findings(item)


def summarize_json_report(report_path: Path) -> dict[str, Any]:
    summary = {
        "finding_count": 0,
        "high_count": 0,
        "critical_count": 0,
        "max_severity": "NONE",
    }

    if not report_path.exists():
        return summary

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return summary

    findings = list(iter_findings(data))
    summary["finding_count"] = len(findings)

    max_value = 0
    max_name = "NONE"

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))

        if severity == "HIGH":
            summary["high_count"] += 1
        elif severity == "CRITICAL":
            summary["critical_count"] += 1

        score = SEVERITY_ORDER.get(severity, 1)
        if score > max_value:
            max_value = score
            max_name = severity

    summary["max_severity"] = max_name
    return summary


def candidate_json_report(output_dir: Path, mode: str) -> Path:
    """
    Prefer mode-specific names but tolerate older/native report naming.
    """
    candidates = [
        output_dir / f"{mode}.json",
        output_dir / "s7sentinel-report.json",
        output_dir / "report.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    json_files = sorted(output_dir.glob("*.json"))
    if json_files:
        return json_files[0]

    return candidates[0]


def candidate_html_report(output_dir: Path, mode: str) -> Path | None:
    candidates = [
        output_dir / f"{mode}.html",
        output_dir / "s7sentinel-report.html",
        output_dir / "report.html",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    html_files = sorted(output_dir.glob("*.html"))
    return html_files[0] if html_files else None


def build_command(
    *,
    mode: str,
    source_raw: str,
    output_dir: Path,
    workspace: Path,
    hash_matches: bool,
    maintenance_start: str,
    maintenance_end: str,
) -> list[str]:
    base = find_s7sentinel_command()

    if mode == "inventory":
        source = resolve_input_path(source_raw, workspace)
        validate_source_exists(source)

        json_report = output_dir / "inventory.json"
        html_report = output_dir / "inventory.html"

        return [
            *base,
            "scan",
            "--inventory",
            str(source),
            "--no-network",
            "--json",
            str(json_report),
            "--html",
            str(html_report),
        ]

    if mode == "s7log":
        source = resolve_input_path(source_raw, workspace)
        validate_source_exists(source)

        argv = [
            *base,
            "logcheck",
            "--csv",
            str(source),
            "--json",
            str(output_dir / "s7log.json"),
        ]

        if maintenance_start:
            argv += ["--maintenance-start", maintenance_start]
        if maintenance_end:
            argv += ["--maintenance-end", maintenance_end]

        return argv

    if mode == "agentlog":
        source = resolve_input_path(source_raw, workspace)
        validate_source_exists(source)

        return [
            *base,
            "agentlog",
            "--csv",
            str(source),
            "--json",
            str(output_dir / "agentlog.json"),
        ]

    if mode in {"hostcheck", "agentcheck"}:
        roots = resolve_source_roots(source_raw, workspace)

        for root in roots:
            validate_source_exists(root)

        argv = [
            *base,
            mode,
            "--roots",
            ",".join(str(root) for root in roots),
            "--json",
            str(output_dir / f"{mode}.json"),
        ]

        if hash_matches:
            argv.append("--hash")

        return argv

    raise ActionError(f"unsupported mode: {mode}")


def main() -> int:
    try:
        workspace = workspace_path()

        mode = env("INPUT_MODE", "inventory").lower()
        source_raw = env("INPUT_SOURCE")
        output_raw = env("INPUT_OUTPUT_DIR", "s7sentinel-results")

        fail_on_findings = parse_bool(
            env("INPUT_FAIL_ON_FINDINGS", "false"),
            name="fail-on-findings",
        )
        hash_matches = parse_bool(
            env("INPUT_HASH_MATCHES", "false"),
            name="hash-matches",
        )

        maintenance_start = env("INPUT_MAINTENANCE_START")
        maintenance_end = env("INPUT_MAINTENANCE_END")

        if mode not in VALID_MODES:
            raise ActionError(
                f"invalid mode {mode!r}; expected one of: "
                + ", ".join(sorted(VALID_MODES))
            )

        validate_hhmm(maintenance_start, name="maintenance-start")
        validate_hhmm(maintenance_end, name="maintenance-end")

        if bool(maintenance_start) != bool(maintenance_end):
            raise ActionError(
                "maintenance-start and maintenance-end must be supplied together"
            )

        output_dir = resolve_output_dir(output_raw, workspace)

        argv = build_command(
            mode=mode,
            source_raw=source_raw,
            output_dir=output_dir,
            workspace=workspace,
            hash_matches=hash_matches,
            maintenance_start=maintenance_start,
            maintenance_end=maintenance_end,
        )

        native_exit = run_command(argv, cwd=workspace)

        report_json = candidate_json_report(output_dir, mode)
        report_html = candidate_html_report(output_dir, mode)

        summary = summarize_json_report(report_json)

        if native_exit == 0:
            result = "clean"
        elif native_exit == 1:
            result = "findings"
        else:
            result = "error"

        github_output("report-json", str(report_json.relative_to(workspace)))
        github_output(
            "report-html",
            str(report_html.relative_to(workspace)) if report_html else "",
        )
        github_output("exit-code", str(native_exit))
        github_output("result", result)
        github_output("finding-count", str(summary["finding_count"]))
        github_output("high-count", str(summary["high_count"]))
        github_output("critical-count", str(summary["critical_count"]))
        github_output("max-severity", str(summary["max_severity"]))

        github_summary(
            [
                "## S7Sentinel defensive analysis",
                "",
                f"- Mode: `{mode}`",
                f"- Result: `{result}`",
                f"- Native exit code: `{native_exit}`",
                f"- Findings: `{summary['finding_count']}`",
                f"- HIGH: `{summary['high_count']}`",
                f"- CRITICAL: `{summary['critical_count']}`",
                f"- Maximum severity: `{summary['max_severity']}`",
                "",
                "> Detailed evidence remains in the generated report artifact.",
            ]
        )

        if native_exit >= 2:
            return native_exit

        if native_exit == 1 and fail_on_findings:
            return 1

        return 0

    except ActionError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        github_output("exit-code", "2")
        github_output("result", "error")
        return 2
    except KeyboardInterrupt:
        print("::error::interrupted", file=sys.stderr)
        github_output("exit-code", "130")
        github_output("result", "error")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
