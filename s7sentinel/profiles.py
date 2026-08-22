from __future__ import annotations

import json
PROFILES = {
    "aa26-231a": {
        "title": "Defending Against an Active Threat to Siemens S7 Series PLCs",
        "source": "NSA/CISA/FBI/DOE/EPA",
        "release_date": "2026-08-19",
        "alert_code": "AA26-231A",
        "scope": "Siemens S7 Series PLC defensive posture, exposure, workstation artifacts, and S7comm monitoring",
        "attack_ids": ["T1596.005", "T1587.004", "T1588.007", "T0834", "T0821", "T0849", "T1694", "T0893"],
        "d3fend_ids": ["D3-HCI", "D3-SU", "D3-NI", "D3-NAM", "D3-CH", "D3-PM", "D3-NTA", "D3-ACH"],
    },
    "dream-agentic-2026": {
        "title": "Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia",
        "source": "Dream Research Labs (report supplied with project requirements)",
        "observed_period": "2026-07-01/2026-07-04",
        "scope": "Defensive telemetry and artifact detection for high-concurrency AI-orchestrated intrusion patterns",
        "defensive_behaviors": [
            "parallel endpoint reconnaissance",
            "password spraying",
            "cross-system SSO pivot patterns",
            "unsigned JWT acceptance indicators",
            "unauthenticated sensitive API access",
            "server-executable file upload events",
            "large sensitive responses",
            "Hermes/OpenClaw workspace artifacts",
            "automation-rate anomalies",
        ],
    },
}


def list_profiles() -> dict:
    return PROFILES


def get_profile(name: str) -> dict:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown profile '{name}'") from exc


def render_profile(name: str | None = None) -> str:
    data = PROFILES if name is None else {name: get_profile(name)}
    return json.dumps(data, indent=2)
