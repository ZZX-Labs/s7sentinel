from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


def write_json(results, path: str):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "s7sentinel",
        "version": __version__,
        "advisory_profile": "CISA/NSA/FBI/DOE/EPA AA26-231A (2026-08-19)",
        "schema": 3,
        "results": [r.to_dict() for r in results],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_generic_json(payload: dict, path: str):
    body = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "s7sentinel",
        "version": __version__,
        "schema": 3,
        **payload,
    }
    Path(path).write_text(json.dumps(body, indent=2), encoding="utf-8")


def _esc(v):
    return html.escape(str(v or ""))


def write_html(results, path: str):
    rows = []
    finding_blocks = []
    for r in results:
        open_ports = ", ".join(str(p.port) for p in r.ports if p.open) or "none"
        rows.append(
            f"<tr><td>{_esc(r.asset.ip)}</td><td>{_esc(r.asset.asset_name)}</td>"
            f"<td>{_esc(r.asset.model)}</td><td>{_esc(r.asset.firmware)}</td>"
            f"<td>{_esc(open_ports)}</td><td><b>{_esc(r.risk_level)}</b></td><td>{r.risk_score}</td></tr>"
        )
        fs = []
        for f in r.findings:
            maps = []
            if f.attack_ids:
                maps.append("ATT&CK: " + ", ".join(_esc(x) for x in f.attack_ids))
            if f.d3fend_ids:
                maps.append("D3FEND: " + ", ".join(_esc(x) for x in f.d3fend_ids))
            fs.append(
                f"<li><b>[{_esc(f.severity)}] {_esc(f.title)}</b><br>"
                f"{_esc(f.detail)}<br><i>Remediation:</i> {_esc(f.remediation)}"
                f"{'<br><i>CVE:</i> ' + _esc(f.cve) if f.cve else ''}"
                f"{'<br><i>Mapping:</i> ' + '; '.join(maps) if maps else ''}"
                f"<br><i>Source:</i> {_esc(f.source)}</li>"
            )
        finding_blocks.append(
            f"<section><h2>{_esc(r.asset.ip)} {_esc(r.asset.asset_name)}</h2><ul>{''.join(fs) or '<li>No findings.</li>'}</ul></section>"
        )

    doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>S7Sentinel AA26-231A Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#111;color:#eee}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #444;padding:.55rem;text-align:left}}th{{background:#222}}
section{{border-top:1px solid #333;margin-top:2rem;padding-top:1rem}}code{{background:#222;padding:.1rem .3rem}}a{{color:#c0d674}}
</style></head><body>
<h1>S7Sentinel Defensive OT Report</h1>
<p>Version {_esc(__version__)}. Profile: CISA/NSA/FBI/DOE/EPA AA26-231A, released 2026-08-19. Generated {_esc(datetime.now(timezone.utc).isoformat())}.</p>
<p>A reachable TCP port, local Snap7 artifact, inventory control gap, or advisory-rule match is not by itself proof of compromise or exploitability.</p>
<table><thead><tr><th>IP</th><th>Name</th><th>Model</th><th>Firmware</th><th>Open checked ports</th><th>Risk</th><th>Score</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{''.join(finding_blocks)}
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
