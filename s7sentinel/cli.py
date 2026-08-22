from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agentic import analyze_agentic_csv, scan_agent_workspaces
from .hostcheck import scan_roots
from .inventory import load_inventory
from .logcheck import analyze_csv
from .models import Asset
from .profiles import render_profile
from .report import write_generic_json, write_html, write_json
from .risk import assess, load_advisories
from .scanner import expand_targets, scan_many


def parse_ports(value: str) -> tuple[int, ...]:
    ports = []
    for part in value.split(","):
        try:
            p = int(part.strip())
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid port {part!r}") from exc
        if not 1 <= p <= 65535:
            raise argparse.ArgumentTypeError(f"invalid port {p}")
        ports.append(p)
    return tuple(dict.fromkeys(ports))


def parse_roots(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="s7sentinel",
        description=(
            "Defensive Siemens S7/OT and agentic-intrusion exposure, posture, artifact, "
            "and normalized-telemetry checker. No exploit execution or PLC writes."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="conservative TCP exposure checks and AA26-231A inventory posture analysis")
    s.add_argument("--targets", help="comma-separated IPv4 addresses/private CIDRs; if omitted, use IPs from --inventory")
    s.add_argument("--inventory", help="optional CSV inventory")
    s.add_argument("--advisories", help="optional local JSON CVE/advisory rules verified against Siemens ProductCERT/CISA")
    s.add_argument("--ports", type=parse_ports, default=(102,), help="TCP ports to test, default: 102")
    s.add_argument("--no-network", action="store_true", help="inventory/advisory assessment only; send no network traffic")
    s.add_argument("--timeout", type=float, default=0.8, help="TCP connection timeout seconds, default: 0.8")
    s.add_argument("--workers", type=positive_int, default=8, help="parallel workers, maximum 32")
    s.add_argument("--max-hosts", type=positive_int, default=256, help="safety cap, default 256")
    s.add_argument("--allow-public", action="store_true", help="allow individually specified non-RFC1918 IPv4 addresses; CIDR expansion remains RFC1918-only")
    s.add_argument("--authorized", action="store_true", help="confirm you own or are authorized to assess all supplied network targets")
    s.add_argument("--json", default="s7sentinel-report.json", help="JSON report path")
    s.add_argument("--html", default="s7sentinel-report.html", help="HTML report path")

    h = sub.add_parser("hostcheck", help="hunt locally for Snap7/python-snap7 artifacts without executing them")
    h.add_argument("--roots", type=parse_roots, required=True, help="comma-separated file/directory roots to inspect")
    h.add_argument("--max-files", type=positive_int, default=20000, help="safety cap for filesystem traversal")
    h.add_argument("--hash", action="store_true", help="compute SHA-256 for matching files")
    h.add_argument("--json", default="s7sentinel-hostcheck.json", help="JSON output path")

    l = sub.add_parser("logcheck", help="analyze normalized S7comm/network event CSV for AA26-231A anomalies")
    l.add_argument("--csv", required=True, help="CSV with timestamp,src_ip,dst_ip,dst_port,operation,authorized_source,change_ticket")
    l.add_argument("--scan-threshold", type=positive_int, default=4, help="unique TCP/102 destinations within the window")
    l.add_argument("--scan-window", type=positive_int, default=300, help="scan-detection window in seconds")
    l.add_argument("--maintenance-start", help="optional HH:MM approved maintenance start")
    l.add_argument("--maintenance-end", help="optional HH:MM approved maintenance end")
    l.add_argument("--json", default="s7sentinel-logcheck.json", help="JSON output path")

    ah = sub.add_parser("agentcheck", help="inspect local roots for Hermes/OpenClaw-style agentic workspace artifacts; never executes discovered files")
    ah.add_argument("--roots", type=parse_roots, required=True, help="comma-separated file/directory roots to inspect")
    ah.add_argument("--max-files", type=positive_int, default=25000, help="safety cap for filesystem traversal")
    ah.add_argument("--hash", action="store_true", help="compute SHA-256 for matching files")
    ah.add_argument("--json", default="s7sentinel-agentcheck.json", help="JSON output path")

    al = sub.add_parser("agentlog", help="analyze normalized identity/web/API telemetry for AI-orchestrated intrusion patterns")
    al.add_argument("--csv", required=True, help="normalized identity/web/API event CSV; see docs/data-formats.md")
    al.add_argument("--spray-users", type=positive_int, default=8, help="distinct failed-auth users in the spray window")
    al.add_argument("--spray-window", type=positive_int, default=900, help="password-spray window seconds")
    al.add_argument("--recon-endpoints", type=positive_int, default=25, help="distinct endpoint threshold")
    al.add_argument("--recon-window", type=positive_int, default=300, help="endpoint-enumeration window seconds")
    al.add_argument("--sso-systems", type=positive_int, default=3, help="distinct successful systems per identity/source")
    al.add_argument("--sso-window", type=positive_int, default=900, help="cross-system SSO window seconds")
    al.add_argument("--burst-events", type=positive_int, default=150, help="event count suggesting automation")
    al.add_argument("--burst-window", type=positive_int, default=60, help="automation burst window seconds")
    al.add_argument("--exfil-bytes", type=positive_int, default=10 * 1024 * 1024, help="large-response threshold bytes")
    al.add_argument("--json", default="s7sentinel-agentlog.json", help="JSON output path")

    pr = sub.add_parser("profile", help="show the built-in defensive threat profiles")
    pr.add_argument("name", nargs="?", choices=("aa26-231a", "dream-agentic-2026"), help="optional profile name")
    return p


def print_summary(results) -> None:
    print("IP              RISK      SCORE  TCP/102  MODEL")
    print("-" * 78)
    for r in sorted(results, key=lambda x: (-x.risk_score, x.asset.ip)):
        s7 = "open" if any(p.port == 102 and p.open for p in r.ports) else "closed"
        print(f"{r.asset.ip:<15} {r.risk_level:<9} {r.risk_score:>5}  {s7:<7}  {r.asset.model or '-'}")


def cmd_scan(args) -> int:
    if not args.no_network and not args.authorized:
        print("Refusing network checks: pass --authorized to confirm permission for every target, or use --no-network.", file=sys.stderr)
        return 2
    try:
        inventory = load_inventory(args.inventory)
        advisories = load_advisories(args.advisories)
        if args.targets:
            targets = expand_targets(args.targets, allow_public=args.allow_public, max_hosts=args.max_hosts)
        elif inventory:
            targets = list(inventory.keys())
            if len(targets) > args.max_hosts:
                raise ValueError(f"inventory exceeds safety limit of {args.max_hosts} hosts")
            if not args.no_network:
                targets = expand_targets(",".join(targets), allow_public=args.allow_public, max_hosts=args.max_hosts)
        else:
            raise ValueError("provide --targets or --inventory")
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    scans = {} if args.no_network else scan_many(targets, args.ports, max(0.1, args.timeout), args.workers)
    results = []
    for host in targets:
        asset = inventory.get(host, Asset(ip=host))
        results.append(assess(asset, scans.get(host, []), advisories=advisories))

    write_json(results, args.json)
    write_html(results, args.html)
    print_summary(results)
    print(f"\nJSON: {Path(args.json).resolve()}")
    print(f"HTML: {Path(args.html).resolve()}")
    return 1 if any(r.risk_level in {"HIGH", "CRITICAL"} for r in results) else 0


def cmd_hostcheck(args) -> int:
    try:
        result = scan_roots(args.roots, max_files=args.max_files, hash_matches=args.hash)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    write_generic_json({"mode": "hostcheck", "profile": "aa26-231a", **result}, args.json)
    actionable = [a for a in result["artifacts"] if a.get("type") != "error"]
    print(f"Scanned files: {result['scanned_files']}")
    print(f"Review artifacts: {len(actionable)}")
    print(f"Truncated: {'yes' if result['truncated'] else 'no'}")
    print(f"JSON: {Path(args.json).resolve()}")
    return 1 if actionable else 0


def cmd_logcheck(args) -> int:
    try:
        result = analyze_csv(
            args.csv,
            scan_threshold=max(2, args.scan_threshold),
            scan_window_seconds=args.scan_window,
            maintenance_start=args.maintenance_start,
            maintenance_end=args.maintenance_end,
        )
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    write_generic_json({"mode": "logcheck", "profile": "aa26-231a", **result}, args.json)
    print(f"Events analyzed: {result['events']}")
    print(f"Findings: {len(result['findings'])}")
    print(f"JSON: {Path(args.json).resolve()}")
    return 1 if any(f.get("severity") in {"HIGH", "CRITICAL"} for f in result["findings"]) else 0


def cmd_agentcheck(args) -> int:
    try:
        result = scan_agent_workspaces(args.roots, max_files=args.max_files, hash_matches=args.hash)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    write_generic_json({"mode": "agentcheck", **result}, args.json)
    actionable = [f for f in result["findings"] if f.get("code") != "ROOT_NOT_FOUND"]
    print(f"Scanned files: {result['scanned_files']}")
    print(f"Review findings: {len(actionable)}")
    print(f"Defensive priority: {result['defensive_priority']:.3f}")
    print(f"JSON: {Path(args.json).resolve()}")
    return 1 if actionable else 0


def cmd_agentlog(args) -> int:
    try:
        result = analyze_agentic_csv(
            args.csv,
            spray_users=max(2, args.spray_users),
            spray_window_seconds=args.spray_window,
            recon_endpoints=max(3, args.recon_endpoints),
            recon_window_seconds=args.recon_window,
            sso_systems=max(2, args.sso_systems),
            sso_window_seconds=args.sso_window,
            burst_events=max(10, args.burst_events),
            burst_window_seconds=args.burst_window,
            exfil_bytes=args.exfil_bytes,
        )
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    write_generic_json({"mode": "agentlog", **result}, args.json)
    print(f"Events analyzed: {result['events']}")
    print(f"Findings: {len(result['findings'])}")
    print(f"Sources scored: {len(result['source_scores'])}")
    print(f"JSON: {Path(args.json).resolve()}")
    return 1 if any(f.get("severity") in {"HIGH", "CRITICAL"} for f in result["findings"]) else 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "hostcheck":
        return cmd_hostcheck(args)
    if args.cmd == "logcheck":
        return cmd_logcheck(args)
    if args.cmd == "agentcheck":
        return cmd_agentcheck(args)
    if args.cmd == "agentlog":
        return cmd_agentlog(args)
    if args.cmd == "profile":
        print(render_profile(args.name))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
