import csv
import ipaddress
from pathlib import Path
from .models import Asset


FIELDS = {
    "ip", "asset_name", "model", "firmware", "network_zone",
    "internet_exposed", "remote_access", "mfa", "patch_status",
    "gold_copy_verified", "engineering_access_restricted", "plc_password",
    "protection_level", "snmp_hardened", "app_allowlisting", "logging_enabled",
    "web_server_disabled", "unused_protocols_disabled", "connection_limits",
    "restart_protection", "know_how_protection", "logic_integrity_verified",
    "vendor_support_verified", "notes"
}


def load_inventory(path: str | None) -> dict[str, Asset]:
    if not path:
        return {}
    p = Path(path)
    with p.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "ip" not in reader.fieldnames:
            raise ValueError("inventory CSV must contain an 'ip' column")
        out: dict[str, Asset] = {}
        for line, row in enumerate(reader, start=2):
            ip = (row.get("ip") or "").strip()
            if not ip:
                raise ValueError(f"inventory CSV missing IP at line {line}")
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"inventory CSV has invalid IP at line {line}: {ip!r}") from exc
            if parsed.version != 4:
                raise ValueError(f"inventory CSV IPv6 is not supported at line {line}: {ip!r}")
            if ip in out:
                raise ValueError(f"inventory CSV contains duplicate IP at line {line}: {ip}")
            clean = {k: (row.get(k) or "").strip() for k in FIELDS}
            clean["ip"] = ip
            out[ip] = Asset(**clean)
        return out
