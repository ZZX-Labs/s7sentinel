from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Asset:
    ip: str
    asset_name: str = ""
    model: str = ""
    firmware: str = ""
    network_zone: str = ""
    internet_exposed: str = "unknown"
    remote_access: str = "unknown"
    mfa: str = "unknown"
    patch_status: str = "unknown"
    gold_copy_verified: str = "unknown"
    engineering_access_restricted: str = "unknown"
    plc_password: str = "unknown"
    protection_level: str = "unknown"
    snmp_hardened: str = "unknown"
    app_allowlisting: str = "unknown"
    logging_enabled: str = "unknown"
    web_server_disabled: str = "unknown"
    unused_protocols_disabled: str = "unknown"
    connection_limits: str = "unknown"
    restart_protection: str = "unknown"
    know_how_protection: str = "unknown"
    logic_integrity_verified: str = "unknown"
    vendor_support_verified: str = "unknown"
    notes: str = ""


@dataclass
class PortResult:
    port: int
    open: bool
    latency_ms: Optional[float] = None
    error: str = ""


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    remediation: str
    cve: str = ""
    attack_ids: list[str] = field(default_factory=list)
    d3fend_ids: list[str] = field(default_factory=list)
    source: str = "AA26-231A"


@dataclass
class ScanResult:
    asset: Asset
    is_public_ip: bool
    ports: list[PortResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "INFO"

    def to_dict(self):
        return asdict(self)
