from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from .models import Asset, Finding, ScanResult


TARGETED_FAMILIES = (
    "s7-200", "s7 200", "s7-300", "s7 300", "s7-400", "s7 400",
    "s7-1200", "s7 1200", "s7-1500", "s7 1500",
)
LEGACY_FAMILIES = ("s7-200", "s7 200", "s7-300", "s7 300", "s7-400", "s7 400")
SEVERITY_POINTS = {"INFO": 0, "LOW": 15, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 95}
TRUE = {"yes", "true", "1", "y", "enabled", "current", "patched", "verified"}
FALSE = {"no", "false", "0", "n", "disabled", "outdated", "unpatched", "not verified"}


def yes(v: str) -> bool:
    return (v or "").strip().lower() in TRUE


def no(v: str) -> bool:
    return (v or "").strip().lower() in FALSE


def unknown(v: str) -> bool:
    return (v or "").strip().lower() in {"", "unknown", "unset", "n/a", "na"}


def family_match(model: str, families=TARGETED_FAMILIES) -> bool:
    m = (model or "").lower()
    return any(x in m for x in families)


def load_advisories(path: str | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("advisory rules file must be a JSON list")
    return data


def _f(severity: str, code: str, title: str, detail: str, remediation: str,
       *, attack_ids=None, d3fend_ids=None, cve="", source="AA26-231A") -> Finding:
    return Finding(
        severity=severity,
        code=code,
        title=title,
        detail=detail,
        remediation=remediation,
        cve=cve,
        attack_ids=list(attack_ids or []),
        d3fend_ids=list(d3fend_ids or []),
        source=source,
    )


def apply_advisories(asset: Asset, advisories: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in advisories:
        model_re = rule.get("model_regex", ".*")
        fw_re = rule.get("firmware_regex", ".*")
        if not re.search(model_re, asset.model or "", flags=re.I):
            continue
        if asset.firmware and not re.search(fw_re, asset.firmware, flags=re.I):
            continue
        sev = str(rule.get("severity", "HIGH")).upper()
        cve = str(rule.get("cve", ""))
        findings.append(_f(
            sev if sev in SEVERITY_POINTS else "HIGH",
            "ADVISORY_MATCH",
            f"Local advisory rule matched{': ' + cve if cve else ''}",
            str(rule.get("summary", "Model/firmware matches a locally supplied vulnerability rule.")),
            str(rule.get("remediation", "Verify against Siemens ProductCERT/CISA guidance and update or mitigate as directed.")),
            cve=cve,
            d3fend_ids=["D3-SU"],
            source=str(rule.get("source", "Local verified advisory rule")),
        ))
    return findings


def assess(asset: Asset, port_results, advisories=None) -> ScanResult:
    advisories = advisories or []
    ip = ipaddress.ip_address(asset.ip)
    public = ip.is_global
    findings: list[Finding] = []
    targeted = family_match(asset.model)
    s7_open = any(p.port == 102 and p.open for p in port_results)

    if s7_open:
        sev = "CRITICAL" if public or yes(asset.internet_exposed) else "HIGH"
        findings.append(_f(
            sev, "S7COMM_REACHABLE", "S7comm service reachable on TCP/102",
            "The host accepted a TCP connection on the Siemens S7comm/ISO-on-TCP service port. This is an exposure signal, not proof of a vulnerability or compromise.",
            "Restrict TCP/102 to explicitly authorized engineering/OT management hosts. Block TCP/102 at perimeter firewalls and verify OT/IT segmentation.",
            attack_ids=["T1596.005"], d3fend_ids=["D3-NI", "D3-NTA"],
        ))

    if public:
        findings.append(_f(
            "HIGH" if s7_open else "MEDIUM", "PUBLIC_IP_TARGET", "Asset address is publicly routable",
            "The assessed address is not in private RFC1918 space. AA26-231A states Internet-exposed PLCs are at high risk.",
            "Remove direct Internet reachability. Use controlled remote-access infrastructure, monitored jump hosts/VPN, and restrictive ACLs.",
            attack_ids=["T1596.005"], d3fend_ids=["D3-NI"],
        ))

    if yes(asset.internet_exposed):
        findings.append(_f(
            "CRITICAL" if s7_open else "HIGH", "INVENTORY_INTERNET_EXPOSED", "Inventory marks asset as Internet-exposed",
            "The supplied inventory explicitly marks this PLC or controller as directly or indirectly Internet-exposed.",
            "Isolate the PLC from untrusted networks and verify there is no unauthorized routing between corporate and industrial networks.",
            attack_ids=["T1596.005"], d3fend_ids=["D3-NI"],
        ))

    if targeted:
        findings.append(_f(
            "INFO", "TARGETED_S7_FAMILY", "Model belongs to the S7 families targeted in AA26-231A",
            f"Inventory model '{asset.model}' matches the S7-200/300/400/1200/1500 family set named in the advisory.",
            "Prioritize this controller for firmware review, network-isolation validation, access-control review, monitoring, and known-good backup verification.",
            d3fend_ids=["D3-HCI", "D3-SU", "D3-NI"],
        ))

    if family_match(asset.model, LEGACY_FAMILIES):
        findings.append(_f(
            "MEDIUM", "LEGACY_S7_FAMILY", "Legacy S7 family requires heightened lifecycle review",
            "This model appears to be from the S7-200, S7-300, or S7-400 families.",
            "Verify support status, latest approved firmware, compensating controls, spare strategy, and migration plan with Siemens and your site change-control process.",
            d3fend_ids=["D3-HCI", "D3-SU"],
        ))

    if targeted and not asset.firmware:
        findings.append(_f(
            "MEDIUM", "FIRMWARE_UNKNOWN", "Firmware version missing from inventory",
            "Patch status cannot be evaluated against Siemens ProductCERT guidance because no exact firmware version was supplied.",
            "Record the exact CPU/order number and firmware version, verify against the approved gold copy, and compare with current Siemens ProductCERT advisories.",
            d3fend_ids=["D3-HCI", "D3-SU"],
        ))

    if targeted and no(asset.patch_status):
        findings.append(_f(
            "HIGH", "PATCH_STATUS_NOT_CURRENT", "Inventory indicates security patching is not current",
            "AA26-231A prioritizes applying critical PLC firmware and TIA Portal/STEP 7 updates, especially for exposed or DMZ-resident systems.",
            "Use Siemens ProductCERT/model-specific guidance, test updates in a development environment, then deploy through OT change control.",
            d3fend_ids=["D3-SU"],
        ))
    elif targeted and unknown(asset.patch_status):
        findings.append(_f(
            "LOW", "PATCH_STATUS_UNKNOWN", "Patch status is not recorded",
            "The inventory does not establish whether applicable Siemens security updates have been reviewed and applied.",
            "Record patch-review status and the source/date of the Siemens ProductCERT verification.",
            d3fend_ids=["D3-SU"],
        ))

    if targeted and no(asset.gold_copy_verified):
        findings.append(_f(
            "MEDIUM", "GOLD_COPY_NOT_VERIFIED", "Controller state not verified against a known-good backup",
            "The inventory states that the PLC firmware/configuration has not been verified against a backup gold copy.",
            "Verify firmware, configuration, and approved logic against a controlled known-good backup and preserve recovery copies offline.",
            d3fend_ids=["D3-HCI", "D3-ACH"],
        ))

    if yes(asset.remote_access) and not yes(asset.mfa):
        findings.append(_f(
            "HIGH", "REMOTE_ACCESS_WITHOUT_MFA", "Remote access is enabled without confirmed MFA",
            "The inventory indicates remote access but does not confirm multi-factor authentication.",
            "Require MFA for all remote OT access, place access behind a managed jump host/VPN, restrict source addresses, and log sessions.",
            attack_ids=["T1694"], d3fend_ids=["D3-CH", "D3-NAM"],
        ))

    if targeted and no(asset.engineering_access_restricted):
        findings.append(_f(
            "HIGH", "ENGINEERING_ACCESS_NOT_RESTRICTED", "Engineering access is not restricted to approved workstations",
            "AA26-231A recommends limiting TIA Portal/STEP 7 access to authorized engineering workstations using PLC/network allowlisting.",
            "Restrict programming access to approved engineering workstations by IP/MAC where supported and enforce equivalent industrial firewall ACLs.",
            attack_ids=["T1694"], d3fend_ids=["D3-NAM"],
        ))

    if targeted and no(asset.plc_password):
        findings.append(_f(
            "HIGH", "PLC_PASSWORD_NOT_ENABLED", "PLC password protection is not confirmed enabled",
            "The inventory indicates PLC password protection is disabled or absent.",
            "Enable model-appropriate PLC password protection and manage credentials under the site's OT credential policy.",
            attack_ids=["T1694"], d3fend_ids=["D3-CH"],
        ))

    if targeted and no(asset.protection_level):
        findings.append(_f(
            "MEDIUM", "PROTECTION_LEVEL_NOT_CONFIGURED", "PLC read/write protection level is not configured",
            "AA26-231A recommends enabling available write or read/write protection levels on Siemens S7 controllers.",
            "Configure the strongest protection level compatible with operations, validate engineering workflows, and document exceptions.",
            d3fend_ids=["D3-CH", "D3-ACH"],
        ))

    if targeted and no(asset.snmp_hardened):
        findings.append(_f(
            "MEDIUM", "SNMP_NOT_HARDENED", "SNMP configuration is not hardened",
            "The inventory indicates default/weak SNMP community configuration has not been removed or changed.",
            "Remove or change default SNMP community strings and disable SNMP where it is not operationally required.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.app_allowlisting):
        findings.append(_f(
            "MEDIUM", "ENGINEERING_APP_ALLOWLISTING_DISABLED", "Application allowlisting is not enabled on the engineering path",
            "AA26-231A recommends application allowlisting on engineering workstations to reduce execution of masquerading scripts and unauthorized tools.",
            "Enable application allowlisting on engineering workstations and explicitly approve required Siemens and support tooling.",
            attack_ids=["T0849", "T0834"], d3fend_ids=["D3-PM"],
        ))

    if targeted and no(asset.logging_enabled):
        findings.append(_f(
            "HIGH", "S7_MONITORING_NOT_ENABLED", "Comprehensive S7comm logging/monitoring is not enabled",
            "The inventory indicates S7comm/TIA/STEP 7 activity is not comprehensively logged or monitored.",
            "Monitor TCP/102, alert on unauthorized PUT/GET or write activity, record engineering connections, baseline normal behavior, and retain logs.",
            attack_ids=["T0834", "T0821", "T0893"], d3fend_ids=["D3-PM", "D3-NTA"],
        ))

    if targeted and no(asset.web_server_disabled):
        findings.append(_f(
            "MEDIUM", "UNNEEDED_WEB_SERVER_ENABLED", "PLC web server is not confirmed disabled",
            "AA26-231A recommends disabling Siemens S7 web servers when not operationally required.",
            "Disable the PLC web server unless a documented operational requirement exists; otherwise restrict and monitor access.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.unused_protocols_disabled):
        findings.append(_f(
            "MEDIUM", "UNUSED_PROTOCOLS_ENABLED", "Unused PLC communication protocols are not disabled",
            "The inventory indicates unused services/protocols have not been disabled.",
            "Disable unused communication protocols such as Modbus TCP or PROFINET when they are not required, following vendor guidance and change control.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.connection_limits):
        findings.append(_f(
            "LOW", "S7_CONNECTION_LIMITS_NOT_CONFIGURED", "S7comm session limits are not configured",
            "AA26-231A recommends limiting simultaneous S7comm connection resources where supported.",
            "Configure model-appropriate connection/session limits after validating legitimate engineering and HMI requirements.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.restart_protection):
        findings.append(_f(
            "LOW", "RESTART_PROTECTION_NOT_ENABLED", "Complete restart protection is not enabled",
            "The inventory indicates the relevant TIA Portal/STEP 7 restart protection feature is not enabled or not applicable.",
            "Where supported and operationally compatible, enable complete restart protection and document exceptions.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.know_how_protection):
        findings.append(_f(
            "LOW", "KNOW_HOW_PROTECTION_NOT_ENABLED", "Know-how protection is not enabled",
            "The inventory indicates Siemens know-how protection is not enabled or not applicable.",
            "Where supported and appropriate, enable know-how protection for sensitive logic and manage recovery material securely.",
            d3fend_ids=["D3-ACH"],
        ))

    if targeted and no(asset.logic_integrity_verified):
        findings.append(_f(
            "HIGH", "LOGIC_INTEGRITY_NOT_VERIFIED", "Ladder logic/configuration integrity is not verified",
            "AA26-231A recommends evaluating ladder-logic changes in online/offline modes and hunting for unauthorized configuration changes.",
            "Compare online controller logic/configuration hashes or approved engineering exports with the change-controlled known-good baseline; investigate drift.",
            attack_ids=["T0821"], d3fend_ids=["D3-ACH", "D3-PM"],
        ))

    if targeted and no(asset.vendor_support_verified):
        findings.append(_f(
            "LOW", "VENDOR_SUPPORT_NOT_VERIFIED", "Model-specific Siemens guidance has not been verified",
            "The inventory indicates model/firmware-specific Siemens support guidance has not been reviewed.",
            "Confirm patch compatibility and hardening guidance with Siemens ProductCERT/Technical Support and document the review date.",
            d3fend_ids=["D3-SU", "D3-HCI"],
        ))

    findings.extend(apply_advisories(asset, advisories))

    base = max((SEVERITY_POINTS.get(f.severity, 0) for f in findings), default=0)
    score = min(100, base + min(20, max(0, len(findings) - 1) * 3))
    if any(f.severity == "CRITICAL" for f in findings):
        level = "CRITICAL"
    elif any(f.severity == "HIGH" for f in findings):
        level = "HIGH"
    elif any(f.severity == "MEDIUM" for f in findings):
        level = "MEDIUM"
    elif any(f.severity == "LOW" for f in findings):
        level = "LOW"
    else:
        level = "INFO"

    return ScanResult(asset=asset, is_public_ip=public, ports=port_results, findings=findings, risk_score=score, risk_level=level)
