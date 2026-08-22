# Detection Catalog

This catalog summarizes the principal finding codes emitted by S7Sentinel. Exact fields may expand during the 0.x series.

## AA26-231A PLC posture

| Code | Severity basis | Meaning |
|---|---|---|
| `S7COMM_REACHABLE` | HIGH/CRITICAL | TCP/102 accepted a conservative connection attempt |
| `PUBLIC_IP_TARGET` | MEDIUM/HIGH | target address is not RFC1918 |
| `INVENTORY_INTERNET_EXPOSED` | HIGH/CRITICAL | inventory explicitly marks the asset Internet-exposed |
| `TARGETED_S7_FAMILY` | INFO | inventory model matches an S7 family named by AA26-231A |
| `LEGACY_S7_FAMILY` | MEDIUM | S7-200/300/400 lifecycle review warranted |
| `FIRMWARE_UNKNOWN` | MEDIUM | exact firmware is missing |
| `PATCH_STATUS_NOT_CURRENT` | HIGH | inventory says patching is not current |
| `REMOTE_ACCESS_WITHOUT_MFA` | HIGH | remote access lacks confirmed MFA |
| `ENGINEERING_ACCESS_NOT_RESTRICTED` | HIGH | approved workstation restriction absent |
| `PLC_PASSWORD_NOT_ENABLED` | HIGH | PLC password protection absent |
| `S7_MONITORING_NOT_ENABLED` | HIGH | S7 activity logging/monitoring absent |
| `LOGIC_INTEGRITY_NOT_VERIFIED` | HIGH | logic/configuration baseline not verified |
| `ADVISORY_MATCH` | local-rule severity | model/firmware matches a locally supplied authoritative rule |

Additional LOW/MEDIUM controls cover gold-copy verification, protection levels, SNMP, application allowlisting, web/protocol hardening, session limits, restart protection, know-how protection, and vendor support review.

## S7 telemetry

| Code | Severity | Meaning |
|---|---|---|
| `UNAUTHORIZED_S7_SOURCE` | HIGH | TCP/102 activity from a source marked unapproved |
| `S7_WRITE_WITHOUT_CHANGE_TICKET` | HIGH | write/change-like activity lacks change record |
| `S7_OUTSIDE_MAINTENANCE_WINDOW` | MEDIUM | S7 activity outside supplied approved hours |
| `SEQUENTIAL_S7_SCAN_PATTERN` | HIGH | one source contacts multiple PLC destinations rapidly |

## Agentic artifact profile

| Code | Severity | Meaning |
|---|---|---|
| `AGENTIC_WORKSPACE_DIRECTORY` | MEDIUM | `.hermes` or `.openclaw` directory observed |
| `AGENTIC_FILE_ARTIFACT` | MEDIUM | filename/content markers suggest related agentic planning/report material |

These are review signals, not compromise declarations.

## Agentic telemetry profile

| Code | Severity | Meaning |
|---|---|---|
| `PASSWORD_SPRAY_PATTERN` | HIGH | many distinct failed-user authentications from one source |
| `PARALLEL_ENDPOINT_RECON` | HIGH | rapid breadth across endpoint/system pairs |
| `CROSS_SYSTEM_SSO_PIVOT_PATTERN` | HIGH | same identity/source succeeds across multiple systems rapidly |
| `JWT_NONE_ALGORITHM_OBSERVED` | MEDIUM/CRITICAL | unsigned JWT algorithm marker, critical when accepted |
| `UNAUTHENTICATED_SENSITIVE_API_SUCCESS` | CRITICAL | sensitive resource succeeds with no authenticated method |
| `SERVER_SIDE_FILE_UPLOAD` | HIGH | successful upload of a server-executable file extension |
| `LARGE_SENSITIVE_RESPONSE` | HIGH | unusually large sensitive/export-like response |
| `AUTOMATED_ACTIVITY_BURST` | MEDIUM | high normalized event rate from one source |

Threshold-based findings should be tuned against known-good behavior and approved scanner/integration sources.
