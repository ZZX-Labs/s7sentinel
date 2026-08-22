# Roadmap

## 0.3 — Public repository baseline

- AA26-231A PLC posture assessment
- TCP/102 reachability with authorization gates
- Snap7/python-snap7 local artifact review
- S7 telemetry anomaly analysis
- Dream-derived agentic artifact and telemetry profile
- Defensive Bayesian priority scoring
- professional CI, security, contribution, and release scaffolding

## 0.4 — Passive analysis

- PCAP metadata ingestion without packet transmission
- richer normalized firewall/IDS import adapters
- configurable allowlists for engineering workstations and approved scanners
- JSON Schema documents for input/output formats
- SARIF export for selected host findings

## 0.5 — Baselines and integrity

- signed asset-baseline manifests
- engineering-workstation allowlist manifests
- known-good hash comparison
- vendor-exported PLC logic/configuration integrity metadata ingestion
- evidence provenance and report signing

## 0.6 — Integration

- syslog/CEF output
- SIEM-oriented JSONL
- STIX-compatible defensive observations where appropriate
- optional PyQt5 desktop front end in a separate extras package

## 1.0 — Stable defensive API

- stabilized JSON report schemas
- documented extension interface for defensive profiles
- long-term compatibility policy
- reproducible release artifacts and signed provenance

The project will not add exploit execution, credential attacks, PLC write capability, Internet-wide discovery, persistence, or autonomous offensive operation.
