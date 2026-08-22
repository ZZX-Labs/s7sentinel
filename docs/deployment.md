# Deployment Guide

## Recommended order

Begin with offline evidence. Run inventory assessment first, then local artifact checks, then telemetry analysis. Introduce active TCP reachability only after the responsible OT owner approves it.

## Workstation installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

For a reproducible internal deployment, build a wheel in CI and distribute the wheel through your approved package channel.

## Production OT guidance

Prefer running S7Sentinel from a management or security analysis host rather than directly on PLC engineering stations. Keep reports in a protected directory because inventories and telemetry may reveal sensitive topology or operational metadata.

For active checks, use the smallest authorized target range, preserve the default TCP/102 port unless another defensive reachability question is explicitly approved, and avoid excessive workers/timeouts on fragile networks.

## Logging pipeline

Normalize firewall, IDS, reverse-proxy, SSO, WAF, and application events outside S7Sentinel. The project intentionally avoids direct vendor API integrations in the core package so that runtime remains small, auditable, and offline-capable.
