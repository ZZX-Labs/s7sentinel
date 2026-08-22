# Architecture

S7Sentinel is intentionally modular. The package separates evidence collection from analysis and reporting so that passive workflows can be used without enabling active behavior.

```text
                     +-------------------+
                     |     CLI layer     |
                     +---------+---------+
                               |
         +---------------------+--------------------+
         |                     |                    |
         v                     v                    v
      scan/OT              host/artifact        telemetry
         |                     |                    |
         v                     v                    v
  scanner.py + risk.py     hostcheck.py      logcheck.py / agentic.py
         |                     |                    |
         +---------------------+--------------------+
                               |
                               v
                         report.py
```

## Active network path

`scanner.py` contains the only active network behavior. It performs ordinary TCP connection attempts to explicitly supplied/expanded targets. Authorization is enforced by the CLI, public CIDR expansion is refused, and no S7 application protocol implementation is included.

## PLC posture path

`inventory.py` validates operator-supplied CSV evidence. `risk.py` converts the inventory plus optional TCP reachability and local advisory rules into structured findings.

## Host artifact path

`hostcheck.py` scans local files for Snap7-related artifacts. `agentic.py` provides a second local scanner for agentic workspace indicators. Both read files as data and never import or execute discovered code.

## Telemetry path

`logcheck.py` analyzes normalized S7/network events. `agentic.py` analyzes normalized identity/web/API events. Both operate only on supplied CSV files.

## Profiles

`profiles.py` exposes human-readable metadata for the built-in AA26-231A and Dream-derived defensive profiles. Repository-level JSON under `rules/` documents the same intent for operators and maintainers.

## Trust boundaries

S7Sentinel treats the following as untrusted inputs:

- inventories;
- normalized telemetry;
- local files being inspected;
- local advisory-rule JSON;
- command-line target strings.

Input parsers validate required structure and avoid dynamic evaluation. Reports escape HTML content where HTML is generated.
