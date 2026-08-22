# GitHub Action: offline analytical access

S7Sentinel ships as a reusable composite GitHub Action and as a manual workflow in this repository.

The GitHub-hosted execution path is intentionally **offline/read-only**. It analyzes files already present in the checked-out repository. It does not perform PLC network scans from GitHub infrastructure and does not provide a route to bypass S7Sentinel's authorization controls.

## Run from the S7Sentinel repository

Open **Actions → S7Sentinel Analysis → Run workflow** and choose an analysis mode.

The default run uses `inventory` mode against `examples/inventory.csv`. The workflow uploads generated reports as a GitHub Actions artifact and publishes only aggregate counts to the job summary.

Supported modes:

| Mode | Source | Output |
|---|---|---|
| `inventory` | inventory CSV | JSON + HTML |
| `s7log` | normalized S7comm/network event CSV | JSON |
| `agentlog` | normalized identity/web/API event CSV | JSON |
| `hostcheck` | repository-relative file/directory roots | JSON |
| `agentcheck` | repository-relative file/directory roots | JSON |

## Use S7Sentinel from another repository

Create a workflow such as `.github/workflows/s7sentinel.yml`:

```yaml
name: S7Sentinel

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: s7
        uses: ZZX-Labs/s7sentinel@v0.3.1
        with:
          mode: agentlog
          source: security/agentic-events.csv
          fail-on-findings: "false"
          upload-artifact: "true"

      - run: |
          printf '%s\n' "Result: ${{ steps.s7.outputs.result }}"
          printf '%s\n' "Findings: ${{ steps.s7.outputs['finding-count'] }}"
          printf '%s\n' "Report: ${{ steps.s7.outputs['report-json'] }}"
```

For production use, pin the action to an immutable release tag or commit SHA according to your organization's software-supply-chain policy.

## Pull-request inventory posture check

A repository containing a sanitized OT inventory can enforce a review gate without allowing network access:

```yaml
name: PLC inventory posture

on:
  pull_request:
    paths:
      - "security/plc-inventory.csv"

permissions:
  contents: read

jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ZZX-Labs/s7sentinel@v0.3.1
        with:
          mode: inventory
          source: security/plc-inventory.csv
          fail-on-findings: "true"
          upload-artifact: "true"
```

This evaluates only the supplied inventory. It sends no network traffic.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `inventory` | `inventory`, `s7log`, `agentlog`, `hostcheck`, or `agentcheck` |
| `source` | required | repository-relative file path or roots |
| `output-dir` | `s7sentinel-results` | report directory inside the workspace |
| `python-version` | `3.12` | Python runtime |
| `fail-on-findings` | `false` | translate S7Sentinel exit code 1 into workflow failure |
| `hash-matches` | `false` | SHA-256 matching artifacts for file-review modes |
| `maintenance-start` | empty | optional `HH:MM` value for `s7log` |
| `maintenance-end` | empty | optional `HH:MM` value for `s7log` |
| `upload-artifact` | `true` | upload the result directory |
| `artifact-name` | `s7sentinel-analysis` | GitHub artifact name |

## Outputs

The Action exposes `report-json`, `report-html`, `exit-code`, `result`, `finding-count`, `high-count`, `critical-count`, and `max-severity`.

The native exit code is retained as an output even when `fail-on-findings=false`. This lets downstream jobs distinguish a clean run from a successful run containing review-required findings.

## Data-handling warning

GitHub-hosted runners and workflow artifacts are not an appropriate place for secrets, production credentials, sensitive plant topology, or uncontrolled critical-infrastructure telemetry. Use sanitized or synthetic material in public repositories. For sensitive analysis, use an appropriately protected private repository and/or a self-hosted runner governed by your organization's OT security policy.

`hostcheck` and `agentcheck` are intentionally restricted by the Action wrapper to paths inside `GITHUB_WORKSPACE`; the Action will not traverse arbitrary GitHub-hosted runner paths.
