# Contributing to S7Sentinel

Thank you for contributing to defensive industrial and infrastructure security.

## Principles

Contributions must preserve S7Sentinel's safety boundary. The project accepts defensive inventory, validation, passive analysis, conservative reachability, detection, reporting, and evidence-correlation functionality. It does not accept exploit execution, credential attacks, Internet-wide discovery, PLC memory read/write operations, ladder-logic extraction, denial-of-service testing, persistence tooling, CAPTCHA bypass, token forgery, or code that autonomously targets third-party systems.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check s7sentinel tests
python -m compileall -q s7sentinel
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e .
py -m pip install -r requirements-dev.txt
py -m unittest discover -s tests -v
ruff check s7sentinel tests
```

## Pull requests

Keep pull requests focused. Include tests for behavioral changes. Explain the threat model and false-positive implications of new detections. Changes to thresholds should include rationale and synthetic test data. New vulnerability signatures must cite an authoritative vendor or government advisory in the rule metadata and must not be inferred solely from model family names.

A PR should pass:

```bash
python -m unittest discover -s tests -v
python -m compileall -q s7sentinel
ruff check s7sentinel tests
python -m build
```

## Detection contributions

A good detection contribution states:

- what telemetry is required;
- what condition is detected;
- why the condition is security-relevant;
- expected false positives;
- recommended remediation or analyst validation;
- whether the detection is source-derived or locally inferred;
- tests using synthetic data only.

Do not commit production logs, customer data, credentials, secrets, PLC configurations, or real incident material without explicit authorization and sanitization.

## Commit style

Use short imperative subjects, for example:

```text
Add validation for agentic event schema
Document AA26-231A control mapping
Fix duplicate inventory handling
```

## Documentation

Update README, CHANGELOG, data-format documentation, and tests when behavior changes. Security-sensitive changes should also update `SECURITY.md` or `docs/threat-model.md` when appropriate.

## Responsible research

If your contribution was inspired by an incident report, advisory, or third-party research, credit the source clearly. Preserve the difference between an indicator, a detection heuristic, a confirmed vulnerability, and a confirmed compromise.
