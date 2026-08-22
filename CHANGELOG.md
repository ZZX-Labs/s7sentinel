# Changelog

All notable changes are documented here. The project follows Semantic Versioning while the public API remains pre-1.0.

## [0.1.0] ~~[0.3.0]~~ - 2026-08-21

### Added

- `agentcheck` for non-executing local review of Hermes/OpenClaw-style agentic workspace artifacts.
- `agentlog` for normalized identity/web/API telemetry analysis.
- detections for password spraying, parallel endpoint reconnaissance, cross-system SSO pivoting, JWT `none` observations, unauthenticated sensitive API success, server-side upload events, large sensitive responses, and automation bursts.
- defensive Bayesian evidence-priority scoring with explicit non-probability semantics.
- `profile` command exposing built-in AA26-231A and Dream-derived defensive profiles.
- strict inventory and event-schema validation.
- professional GitHub issue forms, workflows, governance, support, code-of-conduct, data-handling, architecture, threat-model, deployment, and release documentation.
- expanded unit tests and synthetic examples.

### Changed

- report schema version increased to 3.
- project description broadened from S7-only posture checking to S7/OT plus agentic-intrusion defensive analysis.

### Security

- retained explicit authorization requirement for network checks.
- retained refusal of non-RFC1918 CIDR expansion.
- artifact scanners never execute discovered code.

## [0.2.0] - 2026-08-21

- expanded AA26-231A posture controls.
- added local Snap7 artifact hunt and normalized S7 log analysis.
- added HTML/JSON reporting and verified local advisory rules.

## [0.1.0] - 2026-08-21

- initial conservative TCP/102 exposure and inventory posture checker.
