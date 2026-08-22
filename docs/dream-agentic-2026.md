# Dream-Derived Agentic Intrusion Defensive Profile

This profile is derived from the Dream Research Labs report supplied with the project requirements, *Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia*. The report describes an operation observed across approximately July 1-4, 2026 using Hermes/OpenClaw-style agent workspaces, parallel sub-agents, Bayesian prioritization, learning cycles, repeated verification, credential attacks, SSO pivoting, API weaknesses, and high-volume automated output.

S7Sentinel uses the report only to derive defensive telemetry and artifact checks.

## Defensive behaviors

The profile looks for:

- many failed authentication attempts against distinct users from one source;
- rapid access to many endpoint/system pairs;
- successful authentication by one identity/source across many systems in a short window;
- JWT telemetry indicating algorithm `none`, especially when accepted;
- successful sensitive API responses without an authenticated method;
- successful uploads of server-executable file types;
- unusually large responses from sensitive/export-like operations;
- high event velocity suggesting automation;
- local `.hermes` or `.openclaw` workspace indicators and correlated planning/report markers.

## What the profile does not do

It does not crack passwords, test default credentials, solve CAPTCHA challenges, forge tokens, upload files, test unauthenticated endpoints, exploit web applications, enumerate third-party systems, or search external repositories for exploitation material.

## Bayesian scoring

The report describes probability-based prioritization on the offensive side. S7Sentinel borrows only the general idea of evidence aggregation for defenders. Its output is deliberately labeled `defensive_priority`; it ranks correlated evidence for analyst review and must not be interpreted as a calculated probability that a host is compromised.
