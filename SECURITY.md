# Security Policy

## Supported versions

Security fixes are applied to the latest release line. Operators should run the most recent tagged release and review the changelog before deployment.

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| < 0.3 | No |

## Reporting a vulnerability in S7Sentinel

Do not include exploit details, credentials, production asset information, or sensitive incident artifacts in a public issue.

Use GitHub's private security-advisory mechanism for the repository when available. If the hosting organization publishes an alternative security contact, use that private channel. Include the affected version, component, impact, reproduction conditions using safe local fixtures, and proposed mitigation if known.

Maintainers should acknowledge reports promptly, reproduce them in an isolated environment, coordinate a fix, and publish a security advisory when impact warrants it.

## Operational security boundary

S7Sentinel is intended for defensive use. Active network checks require explicit operator authorization and are intentionally constrained to TCP reachability. The project does not implement:

- S7 application-layer reads or writes;
- ladder-logic extraction;
- PLC configuration modification;
- credential guessing, spraying, or brute force;
- CAPTCHA solving;
- JWT generation/forgery;
- exploit or proof-of-concept execution;
- denial-of-service testing;
- Internet-wide discovery;
- persistence deployment;
- autonomous attack-chain execution.

Pull requests that add those capabilities will not be accepted.

## Safe deployment

Before any active check against production OT:

1. obtain written authorization;
2. coordinate with the responsible control engineer;
3. identify safety-critical assets;
4. confirm backup and rollback procedures;
5. use maintenance/change-control windows where required;
6. begin with `--no-network` inventory mode;
7. use the smallest practical target set and conservative timeout/workers;
8. retain reports as potentially sensitive security data.

## Artifact scanners

`hostcheck` and `agentcheck` read files as data. They do not import, execute, dynamically load, or evaluate discovered code. Tests enforce this invariant.

## Evidence semantics

A finding is not automatically proof of compromise. Local artifacts, open ports, version gaps, and behavioral anomalies can have legitimate explanations. S7Sentinel reports the evidence and remediation context; incident confirmation remains an analyst responsibility.
