# Threat Model

## Assets to protect

S7Sentinel is designed to support protection of PLCs, OT networks, engineering workstations, identity infrastructure, API gateways, web applications, configuration baselines, credentials, and security telemetry.

## Adversary capabilities considered

The defensive profiles assume adversaries may use public scanning data, known vulnerabilities, weak credentials, legitimate automation libraries, high-concurrency scripting, AI-assisted planning, automated reconnaissance, credential spraying, SSO reuse, API abuse, unsigned-token weaknesses, and file-upload paths.

## Defender assumptions

S7Sentinel assumes the operator can provide trustworthy context such as an asset inventory, authorized engineering sources, change tickets, maintenance windows, and normalized logs. Missing or incorrect context can create false positives or false negatives.

## Project abuse resistance

The project reduces dual-use risk by excluding offensive primitives. It does not implement S7 read/write operations, exploit chains, credential attacks, token forgery, CAPTCHA bypass, persistence, or autonomous target discovery.

## Failure modes

A clean report is not proof of safety. Important failure modes include incomplete inventories, missing logs, compromised authorized engineering hosts, attackers operating through valid sessions, suppressed telemetry, low-and-slow activity below thresholds, and vendor-specific behavior not represented by the built-in profiles.

## Safety invariant

The most important invariant is that defensive analysis should not require changing the protected industrial process. When a task can be answered from inventory, firewall policy, endpoint artifacts, or logs, the project prefers those sources over deeper controller interaction.
