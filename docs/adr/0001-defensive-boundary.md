# ADR 0001: Preserve a Defensive-Only Capability Boundary

Status: Accepted

## Context

S7 and agentic intrusion research includes techniques that can be implemented offensively. A public defensive toolkit should not require those primitives to answer routine exposure and monitoring questions.

## Decision

S7Sentinel will not implement PLC read/write operations, credential attacks, CAPTCHA bypass, token forgery, persistence, exploit execution, Internet-wide target discovery, or autonomous attack chaining. Active network behavior is limited to explicitly authorized conservative TCP reachability.

## Consequences

Some vulnerability validation must remain external to the project and be performed through vendor-approved tooling or authorized specialized assessments. The core project remains easier to audit, safer to deploy, and less useful as an offensive framework.
