# ADR 0002: Bayesian Values Are Triage Priority, Not Compromise Probability

Status: Accepted

## Context

The supplied Dream Research Labs report describes Bayesian prioritization in an offensive framework. Defenders also need a way to prioritize correlated evidence, but an uncalibrated number can create false confidence.

## Decision

S7Sentinel may aggregate evidence using odds/likelihood-ratio mathematics, but the output is named `defensive_priority`, starts from a conservative prior, and is explicitly documented as an analyst-ranking score rather than a probability of compromise.

## Consequences

The score can order review queues while preserving semantic honesty. Future calibration work may replace or augment the model, but must document datasets, assumptions, and limitations before any probabilistic claim is made.
