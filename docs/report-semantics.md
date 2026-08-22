# Report Semantics

S7Sentinel uses severity to express review urgency, not certainty of compromise.

- `INFO`: context or profile match without an asserted control failure.
- `LOW`: hygiene/documentation gap with limited immediate exposure.
- `MEDIUM`: meaningful control weakness or suspicious indicator requiring review.
- `HIGH`: strong defensive concern, significant exposure, or correlated suspicious behavior.
- `CRITICAL`: conditions such as exposed PLC reachability combined with Internet exposure or strongly unsafe application behavior such as accepted unsigned tokens or successful unauthenticated access to sensitive resources.

A finding can be true while still benign in context. For example, Snap7 may be installed legitimately on an engineering workstation. Analysts should compare findings against allowlists, maintenance windows, ownership, hashes, change records, and expected workflows.

`defensive_priority` is an evidence-ranking mechanism. It is not a forensic conclusion and is not calibrated as a real-world probability of compromise.
