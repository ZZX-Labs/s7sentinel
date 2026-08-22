# Governance

S7Sentinel uses a lightweight maintainer model suitable for a security-focused open-source project.

Maintainers are responsible for release integrity, security policy, review of detection logic, compatibility, documentation quality, and preserving the defensive safety boundary. Routine changes may be merged after review and CI success. Security-sensitive architectural changes require explicit maintainer review of threat-model implications.

The following areas require heightened review:

- active network behavior;
- authorization gates;
- target expansion;
- new protocol parsers;
- credential or authentication handling;
- artifact execution/loading behavior;
- vulnerability matching;
- Bayesian/evidence scoring semantics;
- CI release credentials and package publication.

Project direction is documented in `ROADMAP.md`. Decisions that materially change the safety boundary should be recorded in documentation or an architecture decision record before release.
