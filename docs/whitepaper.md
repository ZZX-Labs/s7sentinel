# S7Sentinel: Defensive Verification for Industrial Control Systems and AI-Orchestrated Intrusion Patterns

## Technical White Paper

Version 0.3.0 — August 2026

## Abstract

Industrial control-system defense is entering a period in which the economics of attack are changing faster than many operational-technology security programs can change their architecture. Public protocol libraries, searchable vulnerability information, Internet-scale reconnaissance services, and increasingly capable AI agent frameworks reduce the cost of transforming public knowledge into operational cyber capability. The result is not simply faster exploit development. It is the ability to parallelize reconnaissance, credential abuse, endpoint discovery, application testing, and after-action adaptation across many targets at once.

S7Sentinel is a defensive Python framework designed to translate this threat intelligence into low-risk verification checks. Its first profile implements inventory, segmentation, access-control, host-artifact, and telemetry concepts from U.S. Cybersecurity Advisory AA26-231A, *Defending Against an Active Threat to Siemens S7 Series PLCs*, released August 19, 2026 by NSA, CISA, FBI, DOE, and EPA. Its second profile translates a supplied Dream Research Labs report, *Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia*, into local artifact and identity/web/API telemetry detections for highly parallel automated intrusion behavior.

The central design rule is that defensive assessment should not require reproducing the attack. S7Sentinel therefore excludes PLC memory reads and writes, ladder-logic extraction, credential attacks, CAPTCHA bypass, token forgery, persistence, exploit execution, Internet-wide discovery, and autonomous attack chaining. It favors offline inventory analysis, local artifact inspection, normalized telemetry, authoritative advisory correlation, and minimal TCP reachability where active checks are explicitly authorized.

## 1. The Security Problem

Programmable logic controllers occupy a special position in computing because they bridge information systems and physical processes. A compromised enterprise workstation may expose records or credentials. A compromised controller may change the behavior of motors, pumps, valves, furnaces, conveyors, chemical processes, safety interlocks, or other machinery. This makes the risk model qualitatively different from ordinary IT vulnerability management.

AA26-231A describes active targeting of Siemens S7-200, S7-300, S7-400, S7-1200, and S7-1500 controllers, including safety-oriented variants. The advisory emphasizes Internet exposure, inadequate segmentation, known vulnerabilities, weak credentials, and misuse of legitimate industrial libraries such as Snap7. The risk is not merely immediate disruption. Read access and configuration reconnaissance can provide adversaries with operational knowledge that becomes useful later.

The supplied Dream Research Labs report describes a different but complementary problem: offensive work can be distributed across multiple AI agents, orchestrated in parallel, and continuously reprioritized based on results. The report describes workspace identifiers associated with Hermes and OpenClaw, large volumes of automatically generated files, parallel attack waves, credential spraying, SSO pivoting, API weaknesses, unsigned JWT behavior, file-upload abuse, and repeated self-verification.

These two cases share an important structural lesson. Defenders should no longer depend on the assumption that industrial protocols are too obscure, application ecosystems too large, or attack chains too time-consuming for an adversary to operationalize. The durable controls are architectural: know the assets, minimize exposure, enforce authentication, restrict trust relationships, monitor the relevant protocols and identity paths, baseline expected state, and investigate unexplained change.

## 2. Design Objectives

S7Sentinel was designed around six objectives.

First, it should be useful before an operator receives approval for active testing. An inventory-only PLC assessment sends no packets. Artifact and telemetry modes operate on local evidence.

Second, active behavior should be minimal. The only network action in the core package is an ordinary TCP connection attempt to an explicitly authorized target. S7 application-layer protocol operations are unnecessary for determining whether TCP/102 is reachable.

Third, evidence and inference should remain distinct. An S7-1200 is not a vulnerability simply because the family is named in an advisory. A `.openclaw` directory is not proof of compromise. A reachable service is exposure evidence, not proof that exploitation occurred. S7Sentinel encodes these distinctions in finding severity and wording.

Fourth, invalid evidence should fail loudly. A malformed timestamp, invalid address, duplicate inventory row, or missing required telemetry column must not be silently transformed into a clean report.

Fifth, local files under review should never be executed. Artifact scanners inspect names and bounded text content as data and may hash matches, but do not import, dynamically load, or evaluate discovered source code.

Sixth, the project should remain extensible as a defensive profile framework. Threat reports change, but the evidence categories—assets, paths, controls, artifacts, events, baselines, and analyst context—remain reusable.

## 3. Architecture

The system is divided into a command layer, evidence collectors/parsers, analysis modules, profiles, and report writers.

```text
                       S7Sentinel CLI
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
       PLC path          Artifact path      Telemetry path
          |                  |                  |
     inventory.py        hostcheck.py        logcheck.py
     scanner.py          agentic.py          agentic.py
     risk.py                  |                  |
          +------------------+------------------+
                             |
                         report.py
```

The separation is deliberate. `scanner.py` contains the active TCP behavior. `inventory.py` validates asset records. `risk.py` implements the AA26-231A posture logic and local advisory matching. `hostcheck.py` inspects Snap7-related artifacts. `logcheck.py` evaluates normalized S7comm-oriented events. `agentic.py` contains the Dream-derived local artifact and identity/web/API telemetry profile. `profiles.py` exposes profile metadata for operators and integrations.

The runtime package has no third-party dependencies. This reduces supply-chain surface, simplifies review, and helps deployment in isolated environments.

## 4. AA26-231A PLC Posture Model

The PLC profile begins with inventory because vulnerability management without asset identity is incomplete by definition. The recognized inventory fields include IP address, asset name, controller model, firmware, network zone, Internet exposure, remote access, MFA state, patch state, gold-copy verification, engineering workstation restrictions, PLC password protection, protection level, SNMP hardening, application allowlisting, monitoring, web server state, unused protocols, connection limits, restart protection, know-how protection, logic-integrity verification, and vendor-support review.

S7Sentinel recognizes the S7 family set named by the advisory and adds an informational finding so operators can prioritize review. It does not interpret family membership as proof of vulnerability.

Where active testing is approved, the tool can attempt a TCP connection to port 102. A successful connection means only that the ISO-on-TCP/S7comm service path is reachable from the assessment host. It does not identify a CPU, authenticate to the controller, request data blocks, read ladder logic, or attempt a write.

The risk engine raises urgency when reachability combines with Internet exposure or when the inventory explicitly records missing controls such as MFA, engineering access restrictions, current patching, monitoring, or logic-integrity verification.

## 5. Network Exposure and Authorization Controls

A defensive scanner can itself become dangerous if target selection is unconstrained. S7Sentinel therefore treats target expansion as a security boundary.

RFC1918 CIDRs may be expanded locally. Non-RFC1918 CIDR expansion is refused even when the operator enables the public-address flag. An individual non-RFC1918 IPv4 address may be supplied only when `--allow-public` is used, and any network check also requires `--authorized`.

This does not attempt to solve the legal or organizational question of authorization in software. It creates friction against accidental scanning and makes the operator make an explicit declaration.

The design specifically excludes integration with Internet-wide discovery services. Those services may have legitimate defensive use, but incorporating their search capability into the core project would change its abuse potential and is unnecessary for the primary task of verifying known organizational assets.

## 6. Engineering Workstation Artifact Review

AA26-231A identifies Snap7-related tooling as part of the observed threat activity. Snap7 is also a legitimate engineering library. The correct security question is therefore contextual: is the artifact expected on this workstation, does its hash match an approved baseline, who installed it, and is the host allowed to communicate with controllers?

`hostcheck` searches bounded local roots for Snap7-related library names, package metadata, and simple source references such as Snap7 imports. Matching files may be hashed for comparison against an organizational allowlist.

The scanner reads files as data. A test fixture deliberately contains source code that would create a marker file if executed; the test confirms the marker is never created. This invariant is important because defensive endpoint inspection must not activate the material it is examining.

## 7. S7 Telemetry Analysis

`logcheck` consumes a deliberately small normalized CSV schema containing timestamp, source address, destination address, destination port, operation, authorization status, and change ticket.

The analyzer identifies four principal patterns. It reports TCP/102 activity from sources explicitly marked unauthorized. It reports write/change-like operations without a change ticket. It can flag S7 activity outside a supplied maintenance window. It also detects a source contacting multiple TCP/102 destinations within a short window, which may indicate reconnaissance or an unexpected automated process.

These checks are intentionally based on metadata that many firewalls, sensors, or ICS-aware monitoring products can export. S7Sentinel does not attempt to replace a full industrial IDS.

## 8. Agentic Intrusion Defensive Profile

The Dream-derived profile shifts from OT protocol posture to identity, web, API, and local-host evidence. The goal is to detect the observable consequences of highly automated multi-agent operations without recreating the attacker workflow.

`agentcheck` reviews local roots for `.hermes` and `.openclaw` directory names and correlated textual markers such as learning-cycle or posterior-prioritization language. These are contextual review signals only. Development teams may legitimately use the same frameworks or vocabulary.

`agentlog` accepts normalized identity, web, API gateway, WAF, SSO, reverse-proxy, or application events. The minimum required fields are timestamp, source address, and event type. A richer schema adds user, system, endpoint, status, authentication result and method, JWT algorithm metadata, bytes returned, uploaded file name, user agent, local authorization label, sensitivity label, and change ticket.

The analyzer detects several behavior classes.

A password-spray pattern occurs when one source produces failed authentication events against many distinct identities inside a bounded window. The detector never generates passwords or authenticates to a service; it only examines recorded failures.

Parallel endpoint reconnaissance is represented by one source touching many distinct system/endpoint pairs quickly. The threshold is configurable because approved scanners and test automation can create similar behavior.

Cross-system SSO pivoting is represented by one source and identity succeeding across several systems in a short period. This can be legitimate in a tightly integrated environment, so the finding instructs analysts to compare it against expected SSO workflows and role breadth.

JWT algorithm `none` telemetry is treated as particularly important because accepted unsigned tokens indicate an application-validation failure. The tool does not create or submit a token; it analyzes metadata already captured by the defender.

Successful access to a resource locally labeled sensitive with an anonymous/none authentication method is treated as critical evidence of an authorization-control failure. Again, the checker does not probe the endpoint.

Successful upload of a server-executable file extension is treated as high priority because such uploads are uncommon in many application contexts and can be associated with persistence. The tool neither creates nor executes uploaded content.

Large responses from sensitive or export-like operations are reported for exfiltration review. High event velocity is separately reported as an automation indicator.

## 9. Defensive Bayesian Priority Scoring

The supplied Dream report describes Bayesian posterior scoring used to prioritize offensive work. S7Sentinel reuses only the mathematical idea of evidence accumulation for defense.

A small prior odds value is updated with likelihood multipliers attached to defensive evidence classes. The resulting bounded value is called `defensive_priority`.

The name is intentional. It is not a probability that compromise occurred. The likelihood ratios are heuristic, the dataset is not globally calibrated, and base rates vary across environments. A number that looks probabilistic can create more confidence than the underlying evidence supports.

The score therefore has one purpose: when multiple findings point to the same source, place the source higher in the analyst review queue. Formal probabilistic interpretation would require empirical calibration, documented sampling assumptions, and validation against representative benign and malicious datasets.

## 10. Vulnerability Correlation

Industrial vulnerability applicability is often model-, hardware-, firmware-, and feature-specific. A broad statement that a product family is being targeted does not justify inventing a CVE match.

S7Sentinel therefore supports operator-supplied local advisory rules. A rule can specify model and firmware regular expressions, a CVE identifier, severity, summary, remediation, and source. The operator is expected to populate these rules only from authoritative sources such as Siemens ProductCERT or relevant government guidance.

This keeps the built-in profile accurate when the source advisory describes risk without enumerating exact CVE/firmware pairs.

## 11. Evidence Semantics and Severity

S7Sentinel uses severity to express review urgency, not forensic certainty.

`INFO` represents context, such as a model family named by an advisory. `LOW` represents hygiene or documentation gaps. `MEDIUM` represents meaningful control weakness or suspicious indicators. `HIGH` represents significant exposure or strongly correlated suspicious behavior. `CRITICAL` is reserved for combinations or events that imply unusually unsafe conditions, such as Internet-exposed reachable PLC services or successful unsigned/unauthenticated access to sensitive application resources.

The same event can mean different things in different environments. An approved vulnerability scanner may touch many endpoints rapidly. An enterprise portal may legitimately authenticate an identity to several backing systems. An engineering workstation may legitimately contain Snap7. Context remains indispensable.

## 12. Operational Deployment Pattern

A conservative deployment follows four stages.

Stage one is inventory-only assessment. Operators should resolve unknown firmware, patch state, segmentation, remote access, protection settings, and baseline verification before sending traffic.

Stage two is local evidence review. Engineering workstations and management hosts can be checked for relevant artifacts and compared with approved software manifests.

Stage three is telemetry analysis. Existing firewall, IDS, SSO, WAF, reverse-proxy, API gateway, and application logs should be normalized outside the core package and passed to S7Sentinel.

Stage four is minimal active validation. Only after authorization and operational coordination should operators use TCP reachability checks against tightly bounded targets.

This sequencing turns the traditional scan-first approach on its head. In safety-sensitive environments, the defender should exhaust low-risk evidence before increasing interaction with a production controller.

## 13. CI/CD and Supply-Chain Posture

The public repository includes unit tests, compile checks, lint configuration, CodeQL analysis, dependency review, Dependabot configuration, and a tag-triggered release build. The core package has no runtime dependencies.

The release workflow builds source and wheel artifacts and generates SHA-256 checksums. PyPI publication is intentionally not enabled by default. Package-registry publication should be activated only after maintainers configure trusted publishing and provenance requirements.

The repository also includes issue forms designed to prevent accidental publication of real production telemetry, credentials, or undisclosed vulnerabilities.

## 14. Limitations

S7Sentinel is not a replacement for Siemens engineering tools, ProductCERT guidance, an industrial IDS, EDR, identity-protection products, a SIEM, firewall management, a CMDB, process-safety engineering, or incident response.

A sophisticated adversary may operate through a legitimate engineering host, reuse an approved identity, remain under thresholds, tamper with logs, or mimic ordinary maintenance patterns. A clean report therefore cannot establish absence of compromise.

The agentic profile is behavioral, not framework attribution. The presence of Hermes/OpenClaw artifacts does not prove that the campaign described by Dream Research Labs is present. Likewise, password spraying and API abuse can be performed without AI.

## 15. Future Work

Planned defensive extensions include passive PCAP metadata ingestion, signed asset baselines, known-good engineering workstation manifests, vendor-exported controller logic/configuration integrity metadata, JSON Schema definitions, SIEM-oriented JSONL/CEF/syslog output, and a stabilized profile extension interface.

A graphical PyQt5 front end may be developed as an optional extras package so the core runtime can remain dependency-free.

The defensive boundary will remain unchanged: no exploit execution, credential attacks, PLC writes, persistence, Internet-wide target discovery, or autonomous offensive operation.

## 16. Strategic Implications

The deeper lesson behind both source reports is that attacker labor is becoming cheaper to parallelize. Open technical documentation, public code, searchable vulnerability knowledge, and agentic AI reduce the delay between discovery and operational use.

Defenders should therefore optimize for structural resilience rather than attacker inconvenience. A PLC that cannot be reached from an untrusted path is harder to attack. A remote-access path protected by MFA and a managed jump host is harder to abuse. A controller that accepts programming connections only from approved engineering hosts has fewer attack paths. A known-good logic baseline makes unauthorized change easier to detect. A sensitive API that enforces authorization server-side is not protected merely because its URL is obscure. An SSO system that limits session breadth and records token provenance provides stronger evidence during incident response.

Each control removes degrees of freedom from the adversary.

## 17. Conclusion

S7Sentinel treats threat intelligence as an input to verification, not as an instruction to reproduce attacker tooling. It converts two different threat narratives—active PLC targeting and highly automated multi-agent intrusion operations—into a common defensive model built around assets, paths, controls, artifacts, events, and evidence.

The doctrine is straightforward:

```text
Know every critical asset.
Expose nothing unnecessarily.
Authenticate every privileged path.
Restrict engineering and administrative trust.
Monitor the protocols and identities that can change state.
Baseline configurations and applications.
Treat automation velocity as a security signal.
Distinguish evidence from conclusion.
Investigate unexplained change.
```

As offensive capability becomes cheaper to generate and coordinate, disciplined architecture and continuous verification become more valuable, not less.

## References

1. U.S. Cybersecurity Advisory AA26-231A, *Defending Against an Active Threat to Siemens S7 Series PLCs*, August 19, 2026; advisory text supplied with the project requirements.
2. Dream Research Labs, *Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia*; report text supplied with the project requirements.
3. MITRE ATT&CK for ICS and MITRE ATT&CK Enterprise, as referenced by the source advisory and project documentation.
4. MITRE D3FEND, as referenced by the source advisory and project documentation.
5. Siemens ProductCERT and Siemens Industrial Cybersecurity guidance for authoritative product-specific vulnerability and hardening information.
