# Product requirements

Requirement identifiers are stable and should be referenced by implementation tasks and tests.

## Functional requirements

### Scope and ingestion

- **FR-SCP-001:** Create a case-specific scope policy before any tool executes.
- **FR-SCP-002:** Describe allowed repositories, services, identities, networks, actions, tools, time, compute, and approval conditions.
- **FR-SCP-003:** Reject targets and actions that cannot be resolved to an explicit scope object.
- **FR-ING-001:** Ingest source, dependency manifests, SBOMs, SARIF, structured telemetry, and authorized target metadata.
- **FR-ING-002:** Preserve source provenance, timestamps, content hashes, and collection identity.

### Detection and investigation

- **FR-DET-001:** Normalize telemetry into a stable event schema; OCSF compatibility is the preferred direction.
- **FR-DET-002:** Correlate events into incident hypotheses with explicit evidence references.
- **FR-DET-003:** Distinguish observation, inference, uncertainty, and confirmed fact.
- **FR-DET-004:** Map supported behaviors to MITRE ATT&CK and candidate mitigations to D3FEND.
- **FR-INV-001:** Construct a timeline, affected-asset set, likely initial access, blast radius, and open questions.
- **FR-INV-002:** Record competing hypotheses rather than prematurely collapsing uncertainty.

### Vulnerability discovery and localization

- **FR-VUL-001:** Orchestrate deterministic static, dependency, secret, and dynamic-analysis adapters.
- **FR-VUL-002:** Deduplicate and correlate findings without treating scanner output as ground truth.
- **FR-VUL-003:** Attempt controlled reproduction before high-cost patching when a reproducer is feasible.
- **FR-VUL-004:** Link runtime evidence to repository, commit, artifact, file, function, and code owner where provenance permits.

### Response and recovery

- **FR-RSP-001:** Propose containment actions with predicted effect, risk, reversibility, scope, and rollback.
- **FR-RSP-002:** Auto-execute only actions explicitly allowed by policy for the current risk tier.
- **FR-RSP-003:** Verify containment outcome and detect unintended availability impact.
- **FR-RCV-001:** Support clean rebuild and isolated deployment of a verified candidate.
- **FR-RCV-002:** Replay the attack and a benign workload before declaring recovery.
- **FR-RCV-003:** Monitor for recurrence during a policy-defined observation window.

### Repair

- **FR-PAT-001:** Generate one or more minimal candidate diffs from a compact evidence context.
- **FR-PAT-002:** Apply candidates only to disposable, content-addressed workspaces.
- **FR-PAT-003:** Generate or select security and regression tests without exposing hidden evaluator tests.
- **FR-PAT-004:** Preserve the original candidate, rationale, model configuration, prompt template version, and tool transcript.

### Assurance and reporting

- **FR-ASR-001:** Verify candidates in a clean-room environment unavailable for agent modification.
- **FR-ASR-002:** Enforce non-compensating hard failures: build failure, successful exploit replay, required regression failure, scope violation, or evidence tampering cannot be outweighed by model confidence.
- **FR-ASR-003:** Return `VERIFIED`, `REVIEW_REQUIRED`, `REJECTED`, or `CONTROL_FAILURE`.
- **FR-ASR-004:** Produce an evidence-carrying patch bundle with hashes and provenance.
- **FR-RPT-001:** Export machine-readable JSON and SARIF where applicable, plus a human-readable case report.

## Control and safety requirements

- **SR-AUT-001:** The model cannot grant, broaden, or refresh its own capabilities.
- **SR-AUT-002:** Each worker uses a distinct identity; shared credentials and shared writable state are prohibited by default.
- **SR-AUT-003:** Capabilities are short-lived, least-privilege, case-scoped, and action-specific.
- **SR-AUT-004:** The action broker is the only effectful path from reasoning to tools or targets.
- **SR-NET-001:** Network egress is denied by default at both worker and supporting-service boundaries.
- **SR-NET-002:** Any allowed destination is resolved and pinned by policy; indirect egress through proxies, package mirrors, artifact stores, DNS, or metadata services is included in the threat model.
- **SR-AUD-001:** Audit events are append-only, externally stored, and unavailable for agent deletion or rewriting.
- **SR-AUD-002:** Commands, inputs, outputs, decisions, approvals, identities, and artifact hashes are attributable to a case.
- **SR-INJ-001:** Repository content, logs, alerts, tickets, tool output, and threat intelligence are treated as untrusted data, never system instructions.
- **SR-SEC-001:** Secrets are redacted from model context unless explicitly necessary and permitted.
- **SR-SEC-002:** Raw Docker sockets, host shells, cloud-admin credentials, and production IAM mutation are never exposed to a model.
- **SR-STP-001:** A deterministic emergency stop can terminate workers and revoke capabilities without cooperation from the reasoning runtime.
- **SR-HUM-001:** Irreversible, destructive, high-blast-radius, or production-impacting actions require human approval.
- **SR-MON-001:** Safety monitors may restrict, pause, or escalate actions; they cannot grant new authority.

## Quality attributes

- **QR-REP-001 Reproducibility:** A case can be replayed from versioned inputs, images, policies, and model configuration, subject to provider determinism limitations.
- **QR-OBS-001 Observability:** Every workflow transition and tool action emits a structured event.
- **QR-PORT-001 Portability:** Model providers, tools, sandboxes, and storage backends are replaceable adapters.
- **QR-CST-001 Cost control:** Every case has token, tool-call, compute, wall-clock, and monetary budgets.
- **QR-RES-001 Resilience:** Partial tool/provider failure leads to bounded retry, fallback, refusal, or escalation—not an uncontrolled loop.
- **QR-PRV-001 Privacy:** External-provider use is policy-controlled and data minimization is mandatory.
- **QR-TST-001 Testability:** The policy engine, action broker, state transitions, parsers, and assurance gate can be tested without a live LLM.

## Acceptance constraints

The MVP is not accepted unless it includes at least one test for each of these failure modes:

- out-of-scope filesystem path;
- forbidden network destination;
- prompt injection in a log or source comment;
- tampered tool output or artifact hash;
- repeated action-budget exhaustion;
- attempted access to hidden verifier data;
- patch that blocks the exploit but breaks legitimate behavior;
- patch that passes visible tests but fails a hidden security test; and
- human-approval timeout or denial.
