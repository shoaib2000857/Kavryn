# Worklog

## 2026-09-25 — object-authorization end-to-end case integration

- Added a second deterministic, real-Docker incident-to-recovery path using `run_case`: replay a synthetic Bob-to-Alice document request; broker Semgrep and proxy telemetry; correlate `/documents` to `app.py`; obtain attributed approval; temporarily deny only the synthetic Bob token while Alice can still read her own document; verify a known oracle owner-check patch in the clean-room container; deploy through `deployment.rollout`; then confirm cross-owner replay returns 404 and owner access remains 200.
- Added an offline Semgrep CWE-862 rule for the fixture. The full integration asserts that this finding is in the evidence-linked hypothesis and that the synthetic Authorization value is not present in proxy logs. The fixed proxy forwards only the Authorization header to its configured backend; rule selection remains trusted config, not model input.
- Generalized `send_get` for test-only request headers, added route-prefix suspicious-candidate classification, extended the fixed proxy rule format with bounded Authorization matchers, and exempted only `/healthz` from the fixture's synthetic-auth middleware for readiness checks.
- Verification: focused full second-scenario integration **1 passed** (23.90s initial; 13.61s with the extra evidence assertions); full unit suite **487 passed**; full Docker suite **23 passed, 1 credential-gated live-model test skipped** (152.39s); Ruff lint/format (**216 files**), strict mypy (**178 source files**), 18 schemas, and diff checks passed.
- This validates one deterministic scenario workflow; the generated patch is an oracle fixture, not model output. It does not establish generalized auth handling, production proxy behavior, or external benchmark performance. Header-forwarding/configuration limitations are documented in ADR-052/T24. No external credential, public target, or new egress path was introduced; the local image build may use the configured package index as documented.

## 2026-09-25 — configurable local-range response hooks

- Made `ProxyRuleAdapter` accept bounded, owner-configured fixed regex rules and a rule-set identifier. The model still cannot submit a regex or change adapter configuration; malformed, empty, and overlong rules are rejected. Existing default behavior remains the traversal-deny rule.
- Made `RangeEvidenceInvestigator` accept trusted route-to-source bindings and let `CaseDependencies` provide a scenario-specific incident summary instead of hard-coding traversal language.
- Added unit checks for custom object-route containment config and invalid config; updated the active task list, tools/sandbox docs, and fixture README.
- Verification: unit suite **485 passed**; full Docker integration **22 passed, 1 hosted-model test skipped** (137.94 seconds); Ruff lint/format, strict mypy (**177 source files**), **18 schemas**, and diff checks passed.
- Historical note: this initial hook-only slice did not wire object authorization through the complete case orchestrator. The following worklog entry records that now-passing deterministic integration. A generic response/deployment backend and model repair result remain open.

## 2026-09-25 — second-scenario clean-room repair profile

- Extended `scripts/bench_patch_repair.py` with an explicit `--scenario` allowlist for the path-traversal and object-authorization fixtures. Each request binds to that fixture's exact source digest and sends only its `app.py` plus a scenario-specific vulnerability summary; hidden tests are still only mounted into the verifier.
- Added an independent clean-room acceptance/rejection integration pair for object authorization. A locally constructed owner-check patch passes public, hidden exploit-replay, and regression groups; a comment-only patch that leaves cross-owner access fails verification and the assurance gate. No model was called.
- The first verification attempt surfaced that the gate requires public, exploit-replay, and regression test groups. Rather than weaken the gate, split the hidden fixture oracles into the expected test groups; the corrected integration now passes.
- Verification: focused second-scenario integration **2 passed**; unit suite **480 passed**; full Docker suite **22 passed, 1 credential-gated skip** (139.67s); CLI help lists both fixtures; Ruff, formatting (214 files), strict mypy (176 source files), 18 schemas, and diff checks passed.
- Scope: this verifies that the clean-room repair machinery can assess one second vulnerability class. It does not integrate incident investigation, brokered containment, or deployment for that class, and it is not a standard benchmark or live model-patch result.
- No new secrets or runtime network routes. The test builds the existing pinned verifier and fixture images through Docker; the fixture image downloads the pinned Flask package at build time, while the runtime container remains network-disabled.

## 2026-09-25 — second owned cyber-range fixture

- Added `ranges/object-authorization-v1`, a minimal authenticated synthetic document service with an intentional missing object-owner authorization check (CWE-862/CWE-639), owner-access public tests, and verifier-only cross-owner/identity cases.
- Added an optional Docker integration that builds the fixture and reproduces cross-owner document access solely with Flask's in-process test client inside a disposable container (`--network none`, read-only root, dropped capabilities, no-new-privileges, memory/CPU/PID limits). Focused result: **1 passed in 13.02s**; full unit suite **480 passed**; full Docker suite **21 passed, 1 credential-gated skip** (134.46s); Ruff, strict mypy (176 source files), 18 schema checks, formatting, and diff checks passed.
- The fixture is not wired to the Aegis evidence correlator, broker actions, patch provider, or clean-room verifier. It is a second owned scenario artifact, not a supported second end-to-end defense path or a benchmark score. The build installs pinned Flask from the configured package index; no network is available to the runtime container.
- Updated README, benchmark/active-task/progress/threat-model docs, and integration setup notes. No credentials or new runtime network routes were introduced; the existing Docker daemon remains rootful/trusted.

## 2026-09-25 — Broker-level prompt-injection control regression

- Added two adversarial regression tests: one submits an explicitly denied `host.shell` request carrying instruction-like poisoned evidence, and one feeds a provider proposal for `host.shell` through the case orchestrator. The broker denies it before adapter dispatch; the case halts and escalates before entering containment.
- Verification: focused command `uv run pytest -q tests/unit/broker/test_broker.py::test_injected_host_shell_proposal_is_denied_before_adapter_dispatch tests/unit/orchestrator/test_case_runner.py::test_prompt_injected_high_impact_proposal_is_blocked_by_broker` — **2 passed**. Full unit suite then passed **480 tests**; Ruff check/format, strict mypy (175 source files), schema parity (18 schemas), and `git diff --check` passed.
- Requirement satisfied: demonstrate that untrusted text/model proposals cannot grant authority to an explicitly denied action. This is not evidence of general model prompt-injection robustness; poisoned repository, telemetry, and tool-output suites are still needed.
- Files changed: `tests/unit/broker/test_broker.py`, `tests/unit/orchestrator/test_case_runner.py`, `docs/ACTIVE_TASKS.md`, `docs/THREAT_MODEL.md`, `docs/PROGRESS_REPORT.md`, `docs/WORKLOG.md`.
- No permissions, tools, network paths, or secrets were introduced. Threat-model effect is improved denial coverage only; current rootful-Docker and hosted-provider limitations are unchanged.

## 2026-09-25 — Vul4Py artifact provenance and safety preflight

- Located candidate `https://github.com/tabudz/vul4py` at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`. Its README describes 100 Python cases with vulnerable/fixed checkouts plus functional and exploit test sets, consistent with the paper's benchmark design.
- GitHub repository metadata reports no license (`license: null`; `/license` returns 404). The primary paper and author publication page do not link this repository, so provenance is not established by the inspected sources. The paper itself describes the benchmark and paired oracles: https://arxiv.org/abs/2608.00692.
- Static review (no execution) found metadata-driven install/test commands run via `shell=True`, dynamic repository clones, and micromamba bootstrap downloads. The candidate harness has no evident case sandbox. No source cases were cloned and no benchmark command was run.
- Current-environment decision: do not run the candidate harness under rootful-Docker-only isolation; do not copy/redistribute its code without terms. A separate Aegis runner may be designed after provenance/terms and a compliant isolation boundary are established. Updated benchmark matrix, OQ-008, source registry, progress report, and active task list.
- No credentials, permissions, tools, or network paths were added. This is a metadata/code-review preflight, not benchmark performance evidence.

## 2026-09-25 — local range service launch validation

- Tightened `ServiceSpec` validation before range service argv construction: simple Docker image-reference syntax, safe container/network identifiers, normalized absolute mount paths, read-only host mounts, valid environment keys/NUL-free values, and published-port bounds. Stop/log/inspect helpers reject unsafe container names before Docker invocation.
- Added parametrized invalid-configuration/helper cases; focused service tests pass **29/29**. Full unit suite: **478 passed**. Ruff check, 208-file format check, strict mypy (175 source files), 18 schemas, and `git diff --check` passed.
- This is defense-in-depth for the owned local range. It does not provide container isolation, verify image provenance, or expand supported targets. No new tools, permissions, secrets, or network paths were added.
- Final verification: `.venv/bin/pytest -q` **478 passed**; Ruff check passed; Ruff format check reports **208 files already formatted**; strict mypy passed for **175 source files**; all **18 schemas** current; `git diff --check` passed. Docker integration: **20 passed, 1 credential-gated hosted-model test skipped** in 128.86 seconds.
- The service-spec constraints did not require new Docker privileges or a new runtime. They validate the existing fixed range launch configuration only; rootful Docker, image provenance, and broader benchmark/product limitations remain unchanged.

## 2026-09-25 — production investigation and brokered telemetry

- Moved the fixed path-traversal investigation service out of test scaffolding into `src/aegis/investigation/range.py`. It validates fixture/source identity, requires registered scan and telemetry actions, broker-runs Semgrep, records provenance, and emits only evidence-linked hypotheses.
- Added `ProxyLogsAdapter` (`range.proxy.logs` / `telemetry.read`): fixed container and service target, zero model-supplied parameters, at most 200 log lines / 512 KiB, 10-second timeout, and typed timeout/failure results. Docker invocation now occurs only in this adapter; `RangeEvidenceInvestigator` consumes its result through `ActionBroker`.
- The first live integration attempt correctly failed closed because the policy risk classifier did not yet recognize the new `telemetry` namespace. Added deterministic R0 classification and test; the broker then permits only when the scope explicitly allows the action/adapter. The real Docker full-case now passes with both analysis and telemetry brokered.
- Verification: full unit suite **436 passed**; Ruff check/format; strict mypy (**171 source files**); 18 schemas current; focused Docker full-case **1 passed, 4 deselected (14.59 seconds)**; full Docker integration suite **20 passed, 1 credential-gated skip (139.31 seconds)**.
- No provider request, new credential, public target, or network path was introduced. Remaining boundaries include rootful Docker for trusted range adapters, in-memory evidence, and fixed path-traversal-only correlation.

## 2026-09-25 — schema contract CI and provider recheck

- Added a CI workflow with commit-pinned checkout/setup actions, read-only repository permission, no model credentials, a locked-dependency quality job, and an ephemeral-runner Docker integration job. Added an explicit contract assertion that action-transaction and capability schemas remain registered; updated README, task queue, docs index, and CI threat-model notes.
- Revalidated the locally runnable CI steps: `uv sync --locked --extra dev`; **431 unit tests passed**; Ruff check and format passed; strict mypy passed for 169 source files; 18 generated schemas were current; YAML parsing and `actionlint` passed; `git diff --check` passed. The full Docker integration suite (20 passed, 1 live-model skip) had passed immediately before this CI change. GitHub has not run the new workflow yet.
- Rechecked the configured provider using read-only `GET /v1/models`; it returned HTTP 401. No generation request or model switch was made. SWE-bench/Vul4J/AutoPatchBench/cyber-defense benchmark runs remain unperformed; rootful-only runtime, 52 GB free disk, absent adapters, and provider authentication remain documented constraints.

## 2026-09-25 — live case investigation and artifact-linked hypotheses

- Required a same-case, nonempty correlator report before the orchestrator can proceed to containment. Missing, failed, cross-case, or empty investigation results fail closed; reports include the hypothesis in JSON and human output.
- The real Docker full-case integration now broker-runs Semgrep, normalizes proxy telemetry from the owned range, records deployment provenance, and asserts a same-source hypothesis before continuing through containment and repair verification. Hypotheses carry case-scoped references to the scanner-result and deployment-provenance artifacts plus the telemetry artifact.
- Updated benchmark notes to identify the live-model runner as oracle-seeded: it uses real proxy telemetry but a known fixture finding, so it is not attack detection, localization, scanner-quality, or repair scoring.
- Verification: latest unit/static/schema/Docker results are tracked in `docs/ACTIVE_TASKS.md`. An initial concurrent check overlapped schema regeneration and reported one transient mismatch; schemas were regenerated before the clean rerun. Durable artifact storage, broad cross-tool correlation, causal validation, and standard external benchmark runs remain open.

## 2026-09-25 — source-version-bound evidence correlation

- Added typed route/source bindings, a versioned investigation-hypothesis record, and a correlation report. Hypotheses require a suspicious normalized event, same case, explicit path-to-file mapping, and equality of scan/deployment source digests. Cross-case records are rejected; provenance mismatch creates no hypothesis; unsafe paths are ignored with a warning.
- Correlation output links the raw event artifact digest, normalized finding digest, and deployment source digest. It is deliberately a hypothesis, never a causal conclusion; untrusted scanner message text is excluded from the generated summary.
- Fixed static-analysis path handling so worker-absolute `/src/...` findings normalize to safe source-relative paths; findings outside the read-only mount fail the scan result. Added unit tests for absolute/out-of-mount paths.
- Verification at the time of this entry: six focused correlation tests passed; 14 scanner/correlation unit tests passed; the real-Docker Semgrep fixture test asserted the known path-traversal finding is `app.py`. Live orchestration was added in the subsequent entry above; durable evidence retrieval remains open.
- Final checks for this slice: **427 unit tests passed**; Ruff check/format, mypy (**168 source files**), **18 schema files**, and diff checks passed. Targeted real-Docker Semgrep integration: **1 passed**. The full Docker suite was not rerun.

## 2026-09-25 — broker-fed advisory behavior monitor baseline

- Added a bounded process-local monitor that receives structured broker outcomes, action IDs, and deterministic risk tiers. It reports denial frequency, repeated denied action types, elevated-risk requests, and pending approvals as an advisory attached to `BrokerOutcome`.
- The monitor has no authority: it cannot issue/revoke capabilities or alter broker dispatch. A unit test preloads a `PAUSE_AND_ESCALATE` advisory and confirms a subsequently permitted action is still dispatched according to policy. Duplicate request IDs are idempotent; observations are isolated by case and actor.
- Added/exported the versioned assessment schema and documented the monitor's experimental status and threat-model limitations. Scores and thresholds are uncalibrated, do not estimate probability, and do not predict future behavior; no text or hidden-state monitoring is implemented.
- Verification: full unit suite **419 passed**; focused broker/monitor tests **19 passed**; final-code targeted real-Docker full-case/containment/rollback tests **3 passed**. Ruff check/format, mypy (**164 source files**), all **15 schemas**, and `git diff --check` passed. The complete Docker integration suite and external datasets were not run for this advisory-only change.
- Permissions, tools, network, and secrets: no new permissions, tool adapters, network paths, or credentials. The monitor stores bounded in-memory metadata only; no model rationale or telemetry text is ingested.

## 2026-09-02 — Research foundation

### Context received

- User requested an independent full defensive-agent research project.
- Required capabilities: identify attacks/vulnerabilities, defend/contain during compromise, and patch/verify/recover inside sandboxes.
- ASTRA-Kavach material was supplied only as reference, not as hackathon scope.
- User requested comprehensive documentation before heavy implementation and expects either Codex or another coding agent to execute the later build.
- GLM-5.2 or another major open-weight model is a likely reasoning backend, potentially accessed via hosted API or Colab.

### Research performed

- Reviewed primary incident reporting from OpenAI, Hugging Face, and METR/Redwood.
- Reconciled patching, threat-hunting, response, cyber-range, and agent-control benchmark families.
- Checked current GLM model/deployment information from official Z.ai/Hugging Face/vLLM material.
- Determined that full GLM-5.2 hosting is not a normal Colab-scale plan and that the architecture must be provider-neutral.

### Decisions recorded

- independent Aegis project identity;
- control-first architecture;
- explicit state machine before multi-agent swarm;
- typed action broker with no generic model shell;
- clean-room assurance gate;
- evidence-carrying patch terminology;
- narrow Python incident-to-patch MVP;
- capability and safety evaluated separately;
- progressive isolation beyond Docker for high-risk work.

### Artifacts produced

- root project overview and security policy;
- coding-agent instructions;
- charter and requirements;
- architecture, control plane, threat model, and workflows;
- evidence/assurance specification;
- model, tooling, sandbox, benchmark, and research strategies;
- incident lessons and reference-material synthesis;
- MVP roadmap and coding-agent handoff;
- decision log, open questions, source registry, and this worklog.

### Implementation state

No runtime code, model integration, security tool adapter, sandbox, benchmark result, or UI has been implemented. The next action is owner review followed by Change 1 in `IMPLEMENTATION_HANDOFF.md`.

## 2026-09-03 — Change 1: foundation and schemas

### Context received

- Instruction to implement `docs/IMPLEMENTATION_HANDOFF.md` Change 1 only: Python project configuration, the six named domain models, versioned JSON Schema export, validation/serialization tests, and formatting/lint/type/test tooling. Explicitly out of scope: live model APIs, Docker, scanners, raw command execution, target networking, databases, dashboards, multi-agent orchestration, and placeholder trees.

### Work performed

- Added `pyproject.toml` (Python 3.12+, Pydantic v2, pytest, Ruff, mypy) and `uv.lock`.
- Added `src/aegis/domain/`: `base.py` (shared frozen model, `Digest`, `Producer`, ID/URI/action-id value types), `case.py` (`Case`, `CaseStatus`), `scope.py` (`ScopePolicy` and its nested `Authorization`/`Targets`/`NetworkPolicy`/`FilesystemPolicy`/`ToolsPolicy`/`ActionsPolicy`/`Budgets`), `evidence.py` (`EvidenceEnvelope`, `Classification`), `action.py` (`ActionRequest`), `policy.py` (`PolicyDecision`, `PolicyOutcome`, `RiskTier`), `audit.py` (`AuditEvent`, `AuditEventType`), and `registry.py` (fail-closed `parse_record` dispatch by `schema_version`).
- Added `src/aegis/schema_export.py` and `scripts/export_schemas.py` (`--check` mode for CI drift detection); generated `schemas/aegis.*.v1.json`.
- Added `tests/unit/domain/` (80 tests): valid round-trips plus adversarial cases — malformed IDs, non-URI targets, out-of-range ports, ambiguous action disposition (an action in two policy buckets), raw-command-parameter smuggling attempts, a prompt-injection-style `reason` string (stored as inert data), a denied/approval-pending decision forced to carry a capability reference, naive (non-timezone-aware) timestamps, and unknown/missing schema versions.
- Recorded ADR-014 (mypy chosen over Pyright) and ADR-015 (Change 1 schema conventions) in `docs/DECISIONS.md`.
- Added a "Developer setup" section and updated the status table in root `README.md`.
- Added a status marker to the Change 1 section of `docs/IMPLEMENTATION_HANDOFF.md`.

### Decisions recorded

- mypy (strict, `pydantic.mypy` plugin) as the static type checker (ADR-014);
- frozen/immutable models, tuple-based collections, versioned `schema_version` literals with fail-closed registry dispatch, constrained URI/action-id types, and hash-chained audit events (ADR-015).

### Verification

- `ruff format --check .` — 48 files already formatted.
- `ruff check .` — all checks passed.
- `mypy` (strict) — no issues found in 25 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date.
- `pytest -q` — 80 passed.

### Implementation state

Change 1 is implemented and verified per the above. No policy evaluation, workflow engine, model provider, action broker, worker, or verifier code exists yet. The next action is Change 2 (`docs/IMPLEMENTATION_HANDOFF.md`): the pure policy decision function, state transition table, in-memory artifact/audit interfaces, and control tests — no LLM or network code.

## 2026-09-03 — Change 2: policy and workflow core

### Context received

- Instruction to continue implementing `docs/IMPLEMENTATION_HANDOFF.md` sequentially, change by change, with the same rigor as Change 1 (real tests, no overclaiming, docs updated per change), through as many changes as can be genuinely verified in-session; pause and surface rather than silently resolve anything that turns out to need an owner decision.
- Verified the local environment before planning later changes: Docker is present and reachable (`docker info` succeeds) but its Security Options report no rootless mode — this is standard rootful Docker, not the rootless backend ADR-012 requires for the MVP. `docs/OPEN_QUESTIONS.md` OQ-006 explicitly says "verify before build"; this is now verified as **not** satisfied. No action taken on this yet — flagged for the Change 5 checkpoint, not decided silently.

### Work performed

- Added `src/aegis/policy/`: `risk.py` (`classify_risk`, action-type-namespace → `RiskTier`), `targets.py` (`resolve_target`, `ActionRequest.target_ref` → scope resolution by URI scheme), `budget.py` (`BudgetUsage`, `exhausted_dimensions`), `decision.py` (the pure `evaluate_action_request` function).
- Added `src/aegis/workflow/`: `states.py` (`CaseState`, `Trigger` — a direct transcription of `docs/WORKFLOWS.md`'s closed-loop incident-to-patch state diagram), `transitions.py` (the explicit `TRANSITIONS` table and `apply_transition`, failing closed on any undefined or terminal-state transition).
- Added `src/aegis/evidence/`: `store.py` (`InMemoryArtifactStore`, content-addressed by sha256), `audit.py` (`InMemoryAuditSink`, hash-chain-verifying, append-only — no update/delete method exists on the type at all).
- Added `tests/unit/{policy,workflow,evidence}/` (90 new tests; 170 total across the project) and a shared `tests/unit/conftest.py` fixture module.
- **Found and fixed two real bugs while writing adversarial tests for `resolve_target`**, before any release: (1) plain `str.startswith` prefix matching let `workspace://AGE-0001/candidate/../../etc/passwd` pass, because the string still starts with the allowed prefix even though the path resolves outside it; (2) the same bare prefix check let `workspace://AGE-0001/candidate-evil/secret` pass because it shares a string prefix with the allowed `workspace://AGE-0001/candidate` without being beneath it. Both are now rejected (`_has_path_traversal`, `_matches_scope_prefix` in `src/aegis/policy/targets.py`) and covered by regression tests.
- Recorded ADR-016 (target resolution scheme) and ADR-017 (risk-tier classification table, including the unconditional R5 deny) in `docs/DECISIONS.md`.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 2 status marker) and `README.md` (status table).

### Decisions recorded

- ADR-016: scheme-based target resolution with `/`-boundary prefix matching and explicit traversal rejection;
- ADR-017: namespace-based risk-tier classification table, with R5 denied unconditionally regardless of scope configuration.

### Verification

- `ruff format --check .` — 70 files already formatted.
- `ruff check .` — all checks passed.
- `mypy` (strict) — no issues found in 47 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change).
- `pytest -q` — **170 passed** (90 new: risk classification, target resolution incl. the two adversarial cases above, budget exhaustion at and over the exact limit, the full pure-policy-decision matrix — permitted/approval-required/denied for every branch including case/scope mismatch, expired scope, unlisted/denied action types, disallowed adapters, unresolved targets, the R5 hard-block override test, unknown risk classification, exhausted budget, and a permitted path with no capability issued — every documented workflow-state transition, the full happy-path traversal to `Closed`, terminal-state rejection, undefined-transition rejection, in-memory artifact content-addressing and tamper/missing-digest handling, and audit hash-chain acceptance/rejection including a forged-predecessor-digest case).

### Implementation state

Change 2 is implemented and verified per the above. `evaluate_action_request` and the workflow state machine are pure, deterministic, and require no LLM, network, or Docker access. No action broker, provider, tool adapter, or worker exists yet — `evaluate_action_request` is not yet wired to anything that calls it end-to-end; that begins with the broker in Change 4. The next action is Change 3 (`docs/IMPLEMENTATION_HANDOFF.md`): the `ReasoningProvider` protocol, stub and replay providers, structured task/proposal schemas, and bounded structured-response repair — still no real network calls or API keys.

## 2026-09-03 — Change 3: provider boundary (stub/replay only)

### Context received

- Continuing the same sequential build-out; this change is `docs/IMPLEMENTATION_HANDOFF.md` Change 3.
- `docs/IMPLEMENTATION_HANDOFF.md` lists "optional hosted GLM provider behind environment configuration" as part of Change 3's scope. `docs/OPEN_QUESTIONS.md` OQ-004 ("Which hosted model provider/API account and spend cap?") remains unresolved, with a stated current default of "Stub/replay provider only." Per `AGENTS.md` ("do not silently choose high-impact answers" for open questions), no live provider was implemented — recorded as ADR-018.

### Work performed

- Added `src/aegis/providers/`: `schemas.py` (`TaskRole`, `ReasoningTask`, `EvidenceContext`, `ToolDescriptor`, `InferenceLimits`, `ProposalKind`, `ProposedAction`, `StructuredProposal`), `base.py` (the `ReasoningProvider` protocol, `@runtime_checkable`), `stub.py` (`StubProvider`), `replay.py` (`ReplayProvider`, `ReplayExhaustedError`), `parsing.py` (`parse_structured_proposal`, `parse_with_bounded_repair`, `ProposalParseError`).
- Added `tests/unit/providers/` (29 new tests; 199 total): schema validation (a `propose_action` proposal must carry an action, `refuse`/`escalate` must not), stub/replay provider behavior including protocol-conformance checks, and the parsing/repair module — valid parse, non-JSON and schema-invalid rejection (never inferring an action from free text, matching docs/MODEL_STRATEGY.md rule 3), raw-response preservation on failure, prompt-injection text landing inertly in `rationale` with no special interpretation, and the bounded-repair loop (not invoked on first success, succeeding after one correction, exhausting after the configured attempt count with every raw attempt preserved, and failing immediately with no `repair` function supplied).
- Recorded ADR-018 (no live hosted provider this change; provider choice stays with the owner via OQ-004) and ADR-019 (repair mechanism is a caller-injected callable, keeping the bounded-repair policy itself unit-testable with no model dependency) in `docs/DECISIONS.md`.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 3 status marker, noting the hosted-provider exclusion) and `README.md` (status table).

### Decisions recorded

- ADR-018: provider boundary implemented without a live hosted provider, pending OQ-004;
- ADR-019: bounded structured-response repair takes its corrective re-query as an injected callable.

### Verification

- `ruff format --check .` — 83 files already formatted.
- `ruff check .` — all checks passed.
- `mypy` (strict) — no issues found in 60 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change; provider schemas are not part of the Change-1 versioned-schema-export surface).
- `pytest -q` — **199 passed**.

### Implementation state

Change 3 is implemented and verified per the above, with one explicit, documented scope reduction: no live hosted or self-hosted model provider exists (ADR-018) — only `StubProvider` and `ReplayProvider`. Nothing in this change makes a network call or reads a real API key. The provider boundary is not yet wired to the policy engine or a broker; that begins in Change 4. The next action is Change 4 (`docs/IMPLEMENTATION_HANDOFF.md`): the typed tool broker (registry, descriptor validation, typed adapter protocol, local mock worker), with no generic shell adapter and no Docker yet.

## 2026-09-03 — Change 4: typed tool broker

### Context received

- Continuing the same sequential build-out; this change is `docs/IMPLEMENTATION_HANDOFF.md` Change 4. This is the first change that wires Changes 1 (schemas), 2 (policy engine), and audit/artifact interfaces together end-to-end into something that actually dispatches a "tool call," even though the tool is still a local in-process mock.

### Work performed

- Added `src/aegis/broker/`: `adapter.py` (`AdapterDescriptor`/`AdapterPermissions`/`AdapterLimits` — the full, broker-only execution descriptor distinct from the model-facing filtered `aegis.providers.schemas.ToolDescriptor`; `AdapterResult`; the `ToolAdapter` protocol; `validate_parameters`/`ParameterValidationError` for unknown-option rejection), `registry.py` (`AdapterRegistry`, `DuplicateAdapterError`, `UnknownAdapterError`), `mock.py` (`MockAdapter` — an in-process L0 mock worker per `docs/TOOLS_AND_SANDBOXES.md`'s isolation-maturity table; never shells out, never touches the filesystem or network), `broker.py` (`ActionBroker.submit`, the integration point: evaluates the Change-2 policy decision, dispatches to a registered adapter only when `PERMITTED`, and audits the request, decision, and result).
- Extended `AuditEventType` (`src/aegis/domain/audit.py`) with `TOOL_RUN_RECORDED` — additive per ADR-015's own design intent, no schema-version bump; regenerated `schemas/aegis.audit_event.v1.json` accordingly.
- Added `tests/unit/broker/` (19 new tests; 218 total): registry duplicate/unknown-id handling, mock-adapter parameter validation (including a shell-metacharacter-laden parameter value shown to pass through as inert string data, since nothing here ever shells out) and timeout simulation, and full broker integration tests — a permitted request running the adapter and recording exactly the three expected, correctly hash-chained audit events; a denied out-of-scope-path request (the acceptance-constraint case) exercised end-to-end through the broker rather than only the pure decision function; an approval-required request never dispatching; a scope-permitted-but-unregistered adapter raising `BrokerError` rather than silently denying or silently running; repeated action-budget exhaustion denying the request that would exceed the limit while leaving usage unchanged; a simulated timeout recorded as ordinary auditable data rather than raised as an exception; and an unrecognized parameter raising before any tool-run audit event exists.
- **Found and fixed one design flaw before release, caught while writing the audit-chain test**: the first draft of `_append_audit` used the stored result artifact's digest as the `tool_run_recorded` event's own `integrity` field, which would have overloaded that field's meaning (see ADR-020) and made hash-chain verification inconsistent between event types. Fixed to always compute `integrity` as a hash of the event's own content, with the result digest instead appended to the event's `summary` text.
- Recorded ADR-020 (integrity vs. result-digest separation), ADR-021 (network/secrets permissions fixed to `"none"` until a networked worker exists), and ADR-022 (broker-level control faults vs. ordinary policy denials) in `docs/DECISIONS.md`.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 4 status marker) and `README.md` (status table).

### Decisions recorded

- ADR-020: audit-event `integrity` is always a content hash of the event itself, never substituted with a referenced artifact's digest;
- ADR-021: `AdapterPermissions.network`/`.secrets` are `Literal["none"]` until a worker class with real network/secret access exists;
- ADR-022: unregistered-but-scope-permitted adapters and adapter-level parameter-validation failures are broker-level faults (`BrokerError`/`ParameterValidationError`), not policy denials.

### Verification

- `ruff format --check .` — 93 files already formatted.
- `ruff check .` — all checks passed.
- `mypy` (strict) — no issues found in 70 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (`aegis.audit_event.v1.json` regenerated for the new enum member).
- `pytest -q` — **218 passed**.

### Implementation state

Change 4 is implemented and verified per the above. The broker only ever dispatches to adapters explicitly registered with it in-process; there is no generic shell adapter and no Docker/subprocess execution anywhere in this change — `MockAdapter` is a pure in-memory stand-in (isolation level L0 per `docs/TOOLS_AND_SANDBOXES.md`). No real static-analysis tool (Semgrep/Bandit), container backend, or vulnerable fixture exists yet. Before Change 5 (the isolated analysis worker, which requires a real rootless-container backend), the local environment was checked: Docker is present and reachable, but reports no rootless security option — this is standard rootful Docker, which does not satisfy ADR-012's rootless-container requirement for the MVP. `docs/OPEN_QUESTIONS.md` OQ-006 says "verify before build"; that verification is now done, and it does not pass. This is a decision point for the project owner, not something to resolve silently — see the next-step note below.

**Owner decision (same session, 2026-09-03):** asked directly whether to proceed on rootful Docker as an interim measure, wait for rootless Docker, use process-level isolation instead, or stop. The owner chose to proceed on rootful Docker. Recorded as ADR-023, resolving OQ-006 for this phase, with the corresponding gap documented in `docs/THREAT_MODEL.md` (T03 and Residual risk).

## 2026-09-03 — Change 5: isolated analysis worker

### Context received

- `docs/IMPLEMENTATION_HANDOFF.md` Change 5, proceeding on the rootful-Docker interim basis just decided (ADR-023). Confirmed Docker and network access (PyPI, Docker Hub) were reachable in this environment before starting.

### Work performed

- Added the MVP scenario fixture `ranges/path-traversal-v1/`: a minimal Flask service (`app.py`) with a real, intentional CWE-22 path-traversal vulnerability in its `/download` endpoint (unsanitized `os.path.join` on a query parameter), pinned `requirements.txt` (Flask 3.1.3), a `Dockerfile` (pinned to `python@sha256:7838...` — captured via `docker inspect` after `docker pull python:3.12-slim`), and a `README.md` documenting the vulnerability, the expected fix, and authorized-use-only scope. This is the fixture `docs/MVP_AND_ROADMAP.md`'s MVP scenario and later changes (6-8) are expected to use.
- Added the pinned analysis-worker image (`docker/analysis-worker/Dockerfile`, built and pinned to its own content id `sha256:a995...`): pip-installs `semgrep==1.176.0` and `bandit==1.9.4` (latest stable at time of pinning, per PyPI), bakes in a project-authored offline Semgrep ruleset (`docker/analysis-worker/rules/python-security.yaml`, taint-mode, Flask-request-to-path-join), and runs as a non-root `analysis` user (uid 10001) inside the container.
- Added `src/aegis/workers/container.py`: `run_container` (a narrow `docker run` wrapper — argument-array only, `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, resource/time limits; a timeout is returned as data, not raised) and `resolve_read_only_source` (canonicalizes and prefix-checks a host source path before it is ever bind-mounted, rejecting `..`-traversal, symlink escapes, and shared-string-prefix siblings — the same class of bug fixed in Change 2's `resolve_target`, now fixed proactively here before release).
- Added `src/aegis/tools/`: `findings.py` (`NormalizedFinding`, `parse_semgrep_json`/`parse_bandit_json` — malformed or unexpectedly-shaped tool output always raises `FindingsParseError` rather than silently becoming "zero findings"), `static_analysis.py` (`ContainerStaticAnalysisAdapter`, `make_semgrep_adapter`, `make_bandit_adapter` — `ToolAdapter` implementations that run the pinned image with a read-only source mount, separately content-address the raw tool output via the artifact store, and only then normalize it).
- Added `tests/unit/workers/` and `tests/unit/tools/` (23 new tests; 241 total unit tests): pure, Docker-free tests using an injected fake container runner — argv construction (`--network none`, `:ro` mount, image/command ordering), timeout-as-data, `docker`-missing handling, the five source-path adversarial cases (outside root, `..`-traversal, symlink escape, shared-string-prefix sibling, and the valid cases), findings parsing (valid/malformed/wrong-shape for both tools), and adapter-level behavior (success, malformed-output-as-failure, timeout, unknown-parameter rejection, and out-of-root path rejection, each asserting the fake runner was never even called when validation fails first).
- Added `tests/integration/` (4 new tests, run separately — see below): real end-to-end verification against the actual pinned Docker image and the actual fixture. Changed `pyproject.toml`'s `testpaths` to `tests/unit` so these stay out of the default fast `pytest -q` run, and added a `pytest.ini_options.markers` entry plus `tests/integration/README.md` documenting how to run them.
- **Found and fixed two real issues during this change, both caught by writing genuine end-to-end tests against real Docker rather than only mocked unit tests:**
  1. `docker build`-time network dependency is fine (build-time, not run-time), but the first `--config auto`/registry-preset ruleset attempt could never work under `--network none` at scan time — this was expected and is why ADR-024 bakes a ruleset into the image instead.
  2. Even with a local ruleset file and `--metrics=off`, `semgrep --json` still hung until timeout under `--network none` — traced (by running the exact container command directly and bisecting flags) to an automatic post-scan version-check network call, fixed with `--disable-version-check`. See ADR-024.
- Recorded ADR-024 (pinned offline ruleset; the version-check hang and fix) in `docs/DECISIONS.md`.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 5 status) and `README.md` (status table, developer commands for the integration suite).

### Decisions recorded

- ADR-024: Semgrep ruleset is a pinned, offline, in-image artifact, not a registry fetch; `--disable-version-check` is required under a no-network policy.

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 83 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change).
- `pytest -q` (default, `tests/unit` only, no Docker required) — **241 passed**.
- `pytest tests/integration -q -m integration` (real Docker, run explicitly, ~8 seconds with a warm image cache) — **4 passed**: Semgrep finds the real path-traversal finding in the real fixture via the pinned offline ruleset; Bandit completes successfully against the same fixture; a container run with this backend genuinely cannot reach an external address (`--network none` verified, not just asserted); a container run genuinely cannot write into a `:ro`-mounted source directory.

### Known limitations carried forward

- Rootful Docker, not rootless (ADR-023) — accepted, scoped to this low-risk static-analysis use.
- No SBOM or image-signature verification yet (`docs/TOOLS_AND_SANDBOXES.md`'s "Supply-chain controls" beyond digest-pinning the base image and version-pinning the tools).
- Result correlation/deduplication across tools (FR-VUL-002) is not implemented — each tool's findings are normalized independently; cross-tool dedup is deferred.
- The vulnerable fixture service itself is not yet runnable as a network service under Aegis (that begins in Change 7's runtime range); Change 5 only scans its source.

### Implementation state

Change 5 is implemented and verified per the above, including genuine (not mocked) evidence against real Docker: a working pinned image, a real vulnerable fixture, real findings, and real network/read-only-mount denial. The next action is Change 6 (`docs/IMPLEMENTATION_HANDOFF.md`): patch candidate/diff validation, a disposable patch workspace, pytest/public replay adapters, a clean-room verifier with a separate identity from the patch worker, and the assurance gate.

## 2026-09-06 — Change 6: repair and clean-room verifier

### Context received

- Continuing the same sequential build-out; this is `docs/IMPLEMENTATION_HANDOFF.md` Change 6, the most architecturally significant change so far: it is the first to require a genuinely separate trust identity (the clean-room verifier) from the one preparing a candidate fix.
- User asked, mid-session, for the project's own already-documented benchmark/dataset list (`docs/BENCHMARKS_AND_DATASETS.md`) rather than a new one — confirmed it already covers the requested SWE/defensive-cyber benchmark ladder (Vul4J, AutoPatchBench, PatchEval, CVEfixes, PrimeVul, Splunk Attack Range, CALDERA, SecRespond, CyberGym-E2E, BashArena, SHADE-Arena, NIST agent-hijacking evals, etc.) and that running any external one is gated on the unresolved OQ-008, so none were pulled in.

### Work performed

- Restructured `ranges/path-traversal-v1/` into physical siblings: `src/` (the deployable source only — `app.py`, `files/`, a new `secret.txt` sentinel file simulating sensitive data outside the served directory), `public_tests/` (legitimate-behavior tests visible to whatever prepares a patch), `hidden_tests/` (exploit-replay tests across 5 differently-encoded traversal payloads reaching for the sentinel, plus regression tests — mounted only into the verifier). Updated the fixture's `Dockerfile` and `README.md` accordingly (ADR-025).
- Added `src/aegis/repair/`: `candidate.py` (`PatchCandidate`, `changed_files`, `validate_diff_policy` — independently callable on both sides of the loop), `hashing.py` (`hash_source_tree`, deterministic sorted-path content hashing), `workspace.py` (`create_patch_workspace` — copies only the base source, applies the diff via the system `patch` binary, argv only).
- Added `src/aegis/verifier/`: `models.py` (`CheckResult`, `CheckStatus`, `AssuranceOutcome` matching FR-ASR-003's four decisions, `AssuranceBundle`), `gate.py` (`evaluate_assurance`, the pure non-compensating-hard-failure decision function), `junit.py` (JUnit XML parsing), `checks.py` (`check_source_integrity`, `check_diff_policy`, `check_clean_room_tests`, `check_security_rescan` — reusing the Change-5 Semgrep adapter for before/after re-scans).
- Added `docker/verifier/` (`Dockerfile` + a fixed `entrypoint.sh`): a **separate pinned image and separate non-root identity** (`verifier`, uid 10003) from `docker/analysis-worker`'s `analysis` uid 10001 (ADR-009). The entrypoint reconstructs the candidate itself from a read-only-mounted trusted base source and diff file — it never trusts an already-patched tree from the patch-worker side (ADR-026) — then runs public+hidden pytest and emits JUnit XML.
- Added `tests/unit/repair/` and `tests/unit/verifier/` (49 new tests; 290 total unit tests, still Docker-free): diff-policy adversarial cases (unsafe paths, forbidden fragments, out-of-scope files), source-tree hashing determinism/sensitivity, real (non-Docker) `patch` application success/failure, the assurance gate's full outcome matrix (including that a hard failure always outranks a soft failure or error, and that an integrity failure always outranks an ordinary one), JUnit parsing, and every `checks.py` function via an injected fake container runner.
- Added `tests/integration/test_repair_verifier.py` (5 new integration tests; 9 total): the full pipeline — source-integrity check, diff-policy check, a real before/after Semgrep re-scan, the real clean-room verifier container, and the assurance gate — run against five real patch candidates: a genuine fix (expected `VERIFIED`), an exploit-preserving no-op change, a regression-inducing change that blocks all downloads, a test-gaming change that special-cases exactly one literal traversal string while leaving the general vulnerability (expected `REJECTED` for all three), and a candidate claiming a false base-source digest against an otherwise-correct diff (expected `CONTROL_FAILURE`).
- **Found and fixed two real bugs, both only surfaced by testing against the real `patch` binary and real Docker rather than stopping at mocked units:**
  1. `AegisModel`'s model-wide `str_strip_whitespace=True` silently stripped the required trailing newline off `PatchCandidate.diff`, which `patch` then rejected as malformed. Fixed by overriding `strip_whitespace=False` specifically on the `diff` field (ADR-027) — a pattern that will need repeating for any future byte-exact field.
  2. The verifier entrypoint's own `patch` and `python -c "import app"` diagnostic output was landing in the same stdout stream as the JUnit XML the Python side parses, breaking the XML parser outright once real assertions were made about its content (a manual smoke test that only eyeballed the output had missed this). Fixed by silencing both commands (`patch --quiet`, redirecting the import check's stdout).
- Recorded ADR-025 (physical source/test separation), ADR-026 (verifier reconstructs from trusted source + diff, never a pre-patched tree), ADR-027 (whitespace-stripping override for byte-exact fields), and ADR-028 (the assurance-gate outcome mapping) in `docs/DECISIONS.md`.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 6 status) and `README.md` (status table).
- Published an interim project dashboard (Artifact) and `docs/PROGRESS_REPORT.md`, covering Changes 1-5 at the time, per the user's request for a demo/status snapshot alongside continued implementation.

### Decisions recorded

- ADR-025: physical (not filter-based) separation of deployable source from public/hidden tests;
- ADR-026: the clean-room verifier reconstructs the patched tree itself and never trusts the patch worker's output;
- ADR-027: byte-exact string fields (diffs, raw tool output) must explicitly disable `AegisModel`'s default whitespace stripping;
- ADR-028: the assurance-gate outcome-mapping rules (integrity failure > ordinary hard failure > error/soft failure > all-pass).

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 101 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change).
- `pytest -q` (default, `tests/unit` only, no Docker required) — **290 passed**.
- `pytest tests/integration -q -m integration` (real Docker, ~55 seconds including two image builds) — **9 passed**: the 4 from Change 5 plus all 5 new repair/verifier scenarios reaching their expected outcome (`VERIFIED` / `REJECTED` ×3 / `CONTROL_FAILURE`).

### Known limitations carried forward

- Still no live model provider generating candidates — every `PatchCandidate` in this change's tests is hand-authored (standing in for what a future reasoning provider would produce); the schema and pipeline are provider-agnostic already.
- `check_security_rescan`'s "brand new finding" path is exercised by unit tests with canned findings but not by a real integration scenario that actually introduces a new Semgrep-detectable issue; only the "original finding persists/gone" paths are exercised end-to-end.
- No image-signature verification for either pinned image, same as Change 5.
- The verifier's disposable scratch directory lives inside the container's own writable layer (`$HOME/scratch`), not a separately mounted volume — sufficient for this fixture's size but worth revisiting if a larger repository is verified later.

### Implementation state

Change 6 is implemented and verified per the above, including genuine end-to-end evidence for every required scenario (good/exploit-preserving/regression/test-gaming/tampered-evidence). The next action is Change 7 (`docs/IMPLEMENTATION_HANDOFF.md`): the runtime attack range — deploying the vulnerable service itself, a benign-traffic generator, an attack controller, normalized telemetry, and a reversible containment adapter with rollback.

## 2026-09-06 — Change 7: runtime attack range

### Context received

- Continuing the same sequential build-out; this is `docs/IMPLEMENTATION_HANDOFF.md` Change 7 — the first change where the fixture runs as a live network service under attack replay rather than being scanned/patched as source only.
- `docs/OPEN_QUESTIONS.md` has an engineering question ("Which reversible containment primitive best fits the first range?") explicitly meant to be answered experimentally by building, not an owner decision — resolved as part of this change (ADR-029).
- User asked mid-session to see the project's own scores/results against its documented benchmark ladder; confirmed `docs/BENCHMARKS_AND_DATASETS.md` already lists the requested SWE/defensive-cyber benchmarks and reported this project's own current test results (all passing) as the relevant "Layer 0: deterministic fixtures" evidence, since external benchmarks (Layers 1-4) remain gated on the unresolved OQ-008.

### Work performed

- Added `docker/range-proxy/` (`proxy.py` + `Dockerfile`): a fixed, reviewed, stdlib-only (`http.server`/`urllib`) reverse proxy — a third pinned image with its own identity (`rangeproxy`, uid 10004, distinct from `analysis` uid 10001 and `verifier` uid 10003). It forwards to the backend app, enforces a `deny_query_patterns` rule read from a mounted file, and logs every handled request as one structured JSON line to stdout.
- Added `src/aegis/telemetry/`: `events.py` (`NormalizedEvent`, `EventClassification`, `classify_path`, `parse_proxy_log_line` — a malformed or incomplete raw log line always raises `TelemetryParseError` rather than silently becoming a plausible event; the traversal-pattern classification is named `inferred_classification`, an explicit heuristic per FR-DET-003, never a confirmed verdict).
- Added `src/aegis/range/`: `docker_cmd.py` (a shared typed command-runner abstraction), `network.py` (isolated per-range Docker networks), `service.py` (`ServiceSpec`/`start_service`/`stop_service`/`container_logs` for detached, long-running containers — distinct from Change 5's one-shot `run_container`), `traffic.py` (`send_get` — the single primitive both the "benign client" and "attack controller" are built from; what makes a request an attack is the caller's chosen path, not a different code path), `containment.py` (`ContainmentRule`, `write_rules`/`read_rules` — rollback is just re-applying the prior rule, not a separate code path that could drift from apply), `provenance.py` (`DeploymentProvenance`, reusing Change 6's `hash_source_tree` so a deployment's provenance and a patch candidate's claimed base are computed identically and directly comparable).
- Added `tests/unit/telemetry/` and `tests/unit/range/` (29 new tests; 319 total unit tests, still Docker-free): telemetry parsing (valid, malformed JSON, missing fields, invalid timestamp), classification heuristics, Docker-argv construction for network/service operations via an injected fake command runner, containment rule read/write round-trips (including malformed-file and wrong-shape fallbacks to "no containment," and a test that rollback has no separate code path from apply), deployment-provenance round-tripping, and `send_get` against a real local `http.server` (success, a real 404, and a real connection failure) — no Docker needed for any of it.
- Added `tests/integration/test_runtime_range.py` (6 new integration tests; 15 total): deploys the real app+proxy pair on an isolated network, confirms the exploit is genuinely reachable over the network pre-containment (not just via static analysis), confirms containment blocks it (`403`) while benign traffic keeps working (`200`), confirms rollback restores original reachability, confirms real proxy telemetry normalizes into correctly benign/suspicious-classified events, and confirms deployment provenance is independently reproducible from the pinned source tree.
- **Found and fixed one real bug, only surfaced by testing against real container startup timing, not a fake runner:** the first version of `send_get` only caught `HTTPError`, so a container that had started but was not yet accepting connections produced an uncaught `ConnectionResetError`/`URLError` that broke the integration tests' readiness-polling loop. Fixed by catching `OSError` broadly and returning `RequestOutcome(status_code=0, ...)` — a connection-level failure is now data a caller can retry on, matching `ContainerRunResult`'s existing "a completed call does not imply success" treatment of timeouts elsewhere in the codebase (ADR-030).
- Also fixed a Debian username collision found while building the proxy image: `useradd ... proxy` failed because `proxy` is already a reserved system account in the base image; renamed to `rangeproxy`.
- Recorded ADR-029 (proxy-rule containment primitive, resolving the engineering question) and ADR-030 (connection-level failures as `RequestOutcome` data) in `docs/DECISIONS.md`; updated `docs/OPEN_QUESTIONS.md` (the containment-primitive engineering question marked answered) and `docs/THREAT_MODEL.md` (T10's mitigation note and a residual-risk entry for the range's new network path).
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 7 status) and `README.md` (status table).

### Decisions recorded

- ADR-029: the reversible-containment primitive for the first range is a proxy rule (an engineering question answered by building, not an owner decision);
- ADR-030: connection-level request failures are `RequestOutcome` data (`status_code=0`), never an uncaught exception.

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 119 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change; telemetry/range models are not part of the Change-1 versioned-schema-export surface, matching the same choice made for provider/broker schemas in Changes 3-4).
- `pytest -q` (default, `tests/unit` only, no Docker required) — **319 passed**.
- `pytest tests/integration -q -m integration` (real Docker, ~77 seconds including three image builds) — **15 passed**: the 4 from Change 5, the 5 from Change 6, plus all 6 new runtime-range scenarios.

### Known limitations carried forward

- The range's network topology (one app + one proxy on one isolated network, one published port bound to `127.0.0.1`) is scoped to a single local, ephemeral, per-test-run range — not yet designed for multiple concurrent cases or a non-local deployment target.
- `classify_path`'s traversal-indicator heuristic is intentionally narrow (a fixed substring list); it is explicitly an inference (FR-DET-003), not a general-purpose intrusion-detection signature set.
- No incident-hypothesis or timeline construction (FR-INV-001/002) sits on top of the normalized telemetry yet — Change 7 produces correctly classified events, not yet an investigated case narrative.
- Containment is applied directly via `write_rules` in tests; it is not yet wired through the Change 2 policy engine and Change 4 action broker as an R3 `contain.*` action requiring a policy decision — that integration is Change 8's job.

### Implementation state

Change 7 is implemented and verified per the above, including genuine real-Docker evidence for pre-attack reachability, containment, availability preservation, and rollback. The next action is Change 8 (`docs/IMPLEMENTATION_HANDOFF.md`): wiring incident states to the repair/recovery states built in Changes 6-7, approvals and timeouts, hosted-GLM experiment configuration (still gated on the unresolved OQ-004), and a JSON/human case report.

## 2026-09-06 — Change 8: full orchestrated case

### Context received

- Continuing the same sequential build-out; this is `docs/IMPLEMENTATION_HANDOFF.md` Change 8, the final change in the original eight-change plan — wiring every prior change's real components (policy, workflow, providers, broker-adjacent adapters, repair, verifier, range) into one driven incident-to-recovery run.
- Mid-change, the project owner supplied a live API key for a third-party router (Agent Router, agentrouter.org) with explicit authorization to use it for hosted-model access ("use it as the AI provider for our testing... use it sparingly"), resolving the authorization half of `docs/OPEN_QUESTIONS.md` OQ-004. This was handled carefully: the key was stored only in a gitignored `.env.local` (mode 600), never echoed back, and never committed; a second key for the same service and then a key for a second service (kktoken.cc) were tried after the first failed, all with the same careful handling and removed once each was confirmed non-working.
- Both candidate services blocked direct API access before reaching their model backend: Agent Router returned a consistent `401 unauthorized_client_error` (gated to their supported CLI-tool integrations, not generic HTTP clients — confirmed by their own Codex integration docs); kktoken.cc accepted the key for `GET /v1/models` but returned a bare Cloudflare-level `403` for the actual completions endpoint regardless of model or payload. Neither was worked around by disguising requests as an approved client — that would circumvent a deliberate third-party anti-abuse control, not fix a bug on our side. Recorded as ADR-031. Per the owner's explicit follow-up instruction, the hosted-provider configuration is left empty for now; they will supply a working credential later.

### Work performed

- Added `src/aegis/policy/approval.py`: `Approval`, `ApprovalDecision`, `resolve_approval` — a pure function mapping an approval's state to the two workflow triggers every approval gate in `docs/WORKFLOWS.md` defines (`APPROVED`/`DENIED_OR_EXPIRED`), or `None` while genuinely still pending. An explicit denial, a timeout with no decision, and no approval request at all all fail closed to the same outcome; only an explicit approval (regardless of how long ago) resolves to `APPROVED` — expiry bounds how long a decision may be awaited, not how long a granted one remains valid.
- Added `src/aegis/providers/hosted.py`: `HostedOpenAICompatibleProvider`, `HostedProviderConfig` — a generic, provider-neutral `ReasoningProvider` implementation for any OpenAI-Chat-Completions-shaped endpoint, with the HTTP transport dependency-injected (fully unit-testable with no network call) and its raw response run through the same `parse_with_bounded_repair` every other provider's output goes through.
- Added `src/aegis/orchestrator/case_runner.py`: `CaseDependencies`, `CaseTrace`, `run_case` — the capstone integration point, driving the real Change 2 workflow state machine using real outcomes from injected Change 3/5/6/7-shaped callables, never inventing a transition the accepted state diagram does not define.
- Added `src/aegis/reporting/case_report.py`: `render_json_report`, `render_human_report` (FR-RPT-001).
- Added `tests/unit/policy/test_approval.py`, `tests/unit/providers/test_hosted.py`, `tests/unit/orchestrator/test_case_runner.py`, `tests/unit/reporting/test_case_report.py` (49 new tests; 350 total unit tests, still Docker-free): approval resolution's full outcome matrix, the hosted provider's request construction/auth header/model selection/malformed-response handling/bounded-repair recovery (via a fake transport) plus a dedicated prompt-injection-is-inert-data test, and the orchestrator's full happy path (asserting the *exact* sequence of 17 distinct states visited) alongside ten failure/escalation paths (provider refusal, containment approval denial, containment ineffective-then-effective on retry, containment budget exhaustion, containment breaking availability triggering rollback, repair rejected-then-verified on retry, repair exhaustion, an immediate non-retried escalation on `CONTROL_FAILURE`, deployment approval denial, recovery failure, and recurrence detection).
- Added `tests/integration/test_full_case.py` (1 new integration test; 16 total): one genuine end-to-end case run using real Docker infrastructure for every step except reasoning (`StubProvider`) — the real Change 7 range (app + proxy on an isolated network) for exploit detection, containment, and availability checks; the real Change 6 clean-room verifier (a distinct pinned image and identity) for candidate verification; a real image rebuild-and-redeploy for "deploying the verified candidate"; and real post-patch recovery verification (the exploit is now blocked by the patch itself, with containment rolled back first specifically so the check exercises the patch, not the proxy rule). The case reaches `CLOSED`.
- **Found and fixed one real bug in the orchestrator itself, caught by a test assertion, not by inspection:** four transitions (into `AWAIT_APPROVAL`, `CONTAIN`, `AWAIT_DEPLOY_APPROVAL`, `RECOVER`) changed the tracked state without ever recording it, because only some `apply_transition` call sites happened to be followed by a `trace.record(...)` call. Fixed by removing the possibility of the bug's existence rather than patching each missed call site: `CaseTrace.advance(trigger, note)` now applies a transition and records the result as one atomic operation, so no code path can move `state` without that change landing in the trace. See ADR-032.
- Recorded ADR-031 (OQ-004 interim status: authorized, no working credential) and ADR-032 (the orchestrator's three fixed, doc-grounded simplifications, and the state-recording bug/fix) in `docs/DECISIONS.md`; updated `docs/OPEN_QUESTIONS.md` OQ-004.
- Updated `docs/IMPLEMENTATION_HANDOFF.md` (Change 8 status) and `README.md` (status table) — all eight changes in the original plan are now implemented and verified.

### Decisions recorded

- ADR-031: OQ-004 authorization is settled; a working direct-API credential is not, and the hosted-provider config is deliberately left empty pending one;
- ADR-032: the orchestrator's fixed approval-gate/control-failure/undefined-transition rules, and the state-recording-atomicity fix.

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 132 source files.
- `python scripts/export_schemas.py --check` — 6 schemas up to date (unchanged by this change).
- `pytest -q` (default, `tests/unit` only, no Docker required) — **350 passed**.
- `pytest tests/integration -q -m integration` (real Docker, ~86 seconds) — **16 passed**: all prior 15 plus the new full-case capstone run, which reached `CLOSED` on its first real run against genuine infrastructure.

### Known limitations carried forward

- No working hosted-model credential (ADR-031) — every run in this repository, including the full-case capstone, uses `StubProvider`/`ReplayProvider`. "Verification: full stub/replay CI plus separately recorded real-model run" is satisfied for the stub/replay half only; no real-model run has been recorded, honestly, because none has succeeded.
- The orchestrator does not yet route containment/deployment actions through the Change 2 policy engine and Change 4 action broker as typed `ActionRequest`s — it calls the injected dependency callables directly. Wiring the orchestrator through the broker (so every containment/deployment step is itself audited via the Change 4 hash-chained trail, not just the case-level `CaseTrace`) is the natural next increment, not yet done here.
- `CaseDependencies` has no dedicated "deploy" step; `test_full_case.py` triggers the real image rebuild-and-redeploy as a side effect of the first `recovery_attack_blocked` call, guarded by a flag. A future change should add an explicit `deploy_candidate` callable rather than overload an existing one.
- The orchestrator's containment/repair retry loops are bounded (`max_containment_attempts`/`max_repair_attempts`) but the case-level token/tool-call/spend budgets from `docs/CONTROL_PLANE.md`/`aegis.policy.budget` are not yet consulted by the orchestrator itself.

### Implementation state

All eight changes in `docs/IMPLEMENTATION_HANDOFF.md`'s original build sequence are now implemented and verified, each with real passing tests (350 unit + 16 integration, all currently green) and no claim made without evidence behind it. The project's own recommended next steps, per `docs/MVP_AND_ROADMAP.md`'s "Twelve-week research build" and "Expansion roadmap," are: wiring the orchestrator through the action broker for full per-action audit coverage (noted above), a working hosted-model credential to exercise the real-model half of Change 8's verification bullet, and then Phase 2's external repair-benchmark integration (gated on the unresolved OQ-008) as the next genuinely new increment of scope.

## 2026-09-06 — Temporary local-Ollama live-model testing; orchestrator hardened against provider failure

Owner instruction for this session: finish the Change 8 plan but leave the hosted-provider configuration deliberately empty (credentials to be supplied later — see ADR-031); in the meantime, temporarily use a local Ollama model to genuinely exercise the full framework/harness with a real, non-stub model.

- Added `tests/integration/test_live_model_ollama.py`: the Change 8 capstone path (real Docker range, containment, repair verification, recovery) with the containment-proposal step answered by a real local Ollama model (`qwen2.5:7b`) through the existing `HostedOpenAICompatibleProvider`, unchanged — Ollama's OpenAI-Chat-Completions-compatible endpoint needs no new code, only configuration. Skipped automatically when Ollama or the model is not present locally; excluded from the default `pytest -q` run like every other `integration`-marked test.
- **Found and fixed one real bug in the orchestrator itself, caught by running against a genuinely live model, not by inspection:** the live model returned a `StructuredProposal` with `action.adapter = "network_policy_tool_adapter"`, failing the required dotted `namespace.verb` pattern; `parse_with_bounded_repair` exhausted its retry budget and `HostedOpenAICompatibleProvider.propose()` raised `HostedApiError`, which propagated uncaught out of `run_case` and crashed the case run — contradicting docs/WORKFLOWS.md's own "model unavailable... pause safely" failure semantics, which the code already honored for a provider that *responds but declines*, just not for one that raises. Fixed by adding `_propose_or_none` (`src/aegis/orchestrator/case_runner.py`), which wraps every provider call in a broad `try/except Exception` and turns any failure into a graceful halt with the reason recorded in the trace.
- Added `tests/unit/orchestrator/test_case_runner.py::test_raising_provider_halts_gracefully_instead_of_crashing` (351 total unit tests) — a fake provider whose `propose` always raises, confirming the halt-not-crash behavior without needing Ollama at all.
- Relaxed `test_live_model_ollama.py`'s assertions to accept either outcome as evidence the wiring works end to end: `CLOSED` (the live model produced a usable proposal) or a graceful halt at `CONTAIN_PROPOSAL` (a provider failure correctly contained) — never an uncaught exception. A live model's output is not perfectly deterministic even with the rest of the pipeline held fixed, so a strict "must always reach CLOSED" assertion would be testing today's specific model response, not the property that actually matters here.
- Recorded ADR-033 (provider failures halt, never crash, the orchestrator) and ADR-034 (the local-Ollama testing approach itself, and why it does not resolve OQ-004) in `docs/DECISIONS.md`.

### Decisions recorded

- ADR-033: any `ReasoningProvider` failure (exception, not just a well-formed refusal) halts the case gracefully instead of crashing `run_case`;
- ADR-034: local Ollama is temporary live-model verification only, not a hosted-provider decision — OQ-004 stays open.

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 133 source files.
- `pytest -q` (default, `tests/unit` only, no Docker/model required) — **351 passed**.
- `pytest tests/integration/test_live_model_ollama.py -q -m integration -v -s` (real Docker + real local Ollama `qwen2.5:7b`) — **1 passed**: the live model's real (schema-invalid) response is printed in the case report, and the orchestrator halts cleanly at `contain_proposal` with the exact validation error recorded, rather than crashing.

### Known limitations carried forward

- The local-Ollama test demonstrates the provider boundary and orchestrator wiring work with genuinely live model output; it is not a substitute for OQ-004's still-open production hosted-provider decision, and does not by itself demonstrate a model capable of reliably producing valid containment proposals — only that the harness behaves correctly whether or not it does.
- All limitations already listed under Change 8 above remain unchanged by this work.

## 2026-09-06 — Root cause behind the schema failure, model selection, and a small live-model benchmark

Follow-up in the same session: the graceful-halt fix (ADR-033) above was necessary but was masking a more basic problem, found by testing three different local models against the same prompt and watching all three fail the same way.

- **Found and fixed the actual root cause, not just its symptom:** `run_case`'s containment-proposal call always passed an empty `tools` tuple to `provider.propose()`, and the hosted provider's system prompt only said `"adapter": "<tool id>"` with no real id ever supplied. Three different local models (`qwen2.5:7b`, `llama3.1:8b`, `gpt-oss:20b`) each invented a different, equally-plausible, equally-invalid adapter name (`network_policy_tool`, `firewall`, `manual`) — confirming this was a missing-information problem, not a model-quality problem. Fixed by adding `CaseDependencies.containment_tools: tuple[ToolDescriptor, ...]`, threading it through `_propose`/`_propose_or_none` into the real `propose()` call, and tightening `HostedOpenAICompatibleProvider`'s system prompt to require `adapter` be copied verbatim from `available_tools[].id`. See ADR-035.
- Updated `tests/integration/test_live_model_ollama.py` to supply the real `range.proxy` `ToolDescriptor` (the one containment primitive this range has, per ADR-029); it now reaches `CLOSED` reliably instead of only exercising the graceful-halt path.
- Added `scripts/bench_live_model.py`: a repeatable, non-pytest benchmark script that runs N full Change 8 case trials against a chosen local model and the one Layer 0 fixture this project has (`ranges/path-traversal-v1`), reporting the CLOSED rate and average wall time per case. Deliberately scoped and documented as narrow — Layers 1-4 of `docs/BENCHMARKS_AND_DATASETS.md`'s evaluation ladder are not wired into this codebase (OQ-008 open), so this is the only benchmark that can honestly be run right now.
- **Model selection, with evidence:** screened `qwen2.5:7b`, `llama3.1:8b`, and `gpt-oss:20b` (all already present locally) against this machine's hardware (RTX 4060 Laptop, 8 GB VRAM; ~6 GB RAM headroom). `gpt-oss:20b` (13 GB on disk) took 60-87s per single containment-planning call — unusable for iterative testing on this hardware, and excluded. `glm-4.7-flash` (19 GB) and `gemma4:26b` (17 GB) were not tried at all: neither fits in 8 GB VRAM and both would force heavy CPU/RAM offload with only ~6 GB free, risking destabilizing the rest of the machine, so this was a deliberate choice not to try, not a failed attempt. Ran `scripts/bench_live_model.py --trials 5` for both remaining candidates: **`llama3.1:8b`: 5/5 CLOSED, 3.5s/case average; `qwen2.5:7b`: 5/5 CLOSED, 8.6s/case average.** `llama3.1:8b` was selected as the default for this hardware on the basis of that measured latency, both being equally reliable.

### Decisions recorded

- ADR-035: the containment-planning call must supply the model real, available tool ids (not an empty tools tuple) — the actual root cause behind every schema failure seen across three different models, and the model-selection evidence (`llama3.1:8b` vs `qwen2.5:7b` vs `gpt-oss:20b`) that followed once it was fixed.

### Verification

- `ruff format --check .` / `ruff check .` — clean.
- `mypy` (strict) — no issues found in 134 source files.
- `pytest -q` (default, `tests/unit` only) — **351 passed** (unchanged; `containment_tools` defaults to `()`, so no existing test needed updating).
- `pytest tests/integration -q -m integration` (real Docker + real local Ollama) — **17 passed**, including `test_live_model_ollama.py` now reaching `CLOSED`.
- `scripts/bench_live_model.py --model llama3.1:8b --trials 5` and `--model qwen2.5:7b --trials 5` — both 5/5 `CLOSED`, latencies as above; raw JSON kept only in the local scratchpad, not committed (rerunnable on demand, not a static claim to preserve).

### Known limitations carried forward

- This benchmark exercises exactly one Layer 0 fixture and only the containment-proposal step's model call; it says nothing about repair-candidate generation quality, detection recall, or performance against any external benchmark corpus (Layers 1-4 remain unwired, OQ-008 open).
- `llama3.1:8b` was chosen for latency on one specific machine's hardware, not for output quality — both candidate models were equally reliable (5/5) in this small sample. A larger trial count or a different task (e.g. actual repair-candidate generation, once that path also calls a live model) could favor a different model.
# 2026-09-25 — hosted qwen38 trial and transactional runtime foundation

The owner clarified that this is an independent flagship project, not a hackathon submission, and set the broader direction: evolve from a cyber-defense application into a reusable trustworthy execution runtime while retaining cyber defense as the first reference app. The architecture decision is recorded as ADR-036; the name remains provisional and unchanged.

## Model/API

- Read the provided `docs/AGENT_LLAMA_CPP_API_GUIDE.md`; followed its OpenAI-compatible chat-completions contract and `reasoning_effort: none` guidance.
- Used only the supplied `qwen38` alias on the warm A100 server; no model switching.
- Added `scripts/smoke_model_api.py` for a one-request, typed, synthetic-range containment-planning test. It makes no tool call and checks the returned adapter against the supplied allowlist.
- The smoke proposal passed schema validation and selected `range.proxy`.
- Added an environment-gated live hosted-model Docker integration test. One run reached the case's `CLOSED` state. This model answered the containment-planning step only; the patch candidate remains fixture-provided.
- `HostedOpenAICompatibleProvider` now respects per-request token/time limits and optional `reasoning_effort`; `scripts/bench_live_model.py` can target the hosted provider for an explicitly requested run.
- Both live scripts reject non-local plaintext HTTP endpoints before sending an API key.
- Only synthetic fixture context was sent. The API key was not persisted in tracked files; because it was pasted into chat, rotation is recommended after this work.

## Runtime foundation

- Added `aegis.core.transaction.ActionTransaction` with immutable history and explicit transition invariants; the broker records policy, authorization, capability, execution, and terminal adapter-result states.
- Added a process-local capability authority and bound capability model. It verifies expiration/revocation/use count and case, transaction, subject, action, adapter, target, and canonical parameter digest before adapter dispatch.
- Added `ExecutionReceipt` v1 with canonical content digest creation/verification, plus schema export for transaction/capability/receipt records.
- Added a receipt factory from terminal transaction snapshots with state/disposition consistency checks; the factory cannot call an executed action committed.
- Added `verify_audit_chain` for content-digest and predecessor-link verification; broker event generation now uses the shared digest function.
- `ActionBroker` results stop at `EXECUTED` or `FAILED`; independent verification/commit/rollback coordination is intentionally not faked.

## Verification

- `.venv/bin/python -m pytest -q`: **369 passed**.
- `.venv/bin/python -m ruff check src tests scripts`: passed.
- `.venv/bin/python -m mypy`: passed, 143 source files.
- `.venv/bin/python scripts/export_schemas.py --check`: passed, 9 schemas current.
- Live API smoke and one live hosted reasoning integration run: passed.
- Full Docker integration suite: **17 passed, 1 skipped** because the live-hosted test was not given credentials in the full-suite process. The same qwen38 integration test was separately run with environment-only credentials and passed once.
- Final: `.venv/bin/python -m pytest -q` **370 passed**; Ruff format check passed (144 files), Ruff lint passed, strict mypy passed (143 source files), schema check passed (9 schemas), and `git diff --check` passed.

## Next engineering priority

The most important gap remains the effect path: containment and deployment mutations in the existing case orchestrator still use injected callables instead of broker actions. Next implement typed deployment/containment/rollback actions plus a transaction coordinator that requires independent postcondition checks before commit and verifies rollback on failure. See `docs/ACTIVE_TASKS.md` for the ordered queue and explicit guardrails.

---

# 2026-09-25 — scoped model patch provider and benchmark preflight

- Added a typed hosted patch provider and strict JSON output contract. It receives a single allowlisted source file and synthetic vulnerability summary; model-produced diffs are checked locally for exact path scope and converted into content-hashed candidates.
- Added a Layer-0 repair pilot runner. It runs source-integrity and diff-policy checks plus public tests, hidden exploit replay, and regressions in the existing independent network-disabled Docker verifier. The model has no test input or execution authority.
- Unit tests for the new provider: **5 passed**; targeted Ruff and mypy passed.
- Attempted one qwen38 repair call against the configured endpoint. The service returned **HTTP 401** before candidate generation. The result is captured at `artifacts/benchmark_runs/qwen38-path-traversal-pilot-attempt-2026-09-25.json`; this supplies no model-quality score. The request was not retried and no alternate model was loaded.
- External benchmark preflight found ~52 GB free. SWE-bench's official local Docker guide recommends at least 120 GB; Meta AutoPatchBench recommends ~500 GB for sample-20. Vul4J is plausible but requires legacy JDKs and Java setup absent from this Python-only project. No external corpus was downloaded or evaluated.
- Updated README, benchmark/data status, model strategy, open questions, decision log, active tasks, and progress report to reflect what actually happened.
- No new permissions, tools, network paths, or secrets were introduced. The existing synthetic-source HTTPS API route was used once; no credential or endpoint is recorded in the result artifact.

## 2026-09-25 — transaction replay hardening and benchmark reality check

- Continued the runtime work by making transaction-id reservation and transaction lifecycle advances atomic within the process. Duplicate IDs, stale snapshots, and concurrent attempts to advance the same transaction fail before a second action dispatch.
- Changed rollback approval to be explicitly auditable as `AWAITING_APPROVAL` and resumed only against that broker-issued transaction.
- Added the paired real-range acceptance test. A permitted rule is independently checked for attack blocking and benign availability before commit. A deliberately overbroad, test-only adapter causes availability failure; the coordinator invokes typed broker rollback and verifies the original range behavior is restored.
- Verification: 384 unit tests passed; full integration suite 19 passed / 1 skipped in 84.13s; Ruff format 182 files, Ruff lint, strict mypy (149 source files), 11 exported schemas, and `git diff --check` all passed.
- Benchmark action: reviewed official benchmark setup requirements and checked local capacity. At ~52 GB free, SWE-bench (official guide: >=120 GB) and AutoPatchBench sample-20 (~500 GB recommended) were not launched; only Java 26 is installed, so the Vul4J Java 7/8/11/16 matrix is not available. No external dataset was downloaded or scored. Existing internal fixture coverage does not establish general coding or cyber-defense performance.
- qwen38 remains the sole configured model alias. The previous hosted repair pilot returned HTTP 401 before inference; not retried or bypassed. No model switch, new credential, permission, tool, or network path was introduced.
- Updated README, active queue, decision log, progress report, and this worklog. Legacy orchestration still bypasses the broker for some mutations; this remains a priority and is not claimed complete.

## 2026-09-25 — containment migration verification correction

- Removed legacy direct containment approval/apply/rollback callbacks from the orchestrator. The reference case now submits a fixed typed containment action and rollback through `ActionTransactionCoordinator` and `ActionBroker`; the model cannot choose operation parameters. Independent probes gate commit and verify rollback.
- The first full integration rerun found that live Ollama had proposed an action rejected by scope policy. This is the correct fail-closed behavior; the test expectation was stale. Updated the live integration to accept explicit escalation and improved the case trace to include the broker's exact policy denial reason. Updated a report assertion accordingly.
- Final verification after that correction: `pytest -q` **384 passed**; `.venv/bin/pytest tests/integration -q -m integration` **19 passed, 1 skipped** in 82.47s; focused live Ollama test **1 passed**; Ruff format **183 files clean**, Ruff lint clean, strict mypy **150 source files clean**, schema export check **11 schemas current**, and `git diff --check` clean.
- Requirement satisfied: containment effects in the case runner use the brokered action path and out-of-scope proposals remain denied with actionable evidence. Files changed for this correction: orchestrator, live-model integration, report test, Active Tasks, Progress Report, and Worklog. No new permissions, tools, network routes, or secrets; the only live model integration used the already configured local Ollama fixture, not the hosted endpoint. Threat-model impact: denial observability improved; deployment/build/recovery broker migration, rootful Docker, and in-memory authority/audit remain open limitations.
- External benchmark status is unchanged: none of SWE-bench, Vul4J, AutoPatchBench, Cyber Defense Benchmark, or a public dataset was executed. The hosted qwen38 repair pilot previously returned HTTP 401 before candidate generation; it was not retried. Current local fixture/integration tests are not external benchmark scores.

## 2026-09-25 — deployment-path audit

- Re-inspected the current orchestrator and real Docker integration after the containment migration. Confirmed deployment has a deeper bypass than the boolean approval name suggests: `CaseDependencies.approve_deployment` only returns a boolean, and `tests/integration/test_full_case.py`'s `recovery_attack_blocked` callback performs the candidate image build, replaces the running app container, and resets the proxy rule on its first invocation.
- Recorded this precise path in `docs/ACTIVE_TASKS.md`. Do not mark deployment as brokered until build/rollout/rollback are separate typed actions (or a clearly bounded compound action), attributed approval is checked by policy, and independent postcondition checks decide commit versus verified rollback.
- No runtime code changed in this audit. No new permissions, tools, secrets, or network routes. Existing verified test results remain as documented above. Threat-model implication: the end-to-end deployment currently has an authority/observability gap despite the passing test; existing test success does not prove policy mediation for that mutation.

## 2026-09-25 — brokered local-range deployment and verified rollback

- Removed the deployment approval callback and the Docker build/container replacement that had been hidden inside the first recovery attack probe. Added fixed typed `deployment.rollout` and `deployment.rollback` actions through `BrokeredDefenderActions`, `ActionTransactionCoordinator`, `ActionBroker`, and a range-bound `RangeDeploymentAdapter`.
- The adapter accepts the candidate diff plus content digests, checks the trusted source and allowed changed files, constructs a temporary build context without public/hidden tests, builds with Docker network disabled, replaces only its configured local service, waits for health, and remembers the prior image/containment rule for rollback. The model receives no Docker socket, container naming controls, or raw command path.
- Real Docker acceptance: the verified candidate commits after attack replay is blocked and benign traffic remains available. An exploit-preserving comment-only diff fails the independent postcondition, does not commit, rolls back via the broker, and the test verifies the original contained service. The focused rollback test passed.
- Verification: unit suite **388 passed**; complete integration rerun **20 passed, 1 credential-gated hosted-model case skipped** in 86.56s; Ruff lint/format, strict mypy (**152 source files**), schema export (**11 current**), and `git diff --check` passed. An earlier integration run had one readiness timeout; its isolated test and the clean complete rerun passed.
- Documentation updated: README status, architecture, tool/sandbox design, threat model, active task list, progress report, worklog, and ADR-043.
- Permissions/tools/network/secrets: no new credentials or external network routes. The adapter newly declares `docker_control="authorized-range"` and uses the existing local Docker daemon solely for the explicitly configured synthetic range; builds use `--network=none`. No hosted model call was made in this milestone.
- Threat-model impact/limits: closes the direct deployment/build/rollback bypass for this reference range and makes commit depend on independent probes. Docker remains rootful; build resource limits are not a hardened isolation guarantee; adapter state and receipts are process-local; this is not safe or suitable for arbitrary or production deployment. General runtime effect coverage remains unaudited.

## 2026-09-25 — core sandbox contract for the analysis worker

- Added versioned/schema-exported `SandboxExecutionRequest`, `SandboxExecutionResult`, and the `SandboxBackend` protocol to `aegis.core`; moved the one-shot analysis worker's Docker execution into `DockerSandboxBackend` and kept `ContainerRunSpec`/`ContainerRunResult` as compatibility aliases. `run_container` now accepts an alternate backend by dependency injection.
- Added tests that enforce the core package's non-import dependency boundary, validate network-deny/positive budget fields, confirm timeout is represented as unsuccessful result data, and prove backend delegation.
- Verification: default unit suite **392 passed**; focused backend/core/schema tests **16 passed**; Ruff check and format, strict mypy (**155 source files**), all 13 schemas, and `git diff --check` passed. Four real-Docker analysis-worker integration tests passed after this refactor; the immediately preceding clean full integration run (before it) was 20 passed and 1 credential-gated skip.
- New permissions/tools/network/secrets: none. The default implementation continues to use the existing rootful Docker daemon with no network, read-only mounts, dropped capabilities, CPU/memory limits, and timeout. No new backend or isolation claim.
- Remaining scope: Docker range deployment/service/network helpers do not yet implement this backend protocol; no production-grade isolation backend is available. This is dependency inversion only and leaves T03 residual risk unchanged.

## 2026-09-25 — explicit verifier protocol

- Replaced the coordinator's bare callable alias with a runtime-checkable `Verifier` protocol that receives the action transaction, typed adapter result, and control-supplied check timestamp, returning structured evidence-bearing `VerificationOutcome` records. Existing two-argument verifier functions remain supported during migration.
- Added an object-verifier integration unit test through the real broker/coordinator and kept existing callable-based commit, exception, and rollback coverage. Verifier actor identity remains forbidden from matching the action actor; failures remain fail-closed.
- Final verification: **393 unit tests passed; 20 Docker integrations passed and one credential-gated hosted-model test was skipped** in 92.72s; strict mypy (155 source files), Ruff and formatting passed.
- Threat-model impact: API clarity/attribution improved, but verifier code can still run in-process and the protocol is not a process-security boundary. The clean-room patch verifier remains the stronger isolated path.

## 2026-09-25 — Python repair and repository-hunting benchmark refresh

- Rechecked primary benchmark sources in light of the request for standard external scores. Vul4Py's August 2026 paper describes a Python benchmark of 100 real vulnerabilities with paired exploit and functional oracles; it is a closer language/oracle fit than the Java-first Vul4J, but this review did not find/verify a runnable official artifact, license terms, or execution harness. It is not ready to run or cite as an Aegis result.
- Reviewed VulnGym v0.1.4's official README and schema. It publishes 408 repository-level entries, 393 marked human-audited, with a CC-BY-4.0 dataset license and an official prediction evaluator. Its metrics are recall/coverage only and cannot penalize over-reporting; using it will require repo checkout at pinned commits and a project-level investigation/prediction adapter, which Aegis does not yet provide.
- Refreshed the benchmark matrix, source registry, unresolved benchmark-selection question, and active queue. The real provider endpoint continues to return HTTP 401 from prior attempts; no model request, alias switch, benchmark dataset download, or external evaluator run was made in this research update.
- New permissions, tools, secrets, or network paths: none. Read-only web research used primary paper/repository sources. Threat-model effect: none. Remaining blockers to meaningful external model scores are endpoint authorization, a verified dataset artifact, supported agent adapters, and an isolation plan for untrusted project code.

## 2026-09-25 — close default range egress and remove published test port

- Found a mismatch between the range's “isolated network” description and `create_network`: it created a normal Docker bridge with default external routing. Docker's primary reference documents `--internal` as restricting external access and also notes host/gateway connectivity caveats.
- Changed network creation to request `--internal`, validate fixed network identifiers, and inspect the effective flag on every creation—including “already exists”—so a stale non-internal network cannot silently pass. Added a typed fixed-container-IP lookup with identifier/IP validation. Neither app nor proxy receives a published port; local tests and the optional benchmark harness contact the proxy's IP on the internal network.
- The first live integration with `--internal` plus the old published-port approach failed readiness in all five cases. A disposable local probe confirmed host-to-proxy container-IP access works; cleanup explicitly removed its two uniquely named containers and network. After switching the harness, the full integration suite passed **20 runnable tests with 1 hosted-model test skipped** (137.99s); a final focused range rerun, including explicit no-port assertions, passed **6/6** (15.74s). The full unit suite passed **449 tests**; strict mypy (171 source files), 18 schemas, `ruff check`, `ruff format --check` (204 files), and `git diff --check` passed.
- Documentation updated: ADR-051, T04 threat table/residuals, sandbox network constraints, active tasks, benchmark scripts/status, progress report, and this worklog. New permission/tool/secret/API route: none. This removes container egress via ordinary external networks and avoids host-published ports; it does not isolate against the Docker host or prevent access to host/gateway services. Rootful Docker remains trusted; this is not suitable for arbitrary or production targets.

## 2026-09-25 — qwen38 repair-pilot recheck and benchmark preflight refresh

- Per the owner's request to finish evaluation, made one controlled retry of the Layer-0 repair pilot using only the synthetic path-traversal `app.py` source. The configured qwen38 endpoint returned HTTP 401 in 0.146 seconds before generation. Recorded `artifacts/benchmark_runs/qwen38-path-traversal-pilot-recheck-2026-09-25.json`; no candidate was produced, no verifier ran, and no model-quality score exists. No additional request or model switch is planned until endpoint authorization is repaired.
- Refreshed benchmark documentation with the second failure, current 393/20 local test counts, and primary upstream setup/source references. No external benchmark dataset or results were downloaded/run. The local filesystem still has ~52 GB free versus published SWE-bench and AutoPatchBench requirements; Vul4J's JDK matrix remains absent.
- New permissions/tools/secrets/network routes: none. Only previously authorized HTTPS provider route was used once; the prompt included the owned synthetic fixture source and summary only. Threat impact is limited to synthetic data disclosure to the already-configured provider; access failure prevented data from being processed for a patch response.

## 2026-09-25 — Portable audit-stream verification

- Added deterministic compact JSONL export for a verified single-case audit chain, strict parsing/chain validation, and `scripts/verify_audit_stream.py` for offline verification of an exported stream. Export refuses empty or invalid chains.
- Added tamper, reorder, malformed/empty/mixed-case, stable round-trip, and CLI success/failure tests. Updated ADR-046, architecture, active tasks, progress report, and T07 threat-model residuals.
- Verification after this slice: **399 unit tests passed**; Ruff formatting/check passed; strict mypy passed for 158 source files; all 13 JSON schemas are current; `git diff --check` passed. One initial schema command omitted `PYTHONPATH=src` and failed to import the package; rerunning with the repository's required environment passed. No permissions, tools, network routes, or secrets were added. Security impact: audit records are easier to transport and consistency-check; this does not create durability, authenticity, immutability, or completeness guarantees.

## 2026-09-25 — Versioned action contracts enforced by the broker

- Added `aegis.action_definition/v1` models and schema export for typed input/output fields, risk, declared effects and permissions, reversibility/rollback linkage, resources, expected verifier, and idempotency/retry metadata. Adapter registration now requires contracts and rejects duplicate action IDs, mismatched permission metadata, and resource metadata that disagrees with the adapter's declared limits. This is consistency validation, not independent runtime CPU/memory enforcement.
- Bound static-analysis and synthetic range adapters to their contracts. The broker validates action/adapter binding, required/unknown input fields, primitive types, and policy-risk agreement before capability issuance. Successful output fields/types are validated; a mismatch is audited as `CONTROL_FAILURE` rather than ordinary success.
- Added tests for malformed types/fields/outputs, forbidden raw-command contract fields, retry/idempotency mismatch, rollback consistency, and verifier metadata. Exported the v1 JSON Schema.
- Verification: **409 unit tests passed; 20 Docker integrations passed and one credential-gated hosted-model test skipped** in 95.64 seconds; Ruff format/check passed; strict mypy passed for 160 source files; all 14 schemas are current; `git diff --check` passed.
- Permissions/tools/network/secrets: none added; registered network and secrets remain denied. No model-to-shell path was added. The typed catalog narrows malformed dispatch/output behavior and adds a fail-closed transition.
- Follow-up in this session: the coordinator now compares returned verifier identity with the registered expected identity and fails closed on mismatch; a unit test confirms the action rolls back rather than committing. The latest action-contract checks are now **413 unit tests passed**; full integration passed at 20+1 skipped before verifier-ID enforcement, then 3 final-code real-range acceptance tests passed. Ruff/mypy/schema checks remain green.
- Remaining: nested input validation is adapter-owned; retry scheduling and per-action resource reductions are not implemented. The current rootful Docker range does not provide a hardened resource boundary.

## 2026-09-25 — VulnGym official evaluator range-line compatibility check

- Checked the public VulnGym v0.1.4 checkout at commit `cd69f7e163e08485ab5496115ae03439cda6e27e`. This was metadata-only: no benchmark project repositories were cloned or executed and no model was called.
- The release has 408 entries / 184 advisories. A JSON query found 44 entries with an `entry_point.line` or `critical_operation.line` represented as a documented range string. The pinned evaluator converts ground-truth lines with `int(...)` and reports those entries as unmatched.
- Constructed one prediction per entry by copying the repository, commit, and annotated endpoint values from ground truth. The unmodified upstream evaluator matched 364/408 entries (89.22%) and 171/184 advisories (92.93%), with all 44 range-form entries unmatched. This is an evaluator/schema compatibility diagnostic only—not an Aegis score, model score, or meaningful ceiling.
- Recorded the result at `artifacts/benchmark_runs/vulngym-v014-evaluator-oracle-compat-20260925.json`; updated benchmark status, source registry, progress, and the active queue. Future VulnGym reporting must retain the upstream evaluator unmodified and label any separate range-aware metric as supplemental.
- Verification in this continuation: `.venv/bin/pytest -q` **449 passed**; `.venv/bin/pytest tests/integration -q -m integration` **20 passed, 1 skipped** (141.53 seconds; credential-gated model case skipped); Ruff check and format passed; strict mypy passed for 171 source files; all 18 schemas are current. No permissions, tools, secrets, or network paths were added. Remaining limitations: no Aegis VulnGym adapter or external benchmark agent score; endpoint auth still returns HTTP 401.

## 2026-09-25 — corrected qwen38 configuration and repair-provider iteration

- Correction to earlier endpoint status entries above: those HTTP 401s came from a stale/wrong ignored `.env.local`. The owner corrected the local credential; a qwen38 structured smoke proposal succeeded. No credential value is recorded in this worklog or other tracked documentation. The server alias was not switched.
- The first two repair pilots requested model-authored unified diffs. Both candidates passed source/diff policy but failed the clean build because the hunk counts were malformed. This exposed a protocol fragility rather than a verifier issue.
- Changed the patch protocol to ask for complete replacement source for the sole allowlisted file, then construct the unified diff locally. The request uses `reasoning_effort=none` and `max_tokens=8192`, rejects finish-reason truncation and no-op source, checks final-newline convention, and captures usage/finish metadata when returned. Benchmark records now include prompt version and finish reason.
- Ran qwen38 on the two synthetic fixtures using this protocol. Path traversal returned unchanged source and was rejected before verification. Object authorization generated an owner-check patch that passed source integrity, diff policy, two public tests, exploit replay, and two regression tests; 5/5 clean-room checks passed. It completed in 20.838s (18.452s generation, 2.385s verification) and reported 725 prompt + 584 completion = 1,309 total tokens. This is one verified candidate on a synthetic case, not an external benchmark/model-quality score.
- No new permissions, tools, target access, secrets, or network routes were introduced. The provider call transmitted only the already-authorized synthetic fixture and vulnerability context to the existing HTTPS endpoint. Hosted inference remains opt-in/out of CI; no raw model-to-shell or deployment authority was added. Threat impact is limited to the synthetic source disclosure boundary already documented.
- Added a request-boundary test using a malicious source comment: the injection remains inside the untrusted user-data field, hidden tests are absent, and the provider exposes no tools. This only verifies prompt construction; it does not prove the model resists prompt injection.
- Verification after provider implementation: `uv run pytest -q` **497 passed**; Docker integration **23 passed, 1 credential-gated live-model integration skipped** (116.65s); Ruff, format (**219 files**), strict mypy (**181 source files**), all **19 JSON schemas**, and `git diff --check` passed. After the test addition: `uv run pytest -q` **498 passed** with the same lint/format/type/schema/diff checks clean; Docker integration was not rerun because only a unit test changed.
- Documentation/status updated: `ACTIVE_TASKS.md`, `BENCHMARKS_AND_DATASETS.md`, `MODEL_STRATEGY.md`, `OPEN_QUESTIONS.md`, `PROGRESS_REPORT.md`, and README. Earlier HTTP 401 worklog items are preserved as historical observations and corrected here.
- Remaining limits: no external standard benchmark has been run; only one of two model-generated fixture attempts under v2 verified; patching remains narrow and fixture-bound; no broad coding-quality claim is justified. A public external benchmark must wait for an authorized, appropriately isolated harness and is still an open task.

## 2026-09-25 — Supplemental VulnGym range-aware evaluator

- Added `aegis.benchmarks.vulngym` and `scripts/evaluate_vulngym_range_aware.py`. The adapter validates the relevant JSONL contract, handles positive single-line and `start-end` locations, preserves repository/commit and endpoint-role matching, and emits recall-only metrics explicitly labelled non-official. It reports unmatched prediction count but no precision because VulnGym is not a complete negative-label set. It only reads metadata/predictions; no benchmark repositories are fetched or run.
- Added 13 unit tests covering range intersections/tolerance, role and repo/commit strictness, path normalization, duplicate predictions, invalid ranges, empty denominators, and JSONL loading. A ground-truth-copy self-check against VulnGym v0.1.4 returned 408/408 entries and 184/184 advisories; this proves matcher compatibility only, not Aegis detection capability.
- Final checks: `.venv/bin/pytest -q` **462 passed**; Ruff check passed, Ruff format reports **208 files already formatted**, strict mypy passed for **175 source files**, all **18 schemas** current, `git diff --check` and the result artifact's JSON parse passed. The real-Docker suite was run immediately before this isolated benchmark-only change and passed 20 with one credential-gated skip (141.53 seconds); runtime integration was not rerun because this change does not touch range/runtime code.
- Files changed: `src/aegis/benchmarks/`, `scripts/evaluate_vulngym_range_aware.py`, `tests/unit/benchmarks/test_vulngym.py`, VulnGym benchmark artifact, active tasks, benchmark/progress/source/worklog docs. No new permissions, tools, secrets, target repositories, or network routes. Threat impact is limited to metadata validation/scoring; official evaluator defect and absent detection producer remain.

---
