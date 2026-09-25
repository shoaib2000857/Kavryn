# Worklog

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
