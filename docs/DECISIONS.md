# Architecture decision log

Accepted decisions guide implementation. Changes require a new entry; do not rewrite history without noting supersession.

## ADR-001 — Independent research project

- **Status:** Accepted
- **Decision:** Aegis Defender is independent from the supplied ASTRA-Kavach hackathon material.
- **Rationale:** The reference material contributes ideas, but the desired system has broader research scope and no competition constraints.

## ADR-002 — Control-first system

- **Status:** Accepted
- **Decision:** The autonomous defender and deterministic control/verification plane are separate systems.
- **Rationale:** Model capability cannot be the root of authorization, audit integrity, or patch acceptance.

## ADR-003 — Provider-neutral model interface

- **Status:** Accepted
- **Decision:** GLM is a candidate provider, not an architectural dependency.
- **Rationale:** Model releases, API economics, hardware, privacy, and performance change quickly.

## ADR-004 — Colab is a client, not full GLM-5.2 hosting

- **Status:** Accepted
- **Decision:** Use Colab for experimentation and hosted-API access or smaller models; do not plan normal Colab as the full GLM-5.2 inference host.
- **Rationale:** The published 744B/40B-active model requires server-class multi-GPU resources.

## ADR-005 — Explicit state machine before multi-agent orchestration

- **Status:** Accepted
- **Decision:** Start with one reasoning runtime and specialized typed tasks/states.
- **Rationale:** It minimizes coordination failure, cost, hidden communication, and attack surface while providing a baseline for later experiments.

## ADR-006 — Typed adapters; no generic model shell

- **Status:** Accepted
- **Decision:** Every effectful action uses a versioned typed adapter through the action broker.
- **Rationale:** Raw shell access defeats enforceable parameter, target, and provenance controls.

## ADR-007 — Curated tools before broad catalogues

- **Status:** Accepted
- **Decision:** Add a small tool set tied to scenarios and requirements; defer a BlackArch-scale registry.
- **Rationale:** Every adapter has security, maintenance, and evaluation cost.

## ADR-008 — Evidence-carrying patch terminology

- **Status:** Accepted
- **Decision:** Default to “evidence-carrying patch” and “assurance gate.”
- **Rationale:** Build/tests/replay provide empirical assurance, not general mathematical proof.

## ADR-009 — Independent clean-room verification

- **Status:** Accepted
- **Decision:** Candidate generation and verification use separate identities, images, writable state, and data access.
- **Rationale:** Self-verification permits test gaming, contamination, and evidence tampering.

## ADR-010 — Capability and safety metrics remain separate

- **Status:** Accepted
- **Decision:** Do not compress patch/defense success and policy violations into one headline score.
- **Rationale:** A capable but unsafe agent and a safe but useless agent represent different failures.

## ADR-011 — Narrow incident-to-patch MVP

- **Status:** Accepted
- **Decision:** First scenario is one isolated Python service with telemetry, reversible containment, source localization, patching, clean verification, redeployment, and recurrence monitoring.
- **Rationale:** It exercises the defining closed loop with manageable scope.

## ADR-012 — Progressive isolation

- **Status:** Accepted
- **Decision:** Rootless containers are allowed for low-risk MVP fixtures; high-risk evaluation must progress to a stronger sandbox/VM boundary.
- **Rationale:** Container isolation alone is not a complete hostile-code security boundary.

## ADR-013 — Documentation is part of implementation

- **Status:** Accepted
- **Decision:** Requirements, decisions, threats, status, and handoff material are updated with code changes.
- **Rationale:** The repository is intended to support long-lived research and coding-agent handoffs without fictional implementation status.

## ADR-014 — Static type checker: mypy

- **Status:** Accepted
- **Decision:** Use mypy (strict mode, with the `pydantic.mypy` plugin) as the project's static type checker. Pyright is not adopted.
- **Rationale:** mypy was already available in the implementation environment and is well integrated with Pydantic v2 via its official mypy plugin; either tool would satisfy `docs/IMPLEMENTATION_HANDOFF.md`'s requirement to pick one. Revisiting this is low-cost if Pyright is later preferred (e.g. for editor integration).

## ADR-015 — Change 1 domain schema conventions

- **Status:** Accepted
- **Decision:** For `src/aegis/domain/`:
  - every model derives from a shared frozen, extra-forbidding `AegisModel` base (immutable, unrecognized fields rejected);
  - list-like fields use `tuple[...]` rather than `list[...]`, matching the immutable-record posture;
  - every record carries a `schema_version: Literal["aegis.<entity>/v1"]`, and `aegis.domain.registry.parse_record` dispatches on that field, raising `UnknownSchemaVersionError` for anything missing or unregistered rather than guessing a shape;
  - target/resource references use a constrained `Uri` type requiring an explicit scheme (e.g. `workspace://...`), and action/tool identifiers use a constrained dotted `namespace.verb` pattern (e.g. `test.run`) — both reject free-form or shell-like strings at construction time;
  - `ActionRequest.parameters` rejects a small set of reserved keys (`command`, `cmd`, `shell`, `argv`, `exec`, `script`, `raw_command`) so a request cannot smuggle a raw command past the typed-adapter boundary;
  - `PolicyDecision.risk_tier` is assigned by the decision record, never supplied on `ActionRequest`, and `capability_ref` may be set if and only if `outcome == PERMITTED`;
  - `AuditEvent` records are hash-chained (`prev_event_digest` references the previous event's `integrity` digest) to make tampering or deletion detectable once stored in an append-only sink.
- **Rationale:** These are structural, schema-level encodings of already-accepted invariants (ADR-006, ADR-009, SR-AUT-001, SR-NET-001, SR-AUD-001, FR-SCP-003) rather than new policy — they make a class of malformed or adversarial input rejectable before any policy-evaluation code exists (Change 2).

## ADR-016 — Target resolution scheme for the policy engine

- **Status:** Accepted
- **Decision:** `aegis.policy.targets.resolve_target` resolves an `ActionRequest.target_ref` against a `ScopePolicy` by URI scheme: `workspace://` and `artifact://` are matched against `scope.filesystem.write`/`.read` prefixes at a `/`-boundary (never a bare string prefix, and never through a `.`/`..` path segment); `asset://`/`repo://` and `service://` are matched by exact id against `scope.targets.repositories`/`.services`. Any other scheme, or no match, is unresolved.
- **Rationale:** `docs/CONTROL_PLANE.md`'s scope-policy schema is explicitly "not executable yet" — a concrete resolution algorithm is required engineering to satisfy FR-SCP-003 and is not itself an item in `docs/OPEN_QUESTIONS.md`. Plain `str.startswith` prefix matching was tried first and found unsound on two counts during test-writing (both now covered by regression tests in `tests/unit/policy/test_targets.py`): it lets `workspace://AGE-0001/candidate/../../etc/passwd` pass because the *string* still starts with the allowed prefix even though the *path* resolves outside it, and it lets `workspace://AGE-0001/candidate-evil/secret` pass because it shares a string prefix with `workspace://AGE-0001/candidate` without being beneath it. The accepted implementation rejects any `.`/`..` path segment outright and requires the match to land on a `/` boundary.

## ADR-017 — Risk-tier classification table

- **Status:** Accepted
- **Decision:** `aegis.policy.risk.classify_risk` maps an action type's namespace (the segment before the first `.`) to a `RiskTier`, using the exact examples in `docs/CONTROL_PLANE.md`'s risk-tier table (e.g. `evidence.*`→R0, `scan.*`/`patch.*`→R1, `test.*`/`http.*`→R2, `contain.*`→R3, `deployment.*`/`build.*`→R4, `host.*`/`iam.*`/`audit.*`→R5). An unrecognized namespace classifies as `None` and the policy decision function denies the request rather than guessing a tier. Regardless of what a scope policy's `actions.auto`/`.approval` buckets say, an action classified R5 is denied unconditionally by `evaluate_action_request` — scope policy can loosen R1–R4 treatment within the bounds `docs/CONTROL_PLANE.md` already describes as policy-dependent, but it cannot grant R5 authority to itself.
- **Rationale:** `docs/ARCHITECTURE.md` requires that "Risk is determined by the action and context, not by the model's label," and `docs/CONTROL_PLANE.md`'s risk-tier table already states R5 is "Denied in research system" as an absolute rule, not a scope-configurable one. Encoding the R5 block as a hard-coded, scope-independent check gives defense in depth against a misconfigured or compromised scope policy; this is covered by `tests/unit/policy/test_decision.py::test_r5_action_is_denied_even_if_scope_lists_it_as_auto`.

## ADR-018 — Change 3 scope: provider boundary without a live hosted provider

- **Status:** Accepted
- **Decision:** `src/aegis/providers/` implements the `ReasoningProvider` protocol, `StructuredProposal`/`ReasoningTask`/`EvidenceContext`/`ToolDescriptor`/`InferenceLimits` schemas, `StubProvider`, `ReplayProvider`, and bounded structured-response repair (`parse_with_bounded_repair`). It does **not** implement a hosted GLM or any other network-calling provider, even though `docs/IMPLEMENTATION_HANDOFF.md` Change 3 lists "optional hosted GLM provider behind environment configuration" as part of that change.
- **Rationale:** `docs/OPEN_QUESTIONS.md` OQ-004 ("Which hosted model provider/API account and spend cap?") is explicitly unresolved, with a stated current default of "Stub/replay provider only." Building a live provider now — even one gated behind environment configuration — would mean choosing a provider, base URL, and cost posture ahead of that owner decision. The `ReasoningProvider` protocol is written to accommodate a future `OpenAICompatibleProvider`/`ZaiProvider` adapter without modification once OQ-004 is resolved.

## ADR-019 — Structured-proposal repair is caller-supplied, not embedded in the provider

- **Status:** Accepted
- **Decision:** `parse_with_bounded_repair(raw, *, repair, max_repair_attempts)` takes the corrective re-query as an injected `RepairFn` callable (`(raw_response, error_message) -> corrected_raw_response`) rather than owning a model call itself.
- **Rationale:** Keeps the bounded-repair *policy* (preserve every raw attempt, cap the retry count, never infer an action from free text, propagate failure for the caller to refuse/escalate — docs/MODEL_STRATEGY.md's "Structured-output rule") fully unit-testable with no model or network dependency, while leaving the actual re-query mechanism (which does need a real provider) to whichever future change wires a live provider in.

## ADR-020 — Adapter audit-event `integrity` stays a content hash; result digests go in the summary

- **Status:** Accepted
- **Decision:** `ActionBroker` always computes an `AuditEvent.integrity` digest over the event's own canonical content (id, case_id, timestamp, type, actor, role, subject_ref, summary), for every event type including `tool_run_recorded`. The stored result artifact's own content digest is instead appended to that event's human/machine-readable `summary` text (`"...result_digest=sha256:<hex>"`), not substituted in as `integrity`.
- **Rationale:** `integrity` is the field the *next* audit event chains onto (`prev_event_digest`); overloading it to sometimes mean "hash of this event" and sometimes "hash of an artifact this event references" would make the chain semantically inconsistent and harder to verify generically. This was caught and fixed before release while implementing Change 4 — the first draft used the result digest as `integrity` for tool-run events, which would have broken that invariant.

## ADR-021 — Adapter permissions are `Literal["none"]` for network and secrets until a networked worker exists

- **Status:** Accepted
- **Decision:** `AdapterPermissions.network` and `.secrets` only accept `"none"` in Change 4. No adapter or worker introduced so far has network or secret access, so no other value could be truthfully declared yet.
- **Rationale:** Keeps the honesty invariant from `docs/IMPLEMENTATION_HANDOFF.md` ("no implementation claim lacks evidence") at the type level: it is structurally impossible to declare a network- or secret-capable adapter before a worker class that actually provides that capability exists. Widening these to a richer enum is expected alongside the dynamic-validation worker in a later change, not before.

## ADR-022 — Broker-level control faults are distinct from policy denials

- **Status:** Accepted
- **Decision:** `ActionBroker.submit` raises `BrokerError` (not a `PolicyDecision` with `outcome=DENIED`) when a scope policy allow-lists an adapter id that was never registered with the broker's `AdapterRegistry`. Likewise, a `ParameterValidationError` from an adapter's own parameter check propagates uncaught rather than being silently absorbed into an `AdapterResult`.
- **Rationale:** A policy denial means "this specific request is not authorized," which is an expected, everyday outcome the case workflow already knows how to handle (see `docs/WORKFLOWS.md` failure semantics: "Scope/policy denial: Record denial; do not prompt-loop to bypass policy"). An unregistered-but-allow-listed adapter or a malformed parameter set is a different kind of failure — a configuration or input-shape fault in the trusted computing base itself — and conflating the two would let a real control-plane misconfiguration masquerade as an ordinary, expected denial.

## ADR-024 — Pinned, offline Semgrep ruleset baked into the analysis-worker image

- **Status:** Accepted
- **Decision:** The analysis-worker image (`docker/analysis-worker/Dockerfile`) bakes a project-authored Semgrep ruleset (`docker/analysis-worker/rules/python-security.yaml`, a taint-mode rule tracing Flask request input to `os.path.join`/`open`) into the image at `/opt/aegis/rules/`, and `make_semgrep_adapter`'s default `ruleset` points at that in-image path rather than a Semgrep-registry preset (`p/security-audit`, `auto`, etc.).
- **Rationale:** The worker runs with `--network none` (SR-NET-001); a registry-fetched ruleset cannot be resolved at all under that policy. This also directly matches the tool-descriptor convention already in `docs/TOOLS_AND_SANDBOXES.md`'s example (`ruleset_ref: immutable-artifact`) and `docs/TOOLS_AND_SANDBOXES.md`'s supply-chain control "pin rule/test corpora by version/hash" — the ruleset is version-controlled and baked into a digest-identified image, not fetched live.
- **Finding during verification:** even with a local ruleset and `--metrics=off`, `semgrep --json` still attempted a network version-check after scanning and before emitting JSON, which hung under `--network none` until the adapter's own timeout — confirmed by running the exact command directly against the container. Fixed by adding `--disable-version-check` to the adapter's command (`src/aegis/tools/static_analysis.py`). This is exactly what the no-network default is supposed to catch, working as intended, and is recorded here so a future contributor does not "fix" the hang by re-enabling network egress instead.

## ADR-023 — Interim acceptance of rootful Docker for the Change 5 worker sandbox

- **Status:** Accepted (interim; supersedes the rootless assumption in ADR-012 for this phase only)
- **Decision:** `docs/OPEN_QUESTIONS.md` OQ-006 is resolved for the current phase: the project owner has explicitly accepted standard rootful Docker (verified present in the implementation environment; no rootless mode available) as the container backend for the Change 5 isolated analysis worker, rather than pausing for rootless Docker setup or building a process-level-isolation alternative. This is an explicit, informed exception to ADR-012's rootless-container requirement, not a silent substitution.
- **Scope of the exception:** rootful Docker is accepted only for **local development/research use against the project's own low-risk static-analysis fixtures** (L1 isolation per `docs/TOOLS_AND_SANDBOXES.md`'s maturity table: "Rootless container, no network — Low-risk static/dev fixtures"). It is not accepted as sufficient isolation for dynamic validation, exploit replay, or any worker class handling untrusted/hostile input beyond a pinned static-analysis fixture (L2+); those remain gated on either rootless Docker becoming available or progressing to a stronger sandbox (gVisor/Kata/microVM) per ADR-012's own progressive-isolation plan.
- **Compensating controls:** the reasoning runtime and the model are never given the Docker socket or CLI directly (SR-SEC-002, unchanged); only broker/worker-management code (`src/aegis/workers/`) invokes the container backend, through the same typed-adapter/action-broker path as every other effectful operation; containers run with `--network none` and a read-only source mount by default (docs/TOOLS_AND_SANDBOXES.md "Worker classes: Read-only analysis worker").
- **Rationale:** Root-equivalent access to the Docker daemon means a container escape has host-root consequences rather than a compromised unprivileged user's consequences — a strictly larger blast radius than ADR-012 originally accepted. The owner weighed this against the cost of pausing the build to provision rootless Docker (or building and later replacing a process-isolation interim step) and chose to proceed, given the narrow, currently-static-analysis-only scope. See `docs/THREAT_MODEL.md`'s T03 entry and residual-risk section for the corresponding threat-model update, made in the same change.

## ADR-025 — Physical, not just logical, separation of source/public/hidden tests

- **Status:** Accepted
- **Decision:** `ranges/path-traversal-v1/{src,public_tests,hidden_tests}/` are physical siblings, not nested directories. `create_patch_workspace` (the patch-worker side) is only ever given `src/` to copy, so there is no directory tree containing `hidden_tests/` for it to accidentally include — the guarantee holds by construction, not by a runtime exclude-filter that could be misconfigured or bypassed.
- **Rationale:** `docs/TOOLS_AND_SANDBOXES.md`'s "Patch worker" class requires "no hidden tests, evaluator ground truth"; a filter-based exclusion (e.g. `shutil.copytree(..., ignore=...)`) is one missed pattern away from leaking hidden tests into the patch worker's view. A structural guarantee has no such failure mode.

## ADR-026 — The clean-room verifier reconstructs the candidate itself; it never trusts a pre-patched tree

- **Status:** Accepted
- **Decision:** `docker/verifier/entrypoint.sh` copies the trusted base source and applies the candidate's diff *inside the verifier container itself*, from a read-only mount of the same pinned base source the patch worker used and the diff file alone — never from a workspace the patch-worker side already built and handed over.
- **Rationale:** docs/DECISIONS.md ADR-009: generation and verification must not share writable state. If the verifier trusted an already-patched tree, a compromised or buggy patch-worker process could hand the verifier a tree that does not actually correspond to the declared diff (e.g. with extra, undeclared changes), and the verifier would have no way to detect it. Reconstructing from (trusted source, diff) independently closes that gap; `check_source_integrity` (ADR is below) additionally confirms the trusted source itself matches what the candidate claims.

## ADR-027 — Diff and command-adjacent string fields must not be whitespace-stripped

- **Status:** Accepted
- **Decision:** `PatchCandidate.diff` uses `Annotated[str, StringConstraints(strip_whitespace=False)]`, explicitly overriding `AegisModel`'s model-wide `str_strip_whitespace=True`.
- **Finding during verification:** the model-wide whitespace-stripping default — appropriate for human-facing fields like `title` or `reason`, where leading/trailing whitespace is noise — silently stripped the required trailing newline off a unified diff, which `patch` then rejected as malformed ("patch unexpectedly ends in middle of line"). Caught by `tests/unit/repair/test_workspace.py` failing against the real `patch` binary, not by inspection. Any future field whose exact bytes matter (diffs, raw tool output, file content) needs the same explicit override — this is not a one-off fix, it is a reusable pattern for the same class of field.

## ADR-028 — Assurance-gate outcome mapping: integrity vs. ordinary hard failures vs. soft failures

- **Status:** Accepted
- **Decision:** `evaluate_assurance` maps `CheckResult`s to the four `AssuranceOutcome`s as: any hard-failing check tagged as an integrity check (currently only `source_integrity`) → `CONTROL_FAILURE`, taking priority over everything else; any other hard-failing check → `REJECTED`; an `ERROR` status (the verifier infrastructure could not produce a trustworthy result) or a non-hard (`hard_failure=False`) `FAIL` (e.g. `security_rescan` flagging a brand-new, non-original finding) → `REVIEW_REQUIRED`; no checks at all → `REVIEW_REQUIRED`; everything passing → `VERIFIED`.
- **Rationale:** Directly encodes `docs/EVIDENCE_AND_ASSURANCE.md`'s decision table and `docs/WORKFLOWS.md`'s failure semantics ("Verifier infrastructure failure: REVIEW_REQUIRED, never VERIFIED"; "Evidence integrity failure: CONTROL_FAILURE and case stop") as one pure, exhaustively-tested function, so a genuinely new finding introduced by an otherwise-correct patch does not auto-reject the whole candidate but also never silently passes as `VERIFIED`.

## ADR-029 — Reversible containment primitive: a proxy rule

- **Status:** Accepted (resolves an engineering question, not an owner decision)
- **Decision:** `docs/OPEN_QUESTIONS.md`'s engineering question ("Which reversible containment primitive best fits the first range: proxy rule, service-mesh policy, container network rule, or application feature flag?") is answered experimentally: a proxy rule. A fixed, reviewed reverse proxy (`docker/range-proxy/proxy.py`) sits in front of the vulnerable app — the app container itself is never given a published port, only the proxy is — and enforces a `ContainmentRule` (a list of deny-query regex patterns) read from a file. Applying containment and rolling it back are the same operation, `write_rules`, so rollback cannot drift from apply: it is simply re-applying the rule captured before containment began.
- **Rationale:** Of the four candidates, a proxy rule needed no new isolation primitive beyond what Change 5 already established (a fixed reviewed script, argv-only container construction) and gives a single, auditable enforcement point independent of the vulnerable app's own code — the app is never modified in place (its `app.py` docstring already says it must never be "fixed" in place). A container-network rule would have required per-request granularity Docker's network layer doesn't offer cheaply; a service mesh or application feature flag were judged disproportionate to a single-container fixture. This is not a general claim that a proxy rule is the best primitive for every future range — only the one that fit this first one, exactly as `docs/OPEN_QUESTIONS.md` asked to determine by building it.
- **Verified:** `tests/integration/test_runtime_range.py` deploys the real app+proxy pair, confirms the exploit succeeds pre-containment, confirms it is blocked (`403`) while benign traffic keeps working (`200`) post-containment, and confirms rollback restores the original (`200`) behavior.

## ADR-030 — Connection-level failures are `RequestOutcome` data, not exceptions

- **Status:** Accepted
- **Decision:** `aegis.range.traffic.send_get` catches `OSError` (which covers `urllib.error.URLError` and a raw `ConnectionResetError`/`ConnectionRefusedError` alike) and returns `RequestOutcome(status_code=0, ...)` rather than letting the exception propagate.
- **Finding during verification:** the first version of the Change 7 integration tests failed intermittently with an uncaught `ConnectionResetError` from a readiness-polling loop, because `send_get` only caught `HTTPError` — a container that has started but is not yet listening produces a connection-level failure with no HTTP status at all, which is a different thing from a server returning a 4xx/5xx. Fixed by treating "never reached a server" (`status_code=0`) as ordinary `RequestOutcome` data, matching `ContainerRunResult`'s existing "a completed call does not imply success" treatment of infrastructure conditions (timeouts) elsewhere in the codebase — the same class of gap, caught the same way, by testing against a real container's real startup timing instead of only a fake runner.

## ADR-031 — OQ-004 (hosted provider) interim status: owner-authorized, no working credential yet

- **Status:** Accepted (interim; the underlying open question is not fully closed)
- **Decision:** The project owner explicitly authorized building and using a hosted-model provider for Change 8, resolving the *authorization* half of `docs/OPEN_QUESTIONS.md` OQ-004 ("Which hosted model provider/API account and spend cap?"). `src/aegis/providers/hosted.py` (`HostedOpenAICompatibleProvider`) exists, is fully unit-tested against an injected fake transport, and is provider-neutral (ADR-003): any OpenAI-Chat-Completions-shaped endpoint works by changing only `HostedProviderConfig` and the injected API key. **No working direct-API credential was obtained during this change**, and by the owner's own instruction (2026-09-06) the hosted-provider configuration is left empty/unset for now, to be supplied later — every test in this repository, including the Change 8 full-case run, uses `StubProvider`/`ReplayProvider`.
- **What was tried and why it does not resolve OQ-004 yet:** two third-party API-router services were offered, in turn. The first (Agent Router / agentrouter.org, targeting `glm-5.3`) returned a consistent `401 unauthorized_client_error` on every attempt (three retries, then a second unrelated key — identical error both times), traced to their documented CLI-tool-specific integration path (`experimental_bearer_token` inside a Codex/Claude-Code config file), not a generic HTTP client. The second (kktoken.cc) accepted the key for `GET /v1/models` (200) but returned a bare `403` with `content-length: 0` served directly by Cloudflare (not their application) for `POST /v1/chat/completions`, regardless of model name or payload content — an edge-level anti-bot block, not a credentials or balance problem.
- **Rationale for not working around either block:** both look like deliberate anti-abuse/anti-scripting controls (a client-identity gate in one case, a Cloudflare bot-protection rule in the other). Spoofing a User-Agent or otherwise disguising this code as one of their supported client tools to get past either control would be circumventing a third party's explicit access-control decision — not something this project will do regardless of who is asking or which account's key is in use. `docs/OPEN_QUESTIONS.md` OQ-004 remains open for a *working* credential; only the provider-choice-and-authorization half is settled.

## ADR-032 — Orchestrator design: fixed simplifications grounded in accepted docs, never invented transitions

- **Status:** Accepted
- **Decision:** `aegis.orchestrator.case_runner.run_case` drives the exact Change 2 `apply_transition` state machine with three fixed rules, each traceable to an accepted document rather than invented for convenience: (1) containment and deployment always route through their approval-gate edge (`RISK_REQUIRES_APPROVAL`, never `POLICY_PERMITS`) — docs/WORKFLOWS.md's "Human checkpoints in early releases" explicitly requires human approval for "executing any containment, even reversible" and "deploying any patch to the range service" at this stage of the project; (2) a repair outcome of `CONTROL_FAILURE` or `REVIEW_REQUIRED` always escalates immediately via the `INSUFFICIENT_EVIDENCE` edge, without spending a retry, since neither is "the patch is bad, try again" — it is "the evaluation itself cannot be trusted," which docs/EVIDENCE_AND_ASSURANCE.md treats as non-compensating; (3) when a real outcome has no corresponding edge from the current state in the accepted diagram (the clearest case: the reasoning provider declines to propose a containment action at all), the case halts at its current state with an explanatory note rather than forcing a transition that was never accepted.
- **Finding during verification:** the first draft of `run_case` had a distinct bug — four transitions (`AWAIT_APPROVAL`, `CONTAIN`, `AWAIT_DEPLOY_APPROVAL`, `RECOVER`) changed `state` without ever being recorded in the trace, because only some `apply_transition` call sites were followed by a `trace.record(...)` call. Caught by `tests/unit/orchestrator/test_case_runner.py`'s exact-state-sequence assertion, not by inspection. Fixed by removing the possibility of the bug's existence, not just its symptom: `CaseTrace.advance(trigger, note)` now applies the transition and records the resulting state as a single atomic operation, so there is no longer any code path that can move `state` without that change landing in the trace.
- **Also decided:** a containment or repair retry re-runs its entire propose/approve/apply/verify sub-sequence from scratch, never just re-checks a stale prior result — an ineffective containment rule does not become effective by asking the same question twice without changing anything.

## ADR-033 — A provider failure, of any kind, halts the case; it never crashes the orchestrator

- **Status:** Accepted
- **Decision:** `run_case`'s calls into a `ReasoningProvider` go through `_propose_or_none`, which wraps the call in a broad `try/except Exception` and returns `(None, reason)` on any failure instead of letting the exception propagate. The orchestrator treats that the same way it treats a provider that responds but declines to propose an action: a graceful halt at the current state (`CONTAIN_PROPOSAL`), with the failure reason recorded in the trace, never an unhandled exception reaching the caller.
- **Finding during verification:** the temporary, owner-approved local-Ollama live-model test (`tests/integration/test_live_model_ollama.py`, see below) surfaced a real gap the stub/replay-only test suite could not: `qwen2.5:7b` returned a `StructuredProposal`-shaped response with `action.adapter = "network_policy_tool_adapter"` — not the required dotted `namespace.verb` form (e.g. `network.rate_limit`). `parse_with_bounded_repair` retried up to its configured budget and still failed, so `HostedOpenAICompatibleProvider.propose()` raised `HostedApiError`, which propagated uncaught out of `run_case` and crashed the whole case run. This is exactly the class of thing a genuinely live, imperfect model exercises and a canned stub cannot: `docs/MODEL_STRATEGY.md` already says a provider response is "untrusted," and `docs/WORKFLOWS.md`'s failure-semantics table already calls "model unavailable" a "pause safely," not a crash — the code simply had not been made to honor that for the exception path specifically (only for the "responds but declines" path).
- **Rationale for a broad `except Exception`:** `ReasoningProvider` is a protocol any future backend can implement; the orchestrator cannot enumerate every way a given implementation might fail (network errors, timeouts, malformed responses exhausting repair, a bug in the provider itself) and must not assume any of them are well-behaved. Catching narrowly would just move the crash to the next failure mode nobody had thought to add a case for.
- **Verified:** `tests/unit/orchestrator/test_case_runner.py::test_raising_provider_halts_gracefully_instead_of_crashing` (a fake provider whose `propose` always raises) confirms the halt-not-crash behavior without needing Ollama; `tests/integration/test_live_model_ollama.py` re-run against the real local model after the fix now passes, printing the exact schema-validation failure above and halting cleanly rather than crashing.

## ADR-034 — Temporary local-Ollama live-model testing, not a hosted-provider decision

- **Status:** Accepted (interim; does not resolve OQ-004)
- **Decision:** `tests/integration/test_live_model_ollama.py` runs the full Change 8 capstone path (real Docker range, real containment, real repair verification, real recovery) with the containment-proposal step answered by a real local Ollama model (`qwen2.5:7b`) through the exact same `HostedOpenAICompatibleProvider` built for a hosted provider, since Ollama exposes an OpenAI-Chat-Completions-compatible endpoint. Per the owner's instruction (2026-09-06, "keep that ai thing empty for now, I'll attach some AI keys and providers later on"), this is temporary local verification only — it exercises the provider boundary and orchestrator with genuinely live, non-canned model output while `docs/OPEN_QUESTIONS.md` OQ-004 (which hosted provider, for production) stays open and the hosted-provider configuration stays unset everywhere else. The test is skipped automatically (`pytest.mark.skipif`) when Ollama or the configured model is not present locally, and is excluded from the default `pytest -q` run like every other `integration`-marked test.
- **Rationale:** the Change 8 test suite, until now, only ever drove the provider boundary with `StubProvider`/`ReplayProvider` canned responses — real but never actually exercising the "a real model's output can be malformed" path that ADR-033 above was found through. Ollama needed no account, key, or anti-abuse workaround (unlike the two blocked hosted attempts in ADR-031), so it was the lowest-friction way to get genuine live-model evidence without touching the still-open hosted-provider decision at all.
- **Verified:** the test passes, reporting the model's real (schema-invalid) output and the orchestrator's graceful halt; its assertions accept either `CLOSED` (a fully successful live-model run) or a graceful halt at `CONTAIN_PROPOSAL` (a provider failure correctly contained) as evidence the wiring works — never an uncaught exception — reflecting that a live model's output is not perfectly deterministic even when the rest of the pipeline is.

## ADR-035 — The containment-planning call must supply the model real, available tool ids; three different local models all failed the same way until it did

- **Status:** Accepted
- **Decision:** `CaseDependencies` gained a `containment_tools: tuple[ToolDescriptor, ...]` field, threaded through `_propose_or_none`/`_propose` into the real `ReasoningProvider.propose()` call (previously hardcoded to an empty tuple). `HostedOpenAICompatibleProvider`'s system prompt and per-tool JSON now also state explicitly that `adapter` must be copied verbatim from an `available_tools[].id`, never invented, and that both `action_type`/`adapter` must be dotted `namespace.verb` identifiers.
- **Finding during verification:** before this fix, three different local models (`qwen2.5:7b`, `llama3.1:8b`, `gpt-oss:20b`), tried against the identical containment-planning prompt used by `run_case`, *all* invented a plausible-sounding but schema-invalid `adapter` value (`network_policy_tool`, `firewall`, `manual` respectively) — not because any one model was unusually bad, but because the prompt never told any of them a real tool id existed to copy. The system prompt only said `"adapter": "<tool id>"`, and `_propose()` always called `provider.propose(task, context, (), limits)` — an empty tools tuple, regardless of what the real broker/scope actually made available. ADR-033's `_propose_or_none` fix correctly stopped this from crashing the orchestrator, but it was masking a second, more basic problem: the model was being asked to guess a value it had no way to get right. This is exactly the kind of thing a live model exposes that a stub/replay provider (which always returns a canned, self-consistent proposal) cannot.
- **Rationale:** `docs/ARCHITECTURE.md` already treats the model as an "untrusted adviser" that proposes from a known tool surface — it does not invent capabilities. Supplying the actual `ToolDescriptor` for the one containment primitive this range has (`range.proxy`, ADR-029) is not a workaround for a weak model; it is completing the contract the schema already implies (`adapter: "<tool id>"` presupposes a known set of ids to choose from) and matching how the same call would work once containment is eventually routed through the Change 4 broker's own tool registry.
- **Verified:** re-run against the same three models with the fix in place — all three now return a schema-valid, `range.proxy`-adapter proposal on every trial (`tests/integration/test_live_model_ollama.py`; ad hoc script probes for `qwen2.5:7b`/`llama3.1:8b`/`gpt-oss:20b`, not checked in). `scripts/bench_live_model.py` (new) then ran 5 repeated full-case trials against both `qwen2.5:7b` and `llama3.1:8b`: **5/5 reached `CLOSED` for both**, but `llama3.1:8b` averaged 3.5s per case versus `qwen2.5:7b`'s 8.6s (`gpt-oss:20b` was excluded from repeated trials: ~60-87s per single containment-planning call on this machine's 8 GB VRAM, unusable for iterative testing). `llama3.1:8b` is therefore the model used for `scripts/bench_live_model.py`'s default and for the recorded benchmark in `docs/PROGRESS_REPORT.md`. This is a hardware-fit and latency finding for one local machine, not a claim that `llama3.1:8b` is the best model for this task in general.
