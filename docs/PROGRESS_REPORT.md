# Aegis Defender — implementation progress report

> **2026-09-25 live repair-pilot update:** The owner corrected the ignored local `.env.local`; prior HTTP 401 observations were from stale configuration. Using the existing warm `qwen38` alias, the replacement-source v2 object-authorization patch passed clean-room source/diff checks, two public tests, exploit replay, and two regressions. The path-traversal v2 response was unchanged and rejected before verification; two earlier diff-format candidates failed clean build. The provider now requests `reasoning_effort=none`, allows `max_tokens=8192`, locally constructs diffs, and captures finish reason/token usage when supplied. This is one verified repair on one synthetic case—not a standard benchmark or broad model-quality claim. See [benchmark records](BENCHMARKS_AND_DATASETS.md#actual-evaluation-status-2026-09-25).

> **Latest verification:** 498 unit tests passed; Docker integration passed 23 tests with one credential-gated live-model test skipped. Ruff lint, format (219 files), strict mypy (181 source files), all 19 schemas, and `git diff --check` passed. A new unit test checks the hosted patch request's untrusted-source framing and confirms no hidden tests/tools are included; this is request-boundary coverage, not proof of model prompt-injection robustness. See [active task tracker](ACTIVE_TASKS.md) and [worklog](WORKLOG.md).

> **2026-09-25 full second-scenario case:** `object-authorization-v1` now runs through the same case state machine with brokered Semgrep/telemetry, evidence-linked route/source correlation, approval-gated synthetic-token containment, clean-room oracle-patch verification, brokered Docker rollout, and attack/benign recovery replay. Its authorization header is forwarded only to the fixed synthetic backend and is absent from proxy logs. At that checkpoint: **487 unit tests passed; 23 Docker integrations passed, 1 credential-gated hosted-model test skipped** (152.39s); Ruff lint/format (**216 files**), strict mypy (**178 source files**), 18 schemas, and `git diff --check` passed. This remains a stub-proposal/oracle-patch integration test—not a production defense or standard benchmark score. The live model-generated repair result is recorded in the newer addendum above.

> **2026-09-25 configurable range hooks (superseded by the full-case addendum above):** Added bounded owner-configured containment regexes, route/source bindings, and per-scenario summaries; at that point the object-authorization case was not yet wired into the full runner. Its initial verification was 485 unit tests and 22 integrations.

> **Range launch validation (2026-09-25):** `ServiceSpec` now validates image references, container/network identifiers, normalized absolute mount paths, read-only mount mode, environment keys/NUL-free values, and port bounds; stop/log/inspect helpers reject unsafe container names before Docker invocation. Verification: **478 unit tests passed**, **20 Docker integrations passed / 1 hosted-model case skipped**, Ruff, strict mypy, and 18 schemas passed. This is local fixture configuration validation—not hardened isolation, image provenance, or benchmark performance. Standard external benchmark scores remain absent.

> **Second synthetic scenario fixture (2026-09-25):** Added `ranges/object-authorization-v1`, a deliberately vulnerable document service with synthetic authenticated principals and an omitted owner check (CWE-862/CWE-639). Its Docker integration reproduces cross-owner access using only Flask's in-process test client inside a no-network, read-only, capability-dropped, resource-limited container. Result: **1 passed**. This validates the fixture, not Aegis detection or model-generated patching; the full orchestrator remains path-traversal-specific. Image build installs pinned Flask from the configured package index.

> **Second-scenario repair verification (2026-09-25):** Generalized the Layer-0 patch-pilot CLI to select either owned fixture. On the object-authorization case, a locally constructed owner-check diff passed source-integrity, diff-policy, public, exploit-replay, and regression checks; a comment-only exploit-preserving diff was rejected. The full Docker integration suite passed **22 tests with 1 credential-gated hosted-model test skipped**; the full unit suite passed **480**. Ruff, format check (**214 files**), mypy (**176 source files**), 18 schemas, CLI choices, and diff checks passed. This validates the existing clean-room verifier against a second bug class, not live model patching or the full incident-to-recovery workflow.

> **Prompt-injection control check (2026-09-25):** Added unit tests that pass an instruction-like poisoned rationale and a provider proposal for explicitly denied `host.shell` through the case/broker path. The deterministic policy denies before adapter dispatch, and orchestration halts/escalates before containment. Focused result: **2 passed**. This validates the authority boundary for this case only; it does not measure whether a model resists prompt injection generally.

> **Vul4Py artifact preflight (2026-09-25):** Located candidate repository `tabudz/vul4py` at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`; its README describes 100 paired-oracle Python cases, consistent with the paper. However, the paper/publication page does not link this repo, GitHub has no declared license, and static code review found metadata-driven `shell=True` setup/test execution, dynamic upstream clones, and micromamba downloads. No cases or runner code were executed. The candidate remains unresolved on provenance/terms and a safer isolated runner; no Aegis Vul4Py score exists.

> **VulnGym adapter (2026-09-25):** Added a metadata-only JSONL validator and supplemental range-aware recall evaluator. A self-check over copied VulnGym v0.1.4 ground truth matches 408/408 entries, including 44 range-form annotations; this validates the evaluator implementation only and is not an Aegis score. The official evaluator was not changed and its range-line incompatibility remains documented. There is still no repository-level Aegis detector/prediction producer or external benchmark score. No benchmark repositories were cloned or executed.

> **Range egress correction (2026-09-25):** A review found the synthetic app/proxy range used a normal Docker bridge, which provides default external connectivity despite the design describing it as isolated. `create_network` now requests `--internal` and verifies Docker's effective `Internal=true`; existing non-internal networks fail closed. To preserve local host-side probes without publishing the proxy port, a fixed, validated container-IP resolver is used by tests/scripts. Both range containers now have no published ports. Evidence: **449 unit tests passed; full Docker suite 20 passed, 1 hosted-model test skipped; final focused range integration 6 passed** (including explicit no-port assertions); `ruff check`, `ruff format --check` (204 files), mypy (171 source files), 18 schema checks, and diff checks passed. Docker internal mode is not host isolation: the host can reach container IPs and containers may access host/gateway services; the rootful daemon remains trusted. See ADR-051 and the T04 residual-risk note. This does not resolve external benchmark/model inference gaps.

> **Benchmark landscape refresh (2026-09-25):** Rechecked primary benchmark sources. Vul4Py describes 100 Python vulnerabilities with paired exploit and project-functional tests. A candidate repository was located, but it is not linked from the primary paper/publication page, declares no license, and its runner has unsafe host execution; see the Vul4Py preflight addendum above. VulnGym v0.1.4 exposes 408 repository-level localization entries (393 human-audited) under CC-BY-4.0, but its evaluator is recall/coverage-only. A metadata-only compatibility run at commit `cd69f7e163e08485ab5496115ae03439cda6e27e` found 44 documented line-range entries the official matcher cannot parse; the ground-truth-copy diagnostic is not an Aegis/model score. Aegis still has no VulnGym prediction producer or standard external benchmark result. No benchmark repositories were cloned/executed and no model was called during this review. The endpoint unavailability noted at that historical checkpoint is superseded by the corrected-key repair-pilot update at the top of this report. See [benchmark status](BENCHMARKS_AND_DATASETS.md), [source registry](SOURCES.md), and [active tasks](ACTIVE_TASKS.md).

> **Evidence-correlation addendum (2026-09-25):** Added deterministic hypotheses requiring a suspicious normalized range event, explicit route/source binding, and matching scan/deployment source digests. The live case runner now requires this report and halts before containment if it is absent, empty, or cross-case. The real-Docker full-case integration obtains findings via a brokered Semgrep action and telemetry from the local proxy, then verifies a hypothesis exists before continuing. The report is included in JSON/human case outputs and links case-scoped scanner-result and deployment-provenance artifact references. Causality remains unconfirmed and the current evidence/artifact store is in-memory. See `docs/ACTIVE_TASKS.md` for the latest clean verification checkpoint; the full Docker suite has not been rerun after this wiring.

> **Behavior-monitor addendum (2026-09-25):** Added a broker-fed, bounded, process-local rule baseline over structured action outcomes, action types, and policy risk tiers. It reports denial/repetition/high-impact/approval signals as advisory metadata only. A test confirms even `PAUSE_AND_ESCALATE` does not override a `PERMITTED` deterministic policy decision. The weights are engineering defaults, not calibrated probabilities or demonstrated early prediction; there is no trajectory-text or hidden-state monitor. Latest verification after this slice: **419 unit tests passed**, targeted Docker acceptance checks **3 passed**, Ruff check/format passed, mypy passed for **164 source files**, and **15 schemas** are current. The full Docker suite and all external benchmarks were not rerun by this change.

> **Current-state addendum (2026-09-25, typed action catalog and verifier identity):** Added versioned action definitions required at adapter registration. The broker enforces action/adapter binding, primitive request fields/types, policy-risk agreement, and successful output contracts; malformed requests fail before capability issuance and bad success output becomes `CONTROL_FAILURE`. The coordinator now checks returned verifier identity against the action contract and fails closed (verified rollback when available). **413 unit tests passed; latest full integration suite before this verifier-ID change: 20 passed, 1 credential-gated skip; final-code targeted real-range tests: 3 passed** (full case, containment commit, failed deployment rollback). Ruff, mypy (160 source files), all 14 schemas, and diff checks passed. Per-action resource reductions/retries remain declarative only; rootful Docker remains a known limit.

> **Current-state addendum (2026-09-25, audit stream):** Added deterministic one-case JSONL export and verification plus `python scripts/verify_audit_stream.py <file>`. It rejects malformed, empty, mixed-case, reordered, or tampered chains. This makes existing audit evidence portable, but the sink remains in-memory; no durability, signature, writer authentication, or external anchor is provided. Focused tests are recorded in the active task list/worklog; rerun status follows below.

> **Current-state addendum (2026-09-25, sandbox/verifier contracts):** added versioned/schema-exported `SandboxExecutionRequest`/`SandboxExecutionResult` models and a `SandboxBackend` protocol; the one-shot analysis worker delegates to `DockerSandboxBackend`. Added a runtime-checkable `Verifier` protocol to the transaction coordinator while retaining typed callable compatibility. Tests cover protocol dispatch, actor separation, core import boundaries, and clean-room integration. Latest full rerun: **393 unit tests passed; 20 integrations passed and one credential-gated hosted-model test was skipped** (92.72 seconds). Ruff, strict mypy (**155 source files**), formatting, all **13 schemas**, and `git diff --check` passed. These interfaces do not increase isolation, and range Docker lifecycle remains on a separate implementation path.

> **Model repair retry (2026-09-25):** one controlled qwen38 retry sent only the synthetic path-traversal source and vulnerability summary. The endpoint returned HTTP 401 in 0.146 seconds before model output. A second machine-readable infrastructure-failure artifact was recorded; this is not a model score. No model alias was switched; no further API request should be attempted until endpoint authorization is repaired.

> **Current-state addendum (2026-09-25, deployment transaction milestone):** the owned path-traversal range now routes containment, candidate image build/rollout, and rollback through fixed typed broker actions. Independent attack-blocked and benign-availability probes gate commit; a deliberately exploit-preserving candidate triggers brokered rollback, and the integration confirms the original contained service is restored. Latest checks: **388 unit tests passed; 20 integration tests passed, 1 credential-gated test skipped** (86.56 seconds); Ruff, mypy (152 source files), 11-schema export check, and `git diff --check` passed. This does not make Aegis a complete autonomous cybersecurity product: deployment is range-specific, Docker is rootful, transaction/capability/artifact/audit stores are in-memory, model patch generation has no successful live candidate, and no standard external benchmark has been run. One earlier integration attempt had a readiness timeout; the failing test passed alone and the clean full rerun passed.

> **Current-state addendum (2026-09-25):** This file's detailed body is a historical snapshot from 2026-09-06 and must not be used for current provider/test counts. Since that snapshot, the owner supplied an A100 llama.cpp-compatible endpoint. `qwen38` passed one typed synthetic-context smoke test and one live-model full Docker range run. The initial transactional runtime slice is now present: `src/aegis/core/{transaction,capability,receipt}.py`, broker capability issuance/consumption, and transaction-state audit events. Latest unit result before audit-verifier additions: 369 passed. See [active tasks](ACTIVE_TASKS.md), ADR-036–038, and the session addendum at the end of this report for current exact verification.

**Date:** 2026-09-06 (updated from the original 2026-09-03 snapshot)
**Scope:** `docs/IMPLEMENTATION_HANDOFF.md` Changes 1-8 — the entire original build plan — implemented and verified in this build session.

This report is evidence, not a pitch: every number and code path here has a corresponding passing test or a command you can re-run. See `docs/WORKLOG.md` for the full dated history and `docs/DECISIONS.md` for every architecture decision recorded along the way (ADR-001 through ADR-024).

## What Aegis Defender is, in one paragraph

A control-first autonomous defender: a reasoning component proposes actions (scan this, contain that, patch this), but it never has direct access to a shell, a Docker socket, or the audit log. Every proposal passes through a deterministic policy engine and a typed action broker before anything runs, and every request/decision/result is recorded to an append-only, hash-chained audit trail. Nothing in this codebase lets the model execute an arbitrary command.

## Status at a glance

| # | Change | Status | Tests |
| - | --- | --- | --- |
| 1 | Foundation & schemas | ✅ Implemented & verified | 80 |
| 2 | Policy engine & workflow state machine | ✅ Implemented & verified | 170 (cumulative) |
| 3 | Provider boundary (stub/replay only) | ✅ Implemented & verified | 199 (cumulative) |
| 4 | Typed tool broker | ✅ Implemented & verified | 218 (cumulative) |
| 5 | Isolated analysis worker | ✅ Implemented & verified | 241 unit + 4 integration |
| 6 | Repair & clean-room verifier | ✅ Implemented & verified | 290 unit + 9 integration |
| 7 | Runtime attack range | ✅ Implemented & verified | 319 unit + 15 integration |
| 8 | Full orchestrated case | ✅ Implemented & verified (stub/replay) | 350 unit + 16 integration |

All 350 unit tests run in under two seconds with no network, model, or Docker dependency. The 16 integration tests require Docker (three pinned images) and run in a bit over a minute end to end — including one complete, real, incident-to-recovery case run.

## Repository size (this session's work only)

- **Source:** ~65 Python files across 14 packages (`domain`, `policy`, `workflow`, `evidence`, `providers`, `broker`, `workers`, `tools`, `repair`, `verifier`, `telemetry`, `range`, `orchestrator`, `reporting`).
- **Tests:** 350 unit tests + 16 real-Docker integration tests.
- **Architecture decisions recorded:** 32 (`docs/DECISIONS.md`).
- **Real infrastructure built:** one intentionally-vulnerable Flask fixture (source, public tests, and hidden tests as physical siblings), one pinned analysis-worker Docker image (Semgrep 1.176.0, Bandit 1.9.4, an offline taint-mode rule), one pinned clean-room verifier image with its own separate non-root identity, and one pinned containment-proxy image with a third separate identity.

## Change-by-change summary

### Change 1 — Foundation and schemas

Six immutable, frozen Pydantic v2 models with versioned `schema_version` literals and a fail-closed registry dispatch (`aegis.domain.registry.parse_record` rejects any unknown or missing schema version rather than guessing): `Case`, `ScopePolicy`, `EvidenceEnvelope`, `ActionRequest`, `PolicyDecision`, `AuditEvent`. JSON Schema is generated from the models and checked for drift in CI (`scripts/export_schemas.py --check`).

Every field that could carry an ambiguous or dangerous value is constrained at the type level: resource references require an explicit URI scheme, action/tool identifiers must be a dotted `namespace.verb` form (so a request can never smuggle a raw shell string through an "action type" field), and `ActionRequest.parameters` outright rejects reserved keys like `command`/`shell`/`exec`.

### Change 2 — Policy engine and workflow state machine

`evaluate_action_request` is a pure function — no I/O, no clock access beyond an injected `now` — that decides `PERMITTED` / `DENIED` / `APPROVAL_REQUIRED` for one action request against a case, its scope policy, and current budget usage. It fails closed on every ambiguous condition: expired scope, unlisted or explicitly-denied action types, adapters not on the tool allow-list, unresolvable targets, and exhausted budgets.

The workflow state machine (`aegis.workflow`) is a direct transcription of `docs/WORKFLOWS.md`'s closed-loop incident-to-patch diagram — 19 states, 25 transitions — with every transition and every terminal-state rejection unit-tested.

**Two real bugs were caught and fixed here before release**, both found while writing adversarial tests rather than after: naive string-prefix matching on scope paths let `workspace://AGE-0001/candidate/../../etc/passwd` pass (the *string* still started with the allowed prefix even though the *path* resolved outside it), and the same bare prefix check let a sibling directory like `workspace://AGE-0001/candidate-evil` pass because it shared characters with the allowed prefix without being beneath it. Both are now rejected and regression-tested.

### Change 3 — Provider boundary

The `ReasoningProvider` protocol, structured task/proposal schemas, `StubProvider` and `ReplayProvider`, and bounded structured-response repair (`parse_with_bounded_repair`: at most N corrective re-queries, every raw attempt preserved, never inferring an action from free-form text). **No live hosted model provider was built** — `docs/OPEN_QUESTIONS.md` OQ-004 (which provider, what spend cap) is an explicit, unresolved owner decision, and the documented default is stub/replay only. Building a live provider now would have meant silently choosing that answer.

### Change 4 — Typed tool broker

`ActionBroker.submit` is the first place all of the above gets wired together end-to-end: it runs the Change-2 policy decision, dispatches to a registered adapter only when permitted, and audits the request, the decision, and the result — three hash-chained events per successful call. An adapter allow-listed by scope but never registered with the broker raises loudly (`BrokerError`) rather than silently denying or silently running, because that's a control-plane configuration fault, not an ordinary policy denial.

### Change 5 — Isolated analysis worker (the first change that touches real infrastructure)

This is where the project stopped being pure Python and started touching Docker, real tools, and a real vulnerable fixture.

**The fixture:** `ranges/path-traversal-v1/` — a small Flask service with a genuine, intentional CWE-22 path-traversal vulnerability (`os.path.join` on an unsanitized query parameter), pinned dependencies, and a Dockerfile pinned by base-image digest.

**The worker image:** `docker/analysis-worker/` — Semgrep 1.176.0 and Bandit 1.9.4, pinned by exact version, running as a non-root user, with a project-authored offline Semgrep rule baked in (rules can't be fetched from the Semgrep registry at scan time because the container runs with `--network none`).

**A real bug found by testing against real Docker, not mocks:** even with a local ruleset and `--metrics=off`, Semgrep still attempted a network version-check after scanning, which hung under `--network none` until timeout. Found by running the exact container command directly and bisecting flags; fixed with `--disable-version-check`. Documented in ADR-024 specifically so nobody "fixes" this later by opening up network access instead.

**Real, live evidence** (not simulated) from this session, produced by `pytest tests/integration -q -m integration`:

- **Semgrep**, run against the real fixture inside the real pinned container, found the real vulnerability:
  ```json
  {
    "check_id": "opt.aegis.rules.python-flask-path-traversal",
    "path": "/src/app.py",
    "start": { "line": 23 },
    "extra": {
      "message": "Untrusted Flask request input flows into a filesystem path operation without validation or canonicalization (CWE-22, path traversal).",
      "severity": "ERROR"
    }
  }
  ```
- **Bandit**, same fixture, same container, flagged a second real (lower-severity) issue: `B104 hardcoded_bind_all_interfaces` — "Possible binding to all interfaces" — at `app.run(host="0.0.0.0", ...)`.
- **Network denial is real, not asserted:** a container run attempting `socket.create_connection(("8.8.8.8", 53))` inside the same sandbox fails.
- **Read-only mount is real, not asserted:** a container run attempting `touch /src/should-not-be-writable` inside a `:ro`-mounted fixture fails.

### The one owner decision this session surfaced instead of guessing

Change 5 needs container isolation. `docs/DECISIONS.md` ADR-012 calls for **rootless** Docker; this machine only has standard rootful Docker. Rather than silently building on it or silently blocking, this was raised directly — the owner chose to proceed on rootful Docker as an explicit, scoped, documented interim measure (local low-risk static-analysis fixtures only). Recorded as ADR-023, with the corresponding gap added to `docs/THREAT_MODEL.md`'s T03 entry and residual-risk section, and `docs/OPEN_QUESTIONS.md` OQ-006 updated to reflect the resolution.

### Change 6 — Repair and clean-room verifier (the most architecturally significant change so far)

This is the first change where two sides of the system actively cannot trust each other by design, and that separation had to actually hold up, not just be described.

**The fixture, restructured:** `ranges/path-traversal-v1/{src,public_tests,hidden_tests}/` are now physical siblings, not nested directories — the patch-preparation code is only ever given `src/`, so there is no tree containing `hidden_tests/` for it to accidentally copy. A new `secret.txt` sentinel file stands in for sensitive data outside the served directory; `hidden_tests/test_exploit_replay.py` tries 5 differently-encoded traversal payloads against it.

**The clean-room verifier:** a second pinned Docker image (`docker/verifier/`) with its own separate non-root identity (`verifier`, uid 10003 — distinct from the analysis worker's `analysis`, uid 10001). Its entrypoint script reconstructs the candidate itself, from a read-only mount of the trusted base source and the diff file alone — it never receives or trusts an already-patched tree from whoever prepared the candidate.

**The assurance gate:** a pure function mapping check results to one of four outcomes (`VERIFIED`, `REVIEW_REQUIRED`, `REJECTED`, `CONTROL_FAILURE`), with a tampered or mismatched base-source digest always outranking an ordinary failed check, and an ordinary hard failure always outranking an infrastructure error or a soft ("review, don't auto-reject") failure.

**Real, live evidence** from `pytest tests/integration -q -m integration`, five real patch candidates run through the complete pipeline end to end:

| Scenario | What it does | Outcome |
| --- | --- | --- |
| Good patch | Fixes the vulnerability with `werkzeug.utils.safe_join` | `VERIFIED` |
| Exploit-preserving | A no-op comment change, fixes nothing | `REJECTED` |
| Regression-breaking | Blocks the exploit by always returning 404 — breaks legitimate downloads too | `REJECTED` |
| Test-gaming | Special-cases exactly one literal traversal string, leaves the general flaw | `REJECTED` |
| Tampered evidence | The correct fix, but claiming a false base-source digest | `CONTROL_FAILURE` |

**Two real bugs found by testing against the real `patch` binary and real Docker, not by inspection:**

1. `AegisModel`'s project-wide whitespace-stripping default silently ate the trailing newline off a diff, which `patch` then rejected as malformed. A field carrying byte-exact content needs an explicit opt-out (ADR-027) — a pattern, not a one-off fix.
2. The verifier's own diagnostic shell output (`patching file app.py`) was landing in the same stream as the JUnit XML the Python side parses, breaking the parser the moment a real assertion was made about its content — a manual eyeballed smoke test had missed this entirely. Fixed by silencing that output at the source.

### Change 7 — Runtime attack range (the fixture goes live)

Every prior change worked against the fixture's source. This is where it runs, over a real network, under a real attack.

**The setup:** the vulnerable Flask app is deployed with no published port at all — the only way to reach it is through a fixed, reviewed reverse proxy (`docker/range-proxy/`, a third pinned image with its own identity, `rangeproxy` uid 10004) that forwards requests and enforces a containment rule read from a file.

**The reversible-containment question, answered by building:** `docs/OPEN_QUESTIONS.md` left "which containment primitive fits the first range" as an engineering question to resolve experimentally, not an owner decision. The answer: a proxy rule (ADR-029) — applying and rolling back containment are the same operation (write a rule file), so rollback cannot drift from apply.

**Real, live evidence** from `pytest tests/integration -q -m integration`:

1. **Pre-attack:** a benign request (`?filename=welcome.txt`) returns `200`.
2. **Pre-containment attack:** the traversal request (`?filename=../secret.txt`) returns `200` and genuinely leaks the sentinel — over the network, not via static analysis.
3. **Containment applied:** the same attack now returns `403`; the benign request still returns `200` — the exploit is blocked without an availability cost.
4. **Rollback:** the attack request returns `200` again — reversibility is real, not asserted.
5. **Telemetry:** the proxy's real structured logs are parsed into normalized events, correctly classified `benign` and `suspicious` respectively.

**A real bug found by testing against real container startup timing:** the first version of the traffic helper only handled a server returning an HTTP status; a container that had started but wasn't yet accepting connections produced an uncaught `ConnectionResetError` that broke the test's readiness-polling loop. Fixed by treating any connection-level failure as ordinary data (`status_code=0`) a caller can retry on, the same pattern already used for container timeouts (ADR-030).

### Change 8 — Full orchestrated case (the capstone)

Every prior change gets wired into one driven run: a pure orchestrator (`src/aegis/orchestrator/`) walks the real Change 2 workflow state machine using real outcomes from real Change 5/6/7 infrastructure, gated by real approval logic (`src/aegis/policy/approval.py`), producing a JSON and human-readable report (`src/aegis/reporting/`) at the end.

**Real, live evidence:** `tests/integration/test_full_case.py` runs one complete case end to end against genuine Docker infrastructure — detects the exploit is reachable, proposes and applies real reversible containment, verifies it holds while benign traffic keeps working, generates and clean-room-verifies a real patch candidate (the same `werkzeug.utils.safe_join` fix from Change 6), rebuilds and redeploys the app image with the patch applied, rolls back containment, and verifies the *patch itself* — not the proxy rule — now blocks the exploit. The case reaches `CLOSED` on its first real run.

**A real bug found by a test assertion, not by inspection:** the first draft of the orchestrator silently dropped four states from its own trace (`AWAIT_APPROVAL`, `CONTAIN`, `AWAIT_DEPLOY_APPROVAL`, `RECOVER`) — some `apply_transition` calls simply weren't followed by a record call. A unit test asserting the *exact* sequence of states visited caught this immediately. Fixed structurally, not by patching the four missed spots: the tracing and the transition are now one atomic operation (`CaseTrace.advance`), so the bug class can't recur.

**A real model call, temporarily via local Ollama, not a hosted provider.** Mid-session, the project owner supplied API keys for two third-party model-router services with explicit authorization to use them. Both blocked direct API access before it reached their model backend — one with a consistent `401` tied to their CLI-tool-specific integration path, the other with a bare Cloudflare-level `403` on the completions endpoint regardless of payload. Neither was a credentials problem, and neither was worked around: disguising requests as an approved client to get past either service's own anti-abuse control isn't something this project will do. The hosted-provider code (`src/aegis/providers/hosted.py`) is real, generic, and fully unit-tested against a fake transport — it remains unconfigured for production, by the owner's own instruction, until a working credential is available. In the meantime, the owner asked to try a local Ollama model to genuinely exercise the harness with live (non-canned) output: `HostedOpenAICompatibleProvider` works against Ollama's OpenAI-compatible endpoint with zero code changes, and `tests/integration/test_live_model_ollama.py` now runs the full capstone path with a real local model answering the containment-proposal step. Every other test in this repository still runs on deterministic stub/replay; see the benchmark below for what running the same path repeatedly, live, actually showed.

### Live-model benchmark (temporary, local — not a production claim)

Three different local models — `qwen2.5:7b`, `llama3.1:8b`, `gpt-oss:20b` — were tried against the containment-proposal step. The first attempt with each one failed the same way: every model invented a plausible but schema-invalid `adapter` id (`network_policy_tool`, `firewall`, `manual`) because `run_case` was passing an empty tool list — the model had no real id to copy and no way to get it right. This was a genuine orchestrator bug (ADR-035), not a model-quality problem, and it was masking (not caused by) the earlier fix that made a provider failure halt gracefully instead of crashing the case (ADR-033). Fixed by threading the real `range.proxy` tool descriptor through to the model.

With that fixed, `scripts/bench_live_model.py` ran 5 repeated full-case trials per model against the one fixture this project has (`ranges/path-traversal-v1`):

| Model | Trials reaching `CLOSED` | Avg. wall time per case |
| --- | --- | --- |
| `llama3.1:8b` | 5/5 | 3.5s |
| `qwen2.5:7b` | 5/5 | 8.6s |
| `gpt-oss:20b` | not run (repeatedly) | 60-87s for a single call — impractical on this machine's 8 GB VRAM |

`llama3.1:8b` was selected as this machine's default going forward: both small models were equally reliable once given the real tool list, and `llama3.1:8b` was consistently faster. `glm-4.7-flash` (19 GB) and `gemma4:26b` (17 GB) were deliberately not tried — neither fits in 8 GB of VRAM, and forcing either to run would risk destabilizing the rest of the machine for a benchmark that a smaller model already answers.

**What this does and does not show:** it demonstrates the provider boundary and orchestrator genuinely work end to end against live, non-deterministic model output on the one incident scenario this project has built so far, and it surfaced one real bug in the process (ADR-035). It says nothing about repair-candidate generation quality, detection recall at scale, or standing against any external benchmark — `docs/BENCHMARKS_AND_DATASETS.md`'s Layers 1-4 remain unwired (OQ-008 open), so this five-trial, one-fixture result is the only benchmark that can honestly be reported today.

## Known limitations (honest, not hidden)

- No working *hosted* (production) model credential (ADR-031) — the full-case capstone still runs on stub/replay by default. A local Ollama model has been proven to work end to end for the containment-proposal step only (ADR-034/ADR-035); patch-candidate generation and every other reasoning step in the default suite remain hand-authored/stub-provided.
- Rootful, not rootless, Docker (by owner decision — see ADR-023 above).
- No SBOM or image-signature verification beyond digest/version pinning, for any of the three pinned images.
- Initial deterministic same-case/source-version correlation is required by the fixed path-traversal Docker case; generalized cross-tool deduplication, durable evidence retrieval, and causal validation remain incomplete (FR-VUL-002).
- The verifier's "brand-new finding" review path is unit-tested with canned data but not yet exercised by a real integration scenario that introduces a genuinely new Semgrep-detectable issue.
- The range's network topology (one app + one proxy per range, one published port bound to `127.0.0.1`) is scoped to a single local, ephemeral, per-test-run range, not multiple concurrent cases.
- The orchestrator calls its injected dependencies directly rather than routing containment/deployment actions through the Change 2 policy engine and Change 4 action broker as typed `ActionRequest`s — every action is captured in the case-level trace/report, but not yet in the broker's separate hash-chained audit trail.
- `CaseDependencies` has no dedicated "deploy" step yet; the capstone test triggers deployment as a guarded side effect of the first recovery check rather than through its own callable.

## How to reproduce every claim in this report

```bash
# fast unit suite, no Docker needed
.venv/bin/python -m pytest -q                        # 350 passed

# real Docker integration suite (builds all three pinned images, plus
# one more on demand for the full-case capstone test)
docker build -t aegis-analysis-worker:local -f docker/analysis-worker/Dockerfile docker/analysis-worker
docker build -t aegis-verifier:local -f docker/verifier/Dockerfile docker/verifier
docker build -t aegis-range-proxy:local -f docker/range-proxy/Dockerfile docker/range-proxy
.venv/bin/python -m pytest tests/integration -q -m integration   # 16 passed

# static checks
.venv/bin/python -m ruff format --check . && .venv/bin/python -m ruff check . && .venv/bin/python -m mypy
```

## 2026-09-25 session addendum — hosted model + transactional runtime start

This addendum supersedes the 2026-09-06 provider and test-count claims above; the historical record is retained intentionally.

### Hosted model

- Configured through the existing provider abstraction for the owner-provided A100 llama.cpp-compatible endpoint; alias used: `qwen38` only. No model switching was performed.
- `scripts/smoke_model_api.py` makes a single schema-validated synthetic-range containment proposal. It cannot invoke tools. Result: passed; returned the allowlisted `range.proxy` adapter.
- `tests/integration/test_full_case.py::test_full_case_reaches_closed_with_live_hosted_model` ran the existing Docker scenario with live hosted reasoning for containment planning. Result: 1 passed; case reached `CLOSED`.
- Limits: patch generation remains the existing fixture candidate; this model did not generate the repair. One scenario and one trial do not establish detection, patching, or general defensive capability. Hosted calls remain excluded from default tests.
- Secret handling: key was supplied through environment variables for the tests and was not written to tracked files. It was pasted into chat; rotate it after the session. Only synthetic range context was sent.

### Runtime work

- Added `aegis.core.ActionTransaction` with an explicit transition graph and immutable transition history.
- Added `Capability` + process-local `CapabilityAuthority`; broker checks expiry, revocation, single use, case, transaction, actor, action, adapter, target, and canonical parameter digest before execution.
- Broker records transaction-state transitions in the existing hash-linked audit sequence and returns the transaction snapshot. Successful adapter execution is `EXECUTED`, not `COMMITTED`.
- Added `ExecutionReceipt` v1 and deterministic content-digest seal/verify helpers. The receipt is not yet built from real transaction outcomes or linked to an independently verified commit.
- Added a receipt factory from terminal transaction snapshots; it rejects mismatched dispositions (for example, labeling `EXECUTED` as `COMMITTED`). Final emission remains unconnected to the broker because independent verification/commit is not implemented.
- Added exported schemas for transaction, capability, and receipt models.
- Added audit-chain content verification. It is tamper-evident only: a local unsigned hash chain cannot authenticate the writer or prevent full-stream rewrite/re-hash.

### Current verification in this session

- Unit suite: **370 passed** after adding receipt-factory and audit-chain verification assertions.
- Live API smoke: passed once (`qwen38`).
- Live Docker + hosted model case: passed once (`qwen38`).
- Ruff formatting check: 144 Python files already formatted; Ruff lint passed; strict mypy passed for 143 source files; schema check passed for 9 schemas; `git diff --check` passed.
- Full Docker integration suite: **17 passed, 1 skipped** (the environment-gated hosted-model test is skipped when credentials are absent from the test process). Separately, the hosted-model Docker test was run once and passed.

### Important remaining gaps

- Orchestrator containment/deployment still has injected effectful callables that bypass `ActionBroker`.
- No approval-driven generic transaction coordinator, independent postcondition verifier, commit/rollback orchestration, or receipt factory is wired to the broker.
- Capability management is process-local and not cryptographically signed; not a hardened boundary against a compromised process.
- Audit storage is in-memory for current implementations; external anchoring/authentication is future work.
- The exact reusable core-vs-defender module boundary remains incomplete.

## 2026-09-25 addendum — patch generation and benchmark preflight

- Added `HostedPatchProvider` and strict `PatchProposal` schema. The model sees only the explicitly supplied source file and vulnerability summary; source text is marked as untrusted data. Returned diffs are hashed and checked against the allowed-file set before a candidate is created.
- Added `scripts/bench_patch_repair.py`, which routes a candidate through source-integrity, diff-policy, public-test, hidden exploit-replay, and regression checks in the existing separate-identity, network-disabled verifier. The verifier receives source and hidden tests read-only; the model request does not include tests.
- Provider tests: **5 passed**. Full default unit suite: **375 passed**. Full Docker integration suite: **17 passed, 1 skipped** (the environment-gated hosted integration, because credentials were not loaded into the pytest process; the separate API pilot got HTTP 401). Ruff format/lint, strict mypy over 146 source files, schema drift check (9 schemas), and `git diff --check` passed.
- One actual qwen38 repair-pilot request reached the configured service but received HTTP 401 before candidate generation. No candidate was produced and no verifier ran. This is documented as infrastructure failure, not a model-quality failure; see `artifacts/benchmark_runs/qwen38-path-traversal-pilot-attempt-2026-09-25.json`.
- External benchmark preflight: **no SWE-bench, Vul4J, AutoPatchBench, or Cyber Defense Benchmark run is claimed**. At preflight the host had ~52 GB free; official SWE-bench guidance calls for at least 120 GB, and AutoPatchBench recommends ~500 GB for its sample-20. Vul4J's upstream container bundles its JDK matrix, but there is no Aegis adapter and rootful-only Docker is not accepted here for executing its historical build/test payloads. Dataset and tooling licenses differ (CC-BY-4.0 dataset / GPL-3.0 tooling), so both need to be respected.
- Current coverage is still one owned synthetic vulnerable Python service. The external benchmark queue is not complete, the model-generated repair score is **not available**, and detection/threat-hunting at scale is not implemented.
- New permissions, tools, network paths, or secrets: no new permission/tool/network route was added. The same owner-configured HTTPS inference endpoint was contacted once for the synthetic source; the API key was not written to output or tracked files. Existing Docker verifier behavior is unchanged.
- Threat-model impact: the new boundary adds an untrusted model diff path, constrained by typed parsing, a strict one-file allowlist, independent source digest validation, and isolated clean-room tests. It does not address compromised host Docker or service availability risks.
- Next: confirm/repair endpoint authorization without changing model aliases, obtain a single verified pilot result, then expand to a pinned, licensed external repair subset after storage/runtime preflight.

## 2026-09-25 addendum — transaction coordinator, replay guard, and real rollback verification

- Added `ActionTransactionCoordinator` for approval-gated broker actions, independent typed verification checks, evidence artifact recording, commit, brokered rollback, escalation, control failure, and versioned audit-linked receipts. A verifier exception becomes failed evidence and cannot authorize commit.
- Broker now checks transaction snapshots and serializes lifecycle updates; reused transaction IDs are rejected before adapter dispatch. Rollback approval follows the same explicit pending/resume process as the primary action.
- Added real Docker acceptance tests against the local path-traversal range: successful containment blocks traversal and preserves benign download (`COMMITTED`); a test-only overbroad adapter blocks legitimate traffic, fails the verifier, rolls back through the broker, and independently verifies restoration (`ROLLED_BACK`). The overbroad adapter exists only inside the integration test.
- Current checks: `pytest -q` **384 passed**; Docker integrations **19 passed, 1 skipped** (hosted provider test requires credentials in the pytest process), 84.13 seconds; Ruff format **182 files clean**, Ruff lint clean, strict mypy clean for **149 source files**, **11 schemas** current, `git diff --check` clean.
- Scope caveat: the coordinator is now demonstrated, but the legacy `run_case` orchestration still contains effectful injected callbacks and deployment is still embedded in a recovery callback. Full broker-only mutation routing is not complete. Capability/transaction state, audit and artifact stores are process-local/in-memory and are not crash- or compromise-resistant.
- Benchmark result: **no standard external benchmark has been run and no headline model score exists**. Machine preflight is ~52 GB free and Java 26 only; the official Vul4J image bundles legacy JDKs, but Vul4J was not downloaded or run because only rootful runc is available and no Aegis adapter exists. SWE-bench and AutoPatchBench were not started due storage requirements. The qwen38 repair requests failed with HTTP 401 before patch generation. Internal range acceptance and one-fixture tests are not substitutes for external benchmark results.
- New permissions, tools, secrets, or network paths: none. Work was limited to the owned synthetic Docker range and local unit/integration checks. Threat-model impact is positive for transaction replay and fail-closed rollback coverage, but rootful Docker, process-local authority, and in-memory audit remain material risks.

## 2026-09-25 verification correction — brokered containment and live-model denial

- Removed the direct containment/apply/rollback callback branch from `run_case`; containment and rollback are now fixed typed broker requests coordinated with attributed approval, independent attack/availability probes, rollback verification, audit, and receipts. The model cannot supply operation parameters.
- The live Ollama integration initially exposed an expected safety outcome: an unconstrained model proposal was denied by scope policy. The test had incorrectly classified escalation as failure. It now accepts and checks explicit fail-closed escalation, and the human-readable trace carries the broker's concrete denial reason.
- Final reruns: unit suite **384 passed**; full Docker integration **19 passed, 1 credential-gated skip** (82.47s); Ruff formatting **183 files clean**, Ruff lint clean, strict mypy **150 source files clean**, schema drift **11 schemas current**, `git diff --check` clean.
- This does not finish broker routing: deployment, candidate-image build, and some recovery effects remain direct injected operations. The runtime is still process-local/in-memory and the API repair-pilot HTTP 401 remains unresolved. No external standard benchmark was run and no benchmark score is claimed.
- Requirements satisfied: broker-only containment mutations, useful denial evidence, corrected integration expectation. Files changed in this correction: `src/aegis/orchestrator/case_runner.py`, `tests/integration/test_live_model_ollama.py`, `tests/unit/reporting/test_case_report.py`, `docs/ACTIVE_TASKS.md`, and this report. No permissions, tools, credentials, or network paths were added; local Docker/Ollama synthetic fixture only. Threat-model impact is improved fail-closed observability; direct deployment/recovery effects and rootful Docker remain limitations.
