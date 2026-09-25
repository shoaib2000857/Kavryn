# Aegis Defender — implementation progress report

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
- No cross-tool finding correlation/deduplication (FR-VUL-002) yet.
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
