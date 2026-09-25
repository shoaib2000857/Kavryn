# Implementation handoff

This document is the execution contract for Codex, Claude Code, or another coding agent after the owner starts the build phase.

## Required preflight

Before coding, the implementer must read:

1. root `README.md`, `SECURITY.md`, and `AGENTS.md`;
2. all files in `docs/`;
3. especially `PRODUCT_REQUIREMENTS.md`, `CONTROL_PLANE.md`, `THREAT_MODEL.md`, `MVP_AND_ROADMAP.md`, and `DECISIONS.md`.

Do not reinterpret planned components as implemented. Update status only with passing tests.

## Proposed repository layout

Create directories incrementally as working code requires them:

```text
aegis-defender/
|- pyproject.toml
|- src/aegis/
|  |- domain/          # versioned Pydantic models
|  |- cases/           # case and scope lifecycle
|  |- policy/          # deterministic authorization
|  |- workflow/        # explicit state machine
|  |- broker/          # action/capability dispatch
|  |- evidence/        # records, provenance, artifact refs
|  |- providers/       # model provider interfaces
|  |- tools/           # descriptors and typed adapters
|  |- workers/         # execution backends
|  |- verifier/        # clean-room contracts and gate
|  `- reporting/       # JSON/SARIF/human reports
|- tests/
|  |- unit/
|  |- integration/
|  |- control/
|  `- fixtures/
|- ranges/
|  `- path-traversal-v1/
|- schemas/
|- notebooks/
|  `- hosted_model_experiments.ipynb
|- scripts/
|- docs/
`- .github/workflows/
```

Do not create empty placeholder modules for later phases.

## Build sequence by reviewable change

### Change 1 — Foundation and schemas

**Status:** Implemented and verified — see `docs/WORKLOG.md` (2026-09-03).

- `pyproject.toml`, formatter/linter/type/test configuration;
- case, scope, evidence envelope, action request, policy decision, and audit-event models;
- JSON schema export;
- unit tests for validation and serialization;
- no network, model, Docker, or target code.

Verification: format, lint, type-check, unit tests, generated schemas clean.

### Change 2 — Policy and workflow core

**Status:** Implemented and verified — see `docs/WORKLOG.md` (2026-09-03).

- pure policy decision function;
- state transition table;
- in-memory artifact/audit interfaces;
- denials for ambiguous targets, unsupported actions, expired scope, and exhausted budget;
- control tests.

Verification: deterministic tests with no LLM.

### Change 3 — Provider boundary

**Status:** Implemented and verified for the stub/replay boundary — see `docs/WORKLOG.md` (2026-09-03). The hosted GLM provider is intentionally **not** implemented; `docs/OPEN_QUESTIONS.md` OQ-004 (provider/spend-cap choice) is unresolved and its documented default is stub/replay only (`docs/DECISIONS.md` ADR-018).

- `ReasoningProvider` protocol;
- stub and replay providers;
- structured task/proposal schemas;
- bounded structured-response repair;
- optional hosted GLM provider behind environment configuration. *(deferred — see status note above)*

Verification: provider contract tests with no real secret in CI.

### Change 4 — Typed tool broker

**Status:** Implemented and verified — see `docs/WORKLOG.md` (2026-09-03).

- registry and descriptor validation;
- typed adapter protocol;
- local mock worker;
- command construction tests;
- audit every request/decision/result;
- no generic shell adapter.

Verification: injection, path, unknown-option, timeout, and budget tests.

### Change 5 — Isolated analysis worker

**Status:** Implemented and verified, including real-Docker integration tests — see `docs/WORKLOG.md` (2026-09-03). Owner decision recorded 2026-09-03 (ADR-023, resolving OQ-006 for this phase): proceed on standard rootful Docker as an interim, scoped exception to ADR-012's rootless requirement — local low-risk static-analysis fixtures only, documented in `docs/THREAT_MODEL.md`.

- rootless container backend; *(interim: rootful Docker — see status note above)*
- no-network default;
- read-only source mount;
- Semgrep/Bandit adapter for the fixture;
- result normalization and artifact hashing.

Verification: denied network/path tests and pinned worker image.

### Change 6 — Repair and verifier

**Status:** Implemented and verified, including real-Docker integration tests covering all five required scenarios — see `docs/WORKLOG.md` (2026-09-06).

- patch candidate/diff validation;
- disposable patch workspace;
- pytest/public replay adapters;
- physically/logically separate hidden verifier input;
- assurance gate and evidence bundle.

Verification: good patch passes; exploit-preserving, regression, test-gaming, and tampered-evidence patches fail.

### Change 7 — Runtime range

**Status:** Implemented and verified, including real-Docker end-to-end evidence for pre-attack reachability, containment, availability preservation, and rollback — see `docs/WORKLOG.md` (2026-09-06).

- vulnerable service, benign client, attack controller;
- normalized telemetry;
- reversible containment adapter and rollback;
- deployment provenance.

Verification: deterministic pre-attack, attack, containment, and availability checks.

### Change 8 — Full orchestrated case

**Status:** Implemented and verified for the stub/replay half — see `docs/WORKLOG.md` (2026-09-06). The hosted-provider implementation exists and is unit-tested (`src/aegis/providers/hosted.py`), but no working direct-API credential has been obtained (`docs/DECISIONS.md` ADR-031); per the owner's instruction, hosted-provider configuration is left empty pending one. No real-model run has been recorded.

- incident states wired to repair/recovery states;
- approvals and timeouts;
- hosted GLM experiment configuration; *(provider implemented, unconfigured — see status note above)*
- JSON/human report.

Verification: full stub/replay CI plus separately recorded real-model run. *(stub/replay half done; real-model run pending a working credential)*

## First technical defaults

- Python 3.12+;
- Pydantic v2;
- pytest;
- Ruff for formatting/linting;
- mypy or Pyright, choose one and record decision;
- FastAPI only when the case API is introduced;
- SQLite/local content-addressed store initially;
- rootless Docker for the low-risk MVP;
- OpenTelemetry-compatible structured events;
- provider keys in environment/secret manager;
- lock dependencies and pin worker images.

Exact dependency versions must be selected at implementation time from current official documentation and recorded in the lock file.

## Definition of done for each change

- referenced requirement IDs are satisfied;
- success and denial/failure tests pass;
- threat-model changes are documented;
- new authority, identity, secret, tool, or network path is documented;
- commands are reproducible;
- no secrets or generated large artifacts are committed;
- no implementation claim lacks evidence;
- decision/open-question logs are updated;
- handoff report lists limitations.

## Prompt for a future coding agent

```text
Implement the next incomplete change from docs/IMPLEMENTATION_HANDOFF.md.

Before editing, read README.md, SECURITY.md, AGENTS.md, and every file in docs/.
Preserve the accepted decisions in docs/DECISIONS.md and do not silently answer
items in docs/OPEN_QUESTIONS.md. Work only on local fixtures and authorized
benchmarks. Never add generic model-generated shell execution or broaden network
access. Use a small, reviewable vertical slice; add success and adversarial control
tests; update all affected documentation and status claims. At completion report
requirements satisfied, files changed, tests run, permissions/network/secrets added,
threat-model impact, and remaining limitations.
```

## Owner inputs needed before real-model integration

- provider/API choice and account;
- monthly/per-run spending limit;
- allowed data classifications for hosted inference;
- secret-storage method;
- preferred first benchmark licenses/storage budget;
- whether local Docker is available and acceptable for the MVP;
- repository license and private security contact.
