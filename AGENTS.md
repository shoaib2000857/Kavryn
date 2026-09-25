# Instructions for coding agents

These instructions apply to any AI coding agent implementing Aegis Defender.

## Source of truth

1. Read `README.md`, `SECURITY.md`, and every document in `docs/` before proposing structural changes.
2. Treat `docs/DECISIONS.md` as accepted architecture unless the owner explicitly changes a decision.
3. Treat `docs/OPEN_QUESTIONS.md` as unresolved; do not silently choose high-impact answers.
4. Update documentation, status tables, schemas, and acceptance criteria in the same change as implementation.

## Safety and scope

- Work only with local fixtures, explicitly authorized repositories, or documented benchmarks.
- Never add arbitrary model-generated host-shell execution.
- Never give the reasoning process direct production credentials or raw access to Docker/Kubernetes sockets.
- All effectful operations must cross the typed action broker and deterministic policy engine.
- External network access is deny-by-default and case-scoped.
- Do not build offensive persistence, stealth, credential theft, or arbitrary-target automation.

## Engineering expectations

- Prefer a small working vertical slice over broad scaffolding.
- Use typed domain models and narrow interfaces.
- Keep orchestration deterministic and replayable.
- Store immutable event/evidence records with content hashes.
- Make adapters the only place where commands are constructed.
- Keep the clean-room verifier outside the agent's writable boundary.
- Unit-test policy denials and failure paths, not only successful behavior.
- Never claim a capability is implemented until its acceptance tests pass.

## Required change report

Every implementation change must state:

- requirement(s) satisfied;
- files changed;
- tests executed and results;
- new permissions, tools, network paths, or secrets introduced;
- threat-model impact;
- documentation updated; and
- remaining limitations.
