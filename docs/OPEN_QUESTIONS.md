# Open questions

These items are intentionally unresolved. They do not block documentation, but some block later implementation phases.

## Owner decisions

| ID | Question | Needed by | Current default |
| --- | --- | --- | --- |
| OQ-001 | Keep “Aegis Defender” or choose another name? | Public repository creation | Keep as working name |
| OQ-002 | Which repository license? | Public release | None; do not infer |
| OQ-003 | What private vulnerability-reporting channel should be published? | Public release | Minimal issue requesting private contact |
| OQ-004 | Which hosted model provider/API account and spend cap? | Real-model integration | **Partially resolved, 2026-09-06, ADR-031:** the owner authorized building and using a hosted provider (a generic, provider-neutral `HostedOpenAICompatibleProvider` now exists, unit-tested). Two candidate services (Agent Router/glm-5.3, kktoken.cc) were tried and both blocked direct API access at the network/anti-bot layer, unrelated to key validity; neither was worked around. Per the owner's instruction, the hosted-provider configuration is left empty for now — **stub/replay provider only** remains the effective default until a working credential is supplied. |
| OQ-005 | What code/log classifications may leave the local environment? | Hosted inference | Synthetic/public data only |
| OQ-006 | Is local rootless Docker available and acceptable? | Sandbox implementation | **Resolved (interim), 2026-09-03 — see ADR-023.** Rootless Docker is not available (verified: standard rootful Docker only). The owner explicitly accepted rootful Docker as an interim container backend, scoped to local low-risk static-analysis fixtures only (L1 isolation); it is not accepted for dynamic validation or hostile-input worker classes. Revisit before any Change 7 (runtime range) or higher-risk worker is built. |
| OQ-007 | Where should durable artifacts live? | Multi-run experiments | Local content-addressed store first |
| OQ-008 | Which first external repair benchmark fits storage/license constraints? | Phase 2 | Vul4J or a small PatchEval subset |
| OQ-009 | Is hidden-state monitoring a first-year goal? | Research scheduling | Later track |

## Engineering questions to answer experimentally

- Which policy representation is easiest to audit: typed Python rules, OPA/Rego, or Cedar?
- How should OCSF records map into the internal evidence graph without losing raw provenance?
- What is the minimum clean-room separation achievable on one development machine?
- ~~Which reversible containment primitive best fits the first range~~ **Answered, 2026-09-06, ADR-029:** a proxy rule, for the first (single-container Flask) range specifically — not a general claim it is best for every future range.
- How should model context selection trade recall against prompt-injection surface?
- Which hidden tests best detect overfitting without leaking benchmark answers?
- How should infrastructure failures be retried without enabling budget evasion?
- What human-approval interface yields reliable attribution in a local research harness?
- When does PostgreSQL become necessary over SQLite?
- What measured threshold justifies autonomous R3 reversible containment?

## Research questions

- Can runtime-to-source localization be scored independently of patch success?
- How much does clean-room verification reduce false fixes across benchmark families?
- Do agents learn to game evidence-completeness rules?
- Can a monitor detect a policy-boundary probe before the explicit denied request?
- Does multi-agent specialization improve outcomes after controlling for token/tool budget?
- What is the right capability-safety frontier visualization for AegisBench?

## Resolution process

When an answer is chosen:

1. add an ADR to `DECISIONS.md`;
2. update affected requirements, threats, and roadmap;
3. remove or mark the open question resolved;
4. add verification criteria where the decision changes behavior.
