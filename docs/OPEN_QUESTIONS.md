# Open questions

These items are intentionally unresolved. They do not block documentation, but some block later implementation phases.

## Owner decisions

Local-development update (2026-09-30): the owner authorized Ollama while the hosted
API is down. Installed Qwen 2.5 7B now completed a synthetic model-driven full case;
this does not resolve production provider/spend policy (OQ-004), licensing (OQ-002),
or the stronger isolation required for external project execution (OQ-006/008).
The CDB public sample has been scored for a bounded local-model component as well
as the deterministic baseline; **external repair** and full-dataset evaluation
remain open. Historical “no external benchmark” wording below refers to the earlier
checkpoint, not the latest sample/component measurements.

| ID | Question | Needed by | Current default |
| --- | --- | --- | --- |
| OQ-001 | Keep “Aegis Defender” or choose another name? | Public repository creation | **Resolved, 2026-10-01:** owner accepted Kavryn; public package/import/CLI implemented with legacy evidence compatibility (ADR-067/068). |
| OQ-002 | Which repository license? | Public release | **Resolved, 2026-10-01:** owner explicitly approved Apache-2.0; LICENSE, NOTICE and metadata applied (ADR-068). |
| OQ-003 | What private vulnerability-reporting channel should be published? | Public release | Minimal issue requesting private contact |
| OQ-004 | Which hosted model provider/API account and spend cap? | Real-model integration | **Interim endpoint/model choice:** corrected local ignored `.env.local` now works with `qwen38`; synthetic smoke succeeded and one object-authorization repair passed clean-room verification. Earlier 401s came from stale local configuration. Keep alias warm; no alias switching. Spend cap and production-use decision remain open. Stub/replay remains CI default. |
| OQ-005 | What code/log classifications may leave the local environment? | Hosted inference | Synthetic local-range context only was used and is approved for the current experiment. No private code, credentials, personal data, or real telemetry may be sent without a separate owner decision. |
| OQ-006 | Is local rootless Docker available and acceptable? | Sandbox implementation | **Resolved (interim), 2026-09-03 — see ADR-023.** Rootless Docker is not available (verified: standard rootful Docker only). The owner explicitly accepted rootful Docker as an interim container backend, scoped to local low-risk static-analysis fixtures only (L1 isolation); it is not accepted for dynamic validation or hostile-input worker classes. Revisit before any Change 7 (runtime range) or higher-risk worker is built. |
| OQ-007 | Where should durable case state live, how should uncertain effects be reconciled, and how should evidence be externally anchored? | Multi-run experiments | Optional local SQLite artifact/audit/transaction/receipt storage, restart quarantine and SQL-read-only inspection implemented as interim pieces; authority/budget recovery, multi-process coordination, clearance, and external anchoring remain open (ADR-064) |
| OQ-008 | Which first external repair benchmark fits storage/license/isolation constraints? | Phase 2 | Vul4Py is the leading design match (100 Python vulnerabilities, paired exploit/functional oracles per its paper), and a candidate repository `tabudz/vul4py` was located at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`. However, the primary paper/publication page does not link that repo, GitHub reports no license, and inspected runner code invokes metadata commands via `shell=True`, clones projects, and may download micromamba. Provenance/terms and a safer isolated runner remain unresolved. Vul4J is an alternative but its 11.77 GB image includes legacy build environments. Host has ~52 GB free and rootful runc only; no gVisor/Firecracker/Kata runtime is installed. Do not run untrusted project builds until artifact provenance/terms and an appropriate isolation boundary are established. No external benchmark has been run. VulnGym is a separate detection candidate, not a patch benchmark. |
| OQ-009 | Is hidden-state monitoring a first-year goal? | Research scheduling | Later track |

## Engineering questions to answer experimentally

- Which policy representation is easiest to audit: typed Python rules, OPA/Rego, or Cedar?
- How should OCSF records map into the internal evidence graph without losing raw provenance?
- What is the minimum clean-room separation achievable on one development machine?
- How should local range policy block or constrain container-to-host/gateway access on Docker `--internal` networks? Current verification enforces no ordinary external network and no published container ports, but host/gateway service reachability is not blocked or tested.
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
