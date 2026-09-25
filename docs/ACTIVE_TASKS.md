# Active implementation queue

Updated: 2026-09-25. This is the operational task list for the current flagship direction. Status is tied to code/tests, not aspiration.

## Completed this session

- [x] Add a broker-fed behavioral monitoring baseline; it reports bounded-window denials, repeated denied action types, higher-risk requests, and pending approvals as advisory metadata only. Its weights are uncalibrated and it cannot influence authorization.
- [x] Make investigation a required typed case dependency; the runner halts before containment on a missing, empty, failed, or cross-case hypothesis report and includes valid hypotheses in JSON/human reports.
- [x] Move range investigation from integration-only scaffolding into `aegis.investigation.range`; the reference service broker-runs both Semgrep and fixed-proxy telemetry reads, stores deployment provenance, and emits the correlated hypothesis.
- [x] Add `range.proxy.logs` as a typed R0 broker action with fixed target/container, bounded output, and no caller-supplied parameters; classify `telemetry.*` as R0 and test it.
- [x] Wire the real Docker full-case test through brokered scan and telemetry actions, source/deployment provenance, and the correlator; verify a hypothesis is present before containment.
- [x] Close default external routing for the local range: request Docker `--internal`, verify effective isolation even for a pre-existing network, reject unsafe identifiers, and keep app/proxy ports unpublished; host tests use the fixed proxy container IP.
- [x] Add a deterministic same-case/source-version telemetry-to-finding correlator that emits evidence-linked hypotheses; normalize scanner paths relative to the worker mount and reject cross-case/source-mismatch inputs. The fixed-range workflow uses it; generalization and durable evidence retrieval remain open.
- [x] Validate local range service image/container/network identifiers, mount paths/modes, environment keys/values, and published-port ranges before constructing Docker arguments; add negative tests. This is configuration hardening, not Docker isolation or image authenticity.
- [x] Add adversarial control tests: a poisoned instruction embedded in an action rationale and a provider proposal for explicitly denied `host.shell` both fail at the deterministic broker before adapter dispatch; the case escalates without containment. This proves policy enforcement for this proposal, not general model prompt-injection resistance.
- [x] Add a second owned synthetic vulnerability fixture (broken object-level authorization), reproduce cross-owner access in a constrained network-disabled Docker container, and verify known-good/exploit-preserving candidates with hidden tests in the independent clean-room verifier. No model-generated repair result exists.
- [x] Run the object-authorization fixture through the full brokered incident workflow: real proxy replay, brokered scan and bounded telemetry, route/source-linked hypothesis, approval-gated synthetic Bob-token containment, independent clean-room oracle-patch verification, brokered image rollout, attack/benign recovery replay, and audit receipt. This is a deterministic integration test, not a model-generated repair score.
- [x] Generalize the local-range hooks needed by that second case: bounded owner-configured containment regexes/rule IDs, trusted route-to-source bindings, and scenario-specific incident summaries. Model output cannot change these adapter settings.

- [x] Read the existing project instructions and architecture/status documents before editing.
- [x] Keep one live model selected: `qwen38` on the owner-provided A100 llama.cpp-compatible endpoint.
- [x] Smoke-test one typed model proposal using only synthetic local-range context.
- [x] Run one real-Docker full-case integration with live hosted reasoning for containment planning; no model-generated patch or direct execution was enabled.
- [x] Make the hosted provider honor per-call token/time limits and support optional `reasoning_effort` for llama.cpp compatibility.
- [x] Refuse to send hosted API credentials to non-local plaintext HTTP from the live test scripts.
- [x] Add repeatable smoke and hosted benchmark entry points using environment-only credentials.
- [x] Add immutable `ActionTransaction` records and explicit legal transition checks.
- [x] Add a process-local capability authority enforcing expiry, revocation, single-use, and request bindings (case, transaction, actor, action, adapter, target, parameter digest).
- [x] Integrate capability issuance/consumption and transaction transition audit events into `ActionBroker`.
- [x] Add a versioned, content-hashed execution-receipt record/helper and JSON Schemas for new records.
- [x] Record the new runtime-first flagship direction, qwen38 experiment, data boundary, and known implementation limits.
- [x] Add a strict hosted patch-generation provider with a typed output schema, source/diff scope checks, and content-hashed candidates.
- [x] Add a Layer-0 repair pilot runner that sends only the synthetic app source and uses the independent Docker verifier.
- [x] Record benchmark resource preflight and the latest hosted patch-pilot HTTP 401 without turning it into a model score.
- [x] Add a verifier-gated transaction coordinator that records approval, execution, verification, commit/rollback, and receipt linkage.
- [x] Reject stale or replayed transaction snapshots under a broker lock; rollback approval uses the same pending/resume flow.
- [x] Exercise both commit and verified rollback against the real local Docker range.
- [x] Remove direct containment approval/apply/rollback callbacks from the case orchestrator; require a broker-backed cyber action runtime and use it in the real-range case.
- [x] Route local range deployment/build and rollback through fixed typed broker actions; gate rollout on independent attack-blocked and benign-availability checks.
- [x] Introduce a domain-neutral `SandboxBackend` protocol and route one-shot analysis-worker execution through its Docker implementation; add core/defender import-boundary and delegation tests.
- [x] Add a typed `Verifier` protocol for independent postcondition checks while retaining callable compatibility for existing range/test adapters.
- [x] Add stable one-case JSONL audit-chain export/parsing, tamper verification, and a read-only `verify_audit_stream.py` CLI; this does not add durable or authenticated storage.
- [x] Add CI for locked unit/type/lint/schema validation and the synthetic Docker integration suite; pin Actions by commit and grant only repository read permission. The hosted workflow has not yet been observed running on GitHub.
- [x] Explicitly assert the transaction and capability schemas remain registered in the exported schema contract test.
- [x] Revalidate the corrected ignored `.env.local` with one synthetic qwen38 smoke request; structured output passed schema and adapter-allowlist checks without switching aliases.
- [x] Run qwen38 repair pilots on both owned fixtures under the initial diff and replacement-source protocols. The first two model-authored diffs had malformed hunk counts; replacement-source v2 verified the object-authorization repair, while its path-traversal response was unchanged and rejected before verification. Four fixture attempts total; not standard benchmark scores.
- [x] Add a patch-provider prompt-injection regression test confirming repository-supplied instructions remain in the user data field, the system message identifies repository text as untrusted, hidden tests are absent, and no tools are exposed. This verifies request construction only, not model-level prompt-injection resistance.

## Current verification checkpoint

- Latest provider change: `HostedPatchProvider` now requests complete replacement source for the one allowlisted file, then constructs a unified diff locally (avoids model-generated hunk-count corruption). It explicitly sets `reasoning_effort=none`, `max_tokens=8192`, rejects truncated/no-op responses, and records finish reason/token usage when supplied. The v2 object-authorization candidate passed independent clean-room verification; the v2 path-traversal response was unchanged and rejected before verification.
- Latest complete local verification after provider change and request-boundary regression test: **498 unit tests passed**; `ruff check .`, `ruff format --check .` (**219 files**), strict `mypy` (**181 source files**), all **19 schemas** current, and `git diff --check` passed. Full Docker-backed integration: **23 passed, 1 credential-gated hosted-model test skipped** (116.65s; integration was unchanged by the added unit test). The skipped integration needs the pytest process to receive `LLM_URL`/`LLM_API_KEY`; separate synthetic-only smoke and patch pilot calls succeeded using the local env file.

- Previous checkpoint before hosted patch-provider refinements: **487 unit tests**, **23 integration passed / 1 skipped**, Ruff format 216 files, mypy 178 files, 18 schemas. Superseded by the complete checkpoint above.
- The production investigation extraction passes strict mypy (171 source files); the full Docker suite has since passed (20 passed, 1 credential-gated skip).
- GitHub CI workflow passes local YAML parsing and `actionlint`; a remote Actions run is not available from this checkout, so do not claim CI green until GitHub executes it.
- The earlier HTTP 401 came from a stale/wrong ignored `.env.local`; the owner corrected the local credential. A qwen38 synthetic smoke request then succeeded. Do not expose the credential or copy it into tracked files/docs.
- Live model smoke: passed with corrected local configuration (qwen38); no alias switch.
- Live Docker case: passed once with qwen38; do not repeat unless a relevant code change requires it.
- Brokered Docker deployment acceptance pair: full-case verified commit and exploit-preserving candidate rollback both pass; targeted rollback test passed (1 passed, 5.33 seconds).
- The first run after adding artifact-linked correlation failed closed because the integration helper wrapped an already-complete deployment artifact URI twice. The helper now passes the broker-returned case-scoped URI directly; the latest full suite and standalone full-case rerun both pass.
- Formatting/lint: Ruff format/check passed; strict mypy passed for 169 source files; schema drift passed (18 schemas); `git diff --check` passed.
- Secret scan found only the placeholder declaration in the owner-supplied API guide; no credential value was added to the repository. The corrected local API credential remains in ignored `.env.local`; never copy or print it.
- Remaining effect boundary: the reference range's candidate build/rollout and rollback now use fixed broker adapters; recovery-stage probes are observational. This does not establish a general deployment backend, hardened sandboxing, durable state, or a clean domain-neutral runtime boundary. Review other adapters and paths before claiming every effect in every workflow is brokered.
- Sandbox backend status: the core protocol currently governs the one-shot analysis worker only. The range service/network/deployment Docker helpers still use a separate command-runner path; no alternate backend is implemented and the protocol itself adds no isolation.
- The sandbox extraction also passed 4 focused real-Docker analysis-worker integration tests.
- Corrected-key model repair results: prompt v1 produced two malformed model-authored diffs rejected at build; prompt v2 produced a verified object-authorization patch (public, exploit-replay, and regression checks passed) and an unchanged path-traversal response rejected before verification. These are owned-fixture pilot outcomes, not general coding-quality or standard benchmark scores.
- No standard external benchmark has been run. Current free disk is ~52 GB (below SWE-bench's stated 120 GB baseline and AutoPatchBench sample's ~500 GB recommendation). Vul4J's upstream image bundles the legacy JDK matrix, so host Java version is not itself a blocker; current blockers are rootful-only isolation, no Aegis benchmark adapter, and unavailable hosted patch inference. Current internal fixture results are not standard benchmark scores.
- Benchmark selection has been refreshed: Vul4Py is the leading Python paired-oracle candidate, but the located repo's provenance/terms are unconfirmed and its runner is not safe to execute under the current boundary; see OQ-008. VulnGym v0.1.4 remains a repository-localization candidate (408 entries, 393 human-audited, CC-BY-4.0), but its evaluator reports recall/coverage only. Neither has been run by Aegis.
- VulnGym evaluator compatibility was checked at upstream commit `cd69f7e163e08485ab5496115ae03439cda6e27e` using metadata only: the official matcher failed to match 44 documented range-line entries even when predictions copied the ground truth, yielding 364/408 entries and 171/184 advisories on this oracle sanity input. This is not an Aegis score; see the machine-readable diagnostic linked from `BENCHMARKS_AND_DATASETS.md`.
- Added a typed JSONL parser and supplemental range-aware VulnGym metric/CLI; it is explicitly marked non-official, never reports precision for the recall-only dataset, and does not fetch or execute benchmark repositories.
- Current rerun before range-service hardening: **462 unit tests passed**; Docker integration **20 passed, 1 credential-gated hosted-model skip** (141.53 seconds). The supplemental evaluator's ground-truth-copy self-check matches 408/408 entries, including all 44 range-form entries; this is a parser/matcher self-check, not an agent score.
- Latest range-service hardening rerun: **478 unit tests passed**; Ruff check, 208-file format check, strict mypy (175 source files), 18 schemas, and `git diff --check` passed. Docker integration: **20 passed, 1 credential-gated hosted-model test skipped** (128.86 seconds). This verifies local range compatibility, not hostile-container isolation.

## Next implementation priorities

- [x] Latest continuation: validate local range service configuration and container names before launch, stop, log, or inspect Docker operations. Focused service tests **29 passed**; full unit suite **478 passed**; static/schema checks passed; Docker integration **20 passed, 1 skipped**.

### P0 — Close this session safely

- [x] Verify audit event content digests and chain links in memory; add tamper-detection assertions. (Export CLI/durable anchor remain open.)
- [x] Add a receipt factory from terminal transaction snapshots; it rejects labeling `EXECUTED` as committed.
- [x] Wire final receipt emission/audit-root linkage into a real verifier-driven transaction coordinator.
- [x] Add current progress/worklog snapshot, refresh README/handoff status, and verify no credential value was added to the repository.
- [x] Run unit, lint, type, schema, and Docker integration checks; preserve results and limitations.

### P1 — Make transaction semantics real

- [x] Add transaction coordinator for approval, execution, independent verification, commit, rollback, escalation, and control failure. Staging is not yet used by the broker path.
- [x] Refactor containment/containment-rollback mutations out of injected orchestrator callbacks into typed broker actions.
- [x] Route the current path-traversal range deployment/build and rollback through typed broker actions with independent postcondition/rollback verification.
- [x] Add first-class deployment and rollback action records and test broker-only mutation paths for the current range.
- [ ] Generalize beyond the fixed path-traversal range adapter and audit all workflows for hidden effects.
- [x] Add verifier protocol for typed postconditions; preserve clean-room repair verifier separation.
- [x] Add exact acceptance pair against real Docker: containment blocks attack and preserves benign traffic => commit; intentionally overbroad test-only containment breaks availability => brokered rollback and independent restoration checks.

### P2 — Generalize the reusable runtime

- [x] Establish a tested core package boundary: core has no imports from cyber-specific range, orchestration, telemetry, tool, provider, worker, repair, or verifier packages.
- [x] Add versioned typed action definitions describing inputs/outputs, risk, side effects, reversibility, resources, and expected verification; bind the catalog to adapter registration and enforce request/output contracts in the broker. Expected verifier identity is enforced; action-specific resource caps/retries remain follow-up gaps.
- [x] Add versioned/schema-exported domain-neutral sandbox request/result models and move one-shot analysis-worker Docker execution behind the protocol.
- [ ] Migrate range service/network/deployment lifecycle onto an appropriate backend interface; do not claim unavailable backends.
- [x] Add stable per-case audit JSONL export/verification and document that local hash chains are tamper-evident, not immutable/authenticated. The audit source remains in-memory and no signing/anchor is provided.
- [x] Add receipt generation linked to transaction, verifier evidence artifacts, and audit root (in-memory audit/artifact stores remain non-durable).
- [x] Add transaction/capability schemas and contract tests to CI; the test suite asserts both contracts are registered and CI runs the schema-parity test.

### P3 — Strengthen the cyber-defense reference application

- [x] Integrate evidence correlation into the live case orchestrator; brokered Semgrep scan plus same-case telemetry/provenance are mandatory before containment.
- [ ] Generalize durable retrieval for every event, normalized finding, and deployment-provenance reference (current store is in-memory).
- [x] Add a model-patch pilot selectable for two fixture-specific allowlisted files; no model execution/deployment authority was added. Corrected-key qwen38 inference ran on both fixtures; one candidate verified and one no-op was rejected.
- [x] Generalize `scripts/bench_patch_repair.py` with explicit fixture selection and verify the second fixture's clean-room oracle pair; this remains a Layer-0 owned-fixture pilot, not a standard benchmark.
- [x] Obtain working local endpoint configuration and run the Layer-0 generated-patch pilot through the clean-room verifier; results are fixture-specific and mixed (one verified, one rejected before verification).
- [ ] Run an external standard repair/agent benchmark with a valid harness and report an official metric; do not infer this from the two local fixtures.
- [x] Add a second owned synthetic scenario fixture, isolated vulnerable-baseline reproduction, and clean-room acceptance/rejection oracle pair.
- [x] Generalize evidence collection and brokered response so the object-authorization scenario can run through the tested case lifecycle; broader durable/cross-source retrieval remains open.
- [x] Add first adversarial prompt-injection/control tests for denied high-impact proposals; broader poisoned-source/log/tool-output cases remain open.
- [x] Add synthetic Layer-0 repair-pilot reporting for capability, control/safety, and efficiency independently. A general multi-benchmark/AegisBench runner remains unimplemented.
- [x] Locate and statically preflight candidate Vul4Py artifact: `tabudz/vul4py` at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`; no declared license and no link from primary paper/publication page found; harness contains host-side `shell=True` setup/test execution and dynamic repository clones. No code/data was run or downloaded.
- [ ] Confirm artifact provenance and code/data terms with primary authors; design a compliant isolated paired-oracle runner or select an alternative. Current rootful Docker-only host is not accepted for untrusted project builds.
- [ ] Add a VulnGym-compatible repository detection/localization path and official-schema prediction export; keep recall-only interpretation explicit.
- [ ] Produce real Aegis predictions for VulnGym; current code only validates inputs and computes supplemental metadata-only metrics.
- [x] Diagnose official line-range mismatch and implement a separately labelled range-aware evaluator; do not modify the upstream evaluator or present oracle checks as agent scores.
- [x] Add a versioned benchmark-run contract and wire the hosted repair pilot to emit capability, control/safety, and efficiency axes independently; unavailable values remain null with reasons, and no composite score is calculated. This currently covers the synthetic Layer-0 repair pilot only.
- [x] Verify the corrected `.env.local` credential with one synthetic qwen38 smoke request; the structured proposal passed schema and adapter-allowlist validation without switching aliases.
- [x] Run qwen38 repair pilots on both owned scenarios under the initial diff and replacement-source protocols. The first two diffs were rejected as malformed; replacement-source v2 verified the object-authorization patch, while its path-traversal response was unchanged and rejected before verification. These are four fixture attempts, not standard benchmark scores.

### P4 — Research and community readiness

- [ ] Evaluate on licensed external patch/defense datasets with reproducibility metadata.
- [x] Add a behavioral trajectory-monitor baseline; keep it advisory, never authoritative. Calibration and prediction experiments remain open.
- [ ] Build labeled trajectories and calibrate/compare monitor baselines; do not use current score thresholds as performance evidence.
- [ ] Decide whether hidden-state monitoring is a first-year research goal.
- [ ] Select public name, license, contributor policies, and release cadence with owner input.
- [ ] Consider Rust trusted-core extraction only after transaction/runtime boundaries stabilize.

## Guardrails

- The A100 API may receive synthetic range context only under the current owner decision. No private source, real telemetry, credentials, or personal data.
- Keep `qwen38` warm; do not switch model aliases just to compare them.
- Hosted calls stay out of default tests/CI; the stub/replay provider is deterministic default.
- No arbitrary model-generated shell, public-target scanning, host Docker socket exposure to reasoning, or production credentials.
- Broker `EXECUTED` is not `VERIFIED` or `COMMITTED`. Do not conflate these states.
