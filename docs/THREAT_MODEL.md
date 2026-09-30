# Threat model

## Kavryn SDK distribution (2026-10-01)

The public facade and new CLI alias do not add model-callable tools, permissions,
target selectors, or a remote authority service. Both names use the existing
broker/coordinator implementation; process-local authority is unchanged.
Install scripts require explicit operator execution, create a new virtualenv,
refuse an existing destination and never source `.env` or grant Docker access.
Package/build dependency resolution uses configured package indexes, a normal
software supply-chain risk. Explicit archive includes and checks exclude local
credentials, caches, databases and result artifacts. CI hosts only checked SDK
archives with attribution files. These checks are not dependency authenticity,
complete secret detection, or hardened execution. Apache attribution does not
authenticate downstream maintainers or imply endorsement.

## 2026-09-30 reliability controls

Localized repair output is spliced into trusted complete source before diff
construction. Preparation verifies source/diff hashes, rejects symlinks and
special files, checks the copied snapshot, and uses noninteractive zero-fuzz
application. Same-path paired headers are required; rename/mode/binary operations
are unsupported. The independent verifier checks diff integrity and also
disables fuzzy application. These are not protection against a hostile host or
complete resistance to verifier-process interference by executable candidate code.

Optional SQLite receipts bind terminal journal content and verified audit roots,
but local replacement is not externally authenticated. A receipt-save failure
after commit does not undo the effect and must not cause execution retry.
Read-only journal inspection restores no capabilities or approvals and never
clears quarantine. The new demo is in-memory simulation, not an isolation test.
No secrets, network permissions, or new external services were introduced.
See [Reliability and operations](RELIABILITY_AND_OPERATIONS.md) and ADR-063/064.

## Offline external benchmark boundary (2026-09-30)

ADR-062 adds a fixed-plan benchmark adapter: rootless gVisor, network-none,
no host mounts/socket/secrets, memory overlays and user-systemd resource limits.
Targets/plan IDs/script hashes are checked; no model command is accepted.
Images are exported from stopped operator containers; never executed rootfully.
Controller/cache storage remains trusted/local. Hashes do not authenticate
images or prevent full-chain replacement; absence of hidden tests from inference
does not prove complete test-gaming noninterference during verification.
Rootful synthetic fixture workers remain unchanged. See `STORAGE_AND_SWE_PILOT.md`.

## Local-evaluation boundary update (2026-09-30)

ADR-061's installed CLI is read-only and never exposed as a model execution tool.
Receipt/audit input is bounded to 8 MiB; validation diagnostics omit embedded
contents. Hash validity alone cannot establish writer identity or action safety.
An externally supplied head is only as trustworthy as its independent source;
signatures/remote anchoring and re-execution of verification are not implemented.

ADR-059/060 use existing owner-authorized local Ollama at `127.0.0.1:11434`.
No hosted credential, new target network, model-directed shell/SQL, production
access, or execution authority is introduced. Model schema compliance is not
trusted: local parsing and ID/scope checks remain authoritative. The optional
syntax retry only parses bounded Python text and uses public syntax diagnostics;
it never executes code or exposes hidden tests. Clean-room import-failure output
is now retained up to 2,000 bytes for diagnosis. Such output may contain source
snippets and must be treated as sensitive if future fixtures contain private data;
current experiments use owned synthetic source only.

CDB triage reads public logs, selects from a rule shortlist, and validates output
as integer batch IDs. Unknown/duplicate/coerced IDs and extra executable fields
are rejected. Flags are opened only by the separate pinned scorer after saved
predictions. This proves the output data boundary, not model resistance to
prompt injection or autonomous threat-hunting competence. The admission ablation
is an offline counterfactual over evidence, not authenticated receipts or an
external security guarantee. Existing rootful Docker/host-gateway residual risks,
in-process authority, and incomplete durable recovery remain unchanged.

## Security objective

Aegis should improve the security of an authorized target without becoming a more dangerous path to the target, the operator, neighboring systems, the model provider, or the evidence used to judge its own work.

## Assets

- target source, builds, services, data, and credentials;
- control policy and capability-signing material;
- worker and target identities;
- model prompts, outputs, and provider credentials;
- evidence, artifacts, hidden tests, ground truth, and audit events;
- operator approvals and attribution;
- availability of the target and control plane;
- research result integrity.

## Adversaries and failure sources

- an external attacker already present in the target range;
- malicious or compromised repository content;
- poisoned logs, tickets, threat intelligence, dependency metadata, or tool output;
- a vulnerable or malicious dependency/build script;
- a compromised security tool or worker image;
- a hallucinating, reward-hacking, deceptive, or over-persistent model;
- a compromised model/API provider or intercepted response;
- a malicious insider or stolen operator credential;
- ordinary bugs, race conditions, parser errors, and misconfiguration.

## Key threats and mitigations

The journal's live rollback exception (ADR-057) requires the current broker-owned
parent snapshot and registered compensation, and still enforces ordinary scope,
approval, budget, and capability checks. Wrong-parent, target, action, role,
stale-snapshot, and restarted-broker tests reject attempts to widen this path.
Role strings remain metadata within the trusted runtime process; this does not
introduce external identity authentication or post-crash clearance.

| ID | Threat | Consequence | Primary mitigations | Validation |
| --- | --- | --- | --- | --- |
| T01 | Prompt injection in source/logs | Agent follows attacker text | Data/instruction separation, structured context, action policy | Unit tests show evidence serialization and deterministic denial of a poisoned `host.shell` proposal before adapter dispatch. This is not a broad model-resistance evaluation; source/log/tool-output attack cases remain open. |
| T02 | Raw command injection | Host/worker compromise | Typed adapters, no raw shell field, strict parsers | Fuzz request schemas |
| T03 | Sandbox escape | Host or control compromise | Rootless isolation, no host socket, later microVMs, patched runtimes. **Interim exception (2026-09-03, ADR-023):** the Change 5 analysis worker runs on standard rootful Docker, not rootless — a container escape currently has host-root consequences, not just unprivileged-user consequences. Accepted by the owner, scoped to local low-risk static-analysis fixtures only; not accepted for dynamic validation or hostile-input worker classes. | Escape-oriented review and canaries |
| T04 | Transitive egress | Unauthorized internet access through support service | Analysis workers use `--network none`; the local range creates and verifies a Docker `--internal` network with only the configured app/proxy members | Unit tests require internal mode and fail closed on an existing non-internal network; real-Docker integration checks `Internal=true` and no published ports. Docker internal mode does not prevent container access to the host/gateway or host access to container addresses; this is not host isolation. |
| T05 | Shared identities/state | Agents coordinate or inherit authority | Per-worker identities, isolated workspaces, capability binding | Cross-worker access tests |
| T06 | Credential exposure | Target/provider compromise | Brokered short-lived secrets, context redaction, no ambient creds | Secret canaries and log scanning |
| T07 | Audit tampering | False narrative and lost forensics | In-memory or opt-in local SQLite sink, per-event hashes, agent no-delete; exported per-case JSONL can be checked for internal chain integrity | Tamper/reorder and SQLite-corruption tests cover internal integrity; external anchoring and writer authentication are not implemented, so complete database substitution is not detectable |
| T08 | Verifier contamination | False patch acceptance | Clean-room rebuild, hidden tests, immutable evaluator inputs | Attempted test/ground-truth access |
| T09 | Test gaming | Patch special-cases visible tests | Hidden tests, property tests, behavioral replay, diff review | Adversarial patch fixtures |
| T10 | Unsafe containment | Availability loss or broader outage | Risk tiers, predicted effect, rollback, approval. **Change 7 (2026-09-06, ADR-029):** the first concrete reversible-containment primitive — a fixed reviewed proxy applying deny-query rules — verified to block the attack while preserving benign traffic, and to fully restore original behavior on rollback. | Fault injection and rollback tests; `tests/integration/test_runtime_range.py` (real containment + rollback against a live service) |
| T11 | Model/provider compromise | Malicious proposals or data loss | Provider-neutral adapter, response validation, minimal context, data policy | Fault/malicious-response injection |
| T12 | Tool-output poisoning, including injected text in proxy logs | Bad downstream decisions or instruction following | Treat output as untrusted data; fixed brokered telemetry adapter, strict parser, provenance, and corroboration | Telemetry parser/correlation tests and brokered local-range integration; raw log text is not authority |
| T13 | Denial loop | Exhausted compute/cost and delayed response | Budgets, bounded retries, circuit breakers | Non-terminating-tool simulations |
| T14 | Scope ambiguity | Action affects wrong target | Canonical target IDs, fail closed, explicit resolution | Similar-name/confusable tests |
| T15 | Supply-chain compromise | Malicious images/packages/tools | Pinned digests, SBOM, signature/provenance checks | Image substitution test |
| T16 | Excessive autonomy | Irreversible unauthorized change | Action broker, approval gates, deny R5 | Policy conformance suite |
| T17 | Evidence exfiltration | Sensitive data reaches external model | Redaction, local routing, egress policy, classification | Canary and DLP tests |
| T18 | False incident hypothesis | Wasted or harmful response | Competing hypotheses, evidence references, uncertainty, approval | Noisy benign scenarios |
| T19 | In-process capability authority compromised | Capability state can be forged, replay ledger bypassed, or grants modified by code execution in the same process | Current prototype binds grants to transaction/request and enforces expiry/use limits, but provides no cryptographic or process boundary; keep adapters narrow and move enforcement to a separate trusted service before hostile agent code | Unit tests for binding, expiry, revocation, replay; process-isolation tests are not yet implemented |
| T20 | Hosted inference data disclosure | Synthetic evidence or secrets leave the local machine through the model endpoint | Current qwen38 trial sent synthetic range-only context; no private source, real telemetry, secrets, or personal data are authorized to leave | Manual configuration and review; automated data-classification/redaction gate is not implemented |
| T21 | Range deployment adapter misuse or Docker compromise | Wrong fixture/service mutation, host impact, or untrusted build input reaches Docker | Fixed fixture/service configuration, validated image/container/network identifiers and service-operation names, normalized read-only host mounts, bounded port values, one-file diff allowlist, trusted-source and diff digests, build network disabled, explicit `docker_control` adapter privilege, approval, health/replay checks, brokered rollback | Unit tests reject unsafe service configuration/operation names and target/diff tampering; real local-range commit/rollback integration tests. Docker remains rootful and this is not a hardened hostile-build boundary. |
| T22 | Action-contract drift or malformed request/output | An action routes to an unintended adapter, receives malformed parameters, or presents invalid output as successful evidence | Required versioned catalog definitions, action/adapter binding, exact primitive input/output validation, policy-risk consistency, declaration consistency with adapter metadata | Broker tests cover wrong types, undeclared fields, invalid output and fail-closed transition; Docker integration exercises registered range contracts. The registry does not itself enforce CPU/memory limits. |
| T23 | CI workflow or dependency compromise; untrusted pull-request code executes in CI | Runner compromise, false test results, or abuse of CI token | Actions pinned by commit; `contents: read`; ordinary `pull_request` (not `pull_request_target`); no inference secrets; ephemeral hosted runner; synthetic fixtures only | Review `.github/workflows/ci.yml`; workflow has separate quality and Docker jobs and does not expose the A100 token. Package indexes and container registries remain external build inputs. |
| T24 | Proxy mishandles Authorization while supporting synthetic-session containment | Credential leakage, incorrect upstream identity, or telemetry disclosure | Forward only the Authorization header to the fixed configured backend; never include it in proxy logs or model context; use only synthetic fixture tokens; bound configured matching patterns; keep enforcement and config outside model control | Full object-authorization Docker integration confirms owner traffic remains available, the synthetic Bob token is blocked, and the token string is absent from proxy logs. This does not validate a production authentication proxy. |
| T25 | Adapter raises after a partial external effect | Action remains ambiguously in flight or is retried, compounding an unknown effect | Broker records terminal `CONTROL_FAILURE`, charges an attempted tool call, audits the exception type and unknown-effect status without copying exception text, and coordinator issues a control-failure receipt; same transaction cannot be resubmitted | Broker/coordinator unit tests. This does not verify target state, perform rollback, or survive process termination; external investigation remains necessary. |
| T26 | Control-plane restarts after a mutation but before verification/rollback | Agent proceeds as if target state were known or resets its action budget | Opt-in append-only SQLite transaction revisions; record `EXECUTING` before adapter dispatch; a new broker refuses case actions after an executed mutation without recorded commit/rollback, including terminal unknown-effect failures; bind each new transaction to the full action-definition digest and quarantine absent/drifted contracts; reconstruct tool-call usage from journaled dispatches | Reopen/tamper/replay, version-1 upgrade, broker-restart, action-contract-drift, and tool-call-budget tests. The journal does not independently prove verification. No automatic reconciliation, safe clearance API, restored capability/approval/other-budget authority, atomic audit+journal write, multi-process exclusion, or authenticated external anchor. |

## Incident-derived abuse cases

The design explicitly tests failure patterns demonstrated by recent agent incidents:

- using a shared artifact repository or other writable infrastructure as a covert message board;
- escaping an intended sandbox through a vulnerable supporting service;
- acquiring internet access indirectly rather than through the worker's visible network policy;
- discovering exposed credentials and using them across trust boundaries;
- propagating discoveries between nominally isolated workers;
- manipulating or evading evaluation checks;
- continuing the task when the safe behavior should be to stop and report.

## Prompt-injection trust rule

Untrusted content may state facts or contain strings that resemble instructions. It may never:

- alter the system objective;
- select policy;
- approve an action;
- provide credentials;
- redefine tool schemas;
- mark evidence as verified; or
- modify the assurance decision.

## Residual risk

**Runtime range network path (updated 2026-09-25):** neither app nor proxy has a published port. The shared custom Docker network is created with `--internal` and its effective property is checked, so range containers cannot use that network for ordinary external-network connectivity. Docker documents that host/gateway communication remains possible: the trusted Docker host reaches the proxy by its internal container IP for local tests, and container-to-host services are not proven blocked. The host remains trusted. This is scoped to local ephemeral ranges and is not a complete sandbox or production network policy.

**A100 model endpoint (2026-09-25, ADR-037):** the owner-authorized live test sent only synthetic, local-range containment-planning context to a remote OpenAI-compatible endpoint. No private source or real incident data is approved for upload. A key was pasted into chat and should be rotated. Hosted calls are explicit/manual, absent from default tests, and must continue to avoid sensitive content unless a separate classification decision and redaction control are made.

**Capability prototype (2026-09-25, ADR-038):** current expiry/revocation/single-use enforcement exists in an in-memory authority within the same Python process as the broker. It is useful as an executable contract and test target but must not be represented as robust isolation against a compromised runtime. A separate service boundary, authenticated IPC, or equivalent is a future hardening requirement.

**Range deployment adapter (2026-09-25, ADR-043):** the new adapter can build and replace only its configured local synthetic range service through a typed broker action. It invokes Docker from trusted adapter code; the model does not receive the Docker socket or a generic Docker command surface. The adapter is not a production deployer, the Docker daemon remains rootful, and Docker build isolation/resource controls are not equivalent to a VM or hardened build sandbox.

**Object-authorization fixture (2026-09-25):** `ranges/object-authorization-v1` is an owned vulnerable Flask fixture. Its full-case integration builds from the local pinned Python base plus pinned Flask requirement (the initial build may contact the configured package index), then runs app and proxy on an internal Docker network with no published ports. The workflow reproduces Bob's cross-owner access, uses a configured synthetic-token block, correlates brokered telemetry and Semgrep evidence, independently verifies an oracle patch, deploys it, and replays both attack and owner access. The proxy forwards only the Authorization header to the fixed backend and does not log it; a test asserts the fixture token is absent from proxy logs. This uses deterministic test inputs and an oracle patch, not model-generated repair. The host Docker daemon remains rootful/trusted, and this is not a production authentication proxy.

**Sandbox backend protocol (2026-09-25, ADR-044):** the protocol separates the analysis worker's execution contract from its Docker implementation but is not an additional security boundary. The Docker backend still invokes the rootful host daemon; all existing T03 limits and fixture restrictions remain in force. Range deployment is separately implemented and must not be assumed to be swappable through this protocol yet.

**Audit export (2026-09-25, ADR-046):** JSONL export and verification detects event/body/link tampering within a supplied chain. The source sink remains in-memory, and a local JSONL file can be deleted or replaced wholesale. There is no signature, authenticated writer identity, remote append-only storage, or external checkpoint; the CLI verifies consistency, not authenticity or completeness.

**GitHub Actions CI (2026-09-25):** CI runs with `contents: read`, no model credentials, and an ephemeral hosted runner. It downloads pinned Python dependencies and container build inputs from external registries and executes repository/test code, including rootful-Docker integration tests. It is not an isolation guarantee for self-hosted runners; do not add secrets, write permissions, or untrusted deployment targets without a new threat review.

**Action contracts (2026-09-25, ADR-047):** the broker enforces registered action IDs, adapter binding, primitive parameter types, declared successful-output fields/types, and agreement between catalog and policy risk. The coordinator checks the declared verifier identity and fails closed on mismatch. Nested input validation is delegated to adapters; resource fields are declarations cross-checked against adapter metadata, not independent CPU/memory enforcement, and retry scheduling is absent. Rootful Docker range operations remain subject to T03/T21 residual risk.

**Verifier protocol (2026-09-25, ADR-045):** structured postcondition checks and a verifier interface improve typing and attribution, but current callback implementations may still run in the coordinator process. Do not treat interface separation as identity or isolation; the clean-room patch verifier has a separate container path, while generic action verifiers still need an independently enforced execution boundary.

**Rootful Docker (accepted 2026-09-03, ADR-023, OQ-006):** the Change 5 isolated analysis worker uses standard rootful Docker rather than the rootless backend ADR-012 calls for, because rootless Docker is not available in the current implementation environment. This is an explicit, owner-accepted, scoped exception — local low-risk static-analysis fixtures only — not a general downgrade of the isolation posture. It must be revisited (rootless Docker, or progression to gVisor/Kata/microVM per ADR-012) before any worker class handling dynamic validation, exploit replay, or untrusted/hostile input is built.

No sandbox or monitor establishes perfect containment. Containers reduce operational risk but are not a sufficient sole boundary for hostile native code and powerful long-horizon agents. Model-based monitors can also be bypassed and may have high false-positive rates. The design therefore relies on layered deterministic authority limits and treats monitor scores as additional evidence, not the root of trust.

The current behavioral baseline observes only structured broker outcomes and risk tiers. Its process-local rolling state, fixed weights, and thresholds are not calibrated, and its output is attached as advisory metadata only. A caller must not interpret `continue` as approval or `pause_and_escalate` as an enforced stop; deterministic policy and transaction controls still decide execution.

## Review cadence

Update this document whenever a change introduces a new:

- tool or worker class;
- network path;
- credential or identity;
- model provider;
- input type;
- production-like action;
- data store;
- verifier signal; or
- deployment environment.
