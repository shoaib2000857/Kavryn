# Threat model

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

| ID | Threat | Consequence | Primary mitigations | Validation |
| --- | --- | --- | --- | --- |
| T01 | Prompt injection in source/logs | Agent follows attacker text | Data/instruction separation, structured context, action policy | Injection corpus and canary requests |
| T02 | Raw command injection | Host/worker compromise | Typed adapters, no raw shell field, strict parsers | Fuzz request schemas |
| T03 | Sandbox escape | Host or control compromise | Rootless isolation, no host socket, later microVMs, patched runtimes. **Interim exception (2026-09-03, ADR-023):** the Change 5 analysis worker runs on standard rootful Docker, not rootless — a container escape currently has host-root consequences, not just unprivileged-user consequences. Accepted by the owner, scoped to local low-risk static-analysis fixtures only; not accepted for dynamic validation or hostile-input worker classes. | Escape-oriented review and canaries |
| T04 | Transitive egress | Unauthorized internet access through support service | Independent network policy for every service, default deny, destination pinning | DNS/proxy/artifact-store escape tests |
| T05 | Shared identities/state | Agents coordinate or inherit authority | Per-worker identities, isolated workspaces, capability binding | Cross-worker access tests |
| T06 | Credential exposure | Target/provider compromise | Brokered short-lived secrets, context redaction, no ambient creds | Secret canaries and log scanning |
| T07 | Audit tampering | False narrative and lost forensics | Out-of-band append-only sink, hashes, agent no-delete | Tamper and truncation tests |
| T08 | Verifier contamination | False patch acceptance | Clean-room rebuild, hidden tests, immutable evaluator inputs | Attempted test/ground-truth access |
| T09 | Test gaming | Patch special-cases visible tests | Hidden tests, property tests, behavioral replay, diff review | Adversarial patch fixtures |
| T10 | Unsafe containment | Availability loss or broader outage | Risk tiers, predicted effect, rollback, approval. **Change 7 (2026-09-06, ADR-029):** the first concrete reversible-containment primitive — a fixed reviewed proxy applying deny-query rules — verified to block the attack while preserving benign traffic, and to fully restore original behavior on rollback. | Fault injection and rollback tests; `tests/integration/test_runtime_range.py` (real containment + rollback against a live service) |
| T11 | Model/provider compromise | Malicious proposals or data loss | Provider-neutral adapter, response validation, minimal context, data policy | Fault/malicious-response injection |
| T12 | Tool-output poisoning | Bad downstream decisions | Treat output as untrusted, adapter parsing, provenance, corroboration | Parser and poisoned-output tests |
| T13 | Denial loop | Exhausted compute/cost and delayed response | Budgets, bounded retries, circuit breakers | Non-terminating-tool simulations |
| T14 | Scope ambiguity | Action affects wrong target | Canonical target IDs, fail closed, explicit resolution | Similar-name/confusable tests |
| T15 | Supply-chain compromise | Malicious images/packages/tools | Pinned digests, SBOM, signature/provenance checks | Image substitution test |
| T16 | Excessive autonomy | Irreversible unauthorized change | Action broker, approval gates, deny R5 | Policy conformance suite |
| T17 | Evidence exfiltration | Sensitive data reaches external model | Redaction, local routing, egress policy, classification | Canary and DLP tests |
| T18 | False incident hypothesis | Wasted or harmful response | Competing hypotheses, evidence references, uncertainty, approval | Noisy benign scenarios |

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

**Runtime range network path (Change 7, 2026-09-06):** the range's app container is never given a published port (only reachable from the proxy, over the range's own isolated Docker network); the proxy container publishes exactly one port, bound to `127.0.0.1` in the current test harness. This is a new network path introduced by this change and is scoped to local, ephemeral, per-test-run ranges — it is not a general statement about how a longer-lived or multi-case range's network topology should look, which remains for a later change to design if the project moves beyond one fixture at a time.

**Rootful Docker (accepted 2026-09-03, ADR-023, OQ-006):** the Change 5 isolated analysis worker uses standard rootful Docker rather than the rootless backend ADR-012 calls for, because rootless Docker is not available in the current implementation environment. This is an explicit, owner-accepted, scoped exception — local low-risk static-analysis fixtures only — not a general downgrade of the isolation posture. It must be revisited (rootless Docker, or progression to gVisor/Kata/microVM per ADR-012) before any worker class handling dynamic validation, exploit replay, or untrusted/hostile input is built.

No sandbox or monitor establishes perfect containment. Containers reduce operational risk but are not a sufficient sole boundary for hostile native code and powerful long-horizon agents. Model-based monitors can also be bypassed and may have high false-positive rates. The design therefore relies on layered deterministic authority limits and treats monitor scores as additional evidence, not the root of trust.

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
