# MVP and roadmap

## MVP thesis

Build one narrow but complete incident-to-patch vertical slice before adding languages, tools, agents, databases, or a dashboard.

## MVP scenario

An isolated Python web service contains a path-traversal vulnerability. A controlled attacker replays a request while benign traffic and noisy logs are present.

Aegis must:

1. ingest structured application, proxy, and container events;
2. detect suspicious file access and form an evidence-linked hypothesis;
3. propose and, after approval, apply a reversible range-only containment rule;
4. verify that the malicious request is blocked while benign traffic remains available;
5. trace the deployed artifact to a pinned repository commit and vulnerable handler;
6. generate a minimal patch in a disposable workspace;
7. pass clean build/load, public tests, original attack replay, hidden security tests, benign workload replay, Semgrep/Bandit re-scan, and diff policy;
8. request deployment approval;
9. deploy a clean image, remove temporary containment when safe, and replay the attack;
10. monitor for recurrence; and
11. export the assurance bundle and audit timeline.

## MVP non-goals

- public target scanning;
- production deployment;
- multiple languages;
- general malware analysis;
- automated IAM or credential rotation;
- broad fuzzing infrastructure;
- a multi-agent swarm;
- a web dashboard;
- GLM-5.2 self-hosting in Colab;
- formal security proof.

## MVP acceptance criteria

### Capability

- Correctly identifies the affected service and vulnerable handler in at least the project fixture.
- Every incident claim links to evidence IDs.
- Containment has before/after availability and attack results.
- The candidate patch is minimal and passes all clean-room checks.
- Recovery replay demonstrates malicious failure and benign success.

### Control

- No model-to-shell path exists.
- All tool calls cross the action broker and appear in the append-only audit.
- Out-of-scope path and network requests are denied.
- Worker identities/capabilities cannot be reused across cases.
- The agent cannot read hidden tests or modify verifier/policy/audit data.
- Prompt injection in logs/source does not change authority or workflow objective.
- Emergency stop revokes active capabilities and terminates workers.

### Reproducibility

- One documented command starts the range and case.
- Images, source, rules, tests, model configuration, and policy are pinned.
- The case can run with a replay/stub model for deterministic CI.
- A real-model run records provider/model/version and all non-secret configuration.

## Twelve-week research build

### Weeks 1–3: control foundation

Deliver:

- Python package and typed domain schemas;
- case/scope service;
- explicit workflow engine;
- policy and action broker;
- content-addressed artifact store;
- append-only audit abstraction;
- rootless no-network worker;
- stub/replay model provider.

Exit criterion: control conformance tests pass without a live LLM.

### Weeks 4–5: repository repair loop

Deliver:

- vulnerable Python fixture and public/hidden tests;
- source/profile adapter;
- Semgrep/Bandit and pytest adapters;
- patch candidate schema/application;
- clean-room verifier and assurance decisions;
- initial hosted GLM adapter.

Exit criterion: evidence-carrying repair succeeds, rejects an exploit-preserving patch, and rejects a regression-inducing patch.

### Weeks 6–8: runtime incident loop

Deliver:

- instrumented service and benign/attack generators;
- normalized telemetry ingestion with OCSF mapping;
- incident hypothesis and timeline model;
- reversible containment adapter;
- containment verification;
- build/deployment-to-source provenance.

Exit criterion: the system goes from noisy telemetry to verified range containment and correct source candidate.

### Weeks 9–10: recovery loop

Deliver:

- clean image rebuild;
- approval-gated range deployment;
- attack and benign workload replay;
- rollback and recurrence monitor;
- human-readable and JSON case reports.

Exit criterion: a full incident-to-recovery run completes with auditable evidence.

### Weeks 11–12: adversarial evaluation

Deliver:

- prompt/tool-output injection suite;
- scope/egress/identity/audit/verifier attack cases;
- behavioral monitor baseline;
- capability, safety, and efficiency metrics;
- experiment report and limitations.

Exit criterion: results include failures and confidence intervals, not only a demo.

## Expansion roadmap

### Phase 2 — External repair benchmarks

- Vul4J adapter;
- small pinned PatchEval subset;
- C/C++ worker with sanitizers;
- AutoPatchBench sample adapter;
- repair ablation study.

### Phase 3 — Richer runtime defense

- Windows/Linux/cloud/Kubernetes telemetry adapters;
- OTRF/Splunk range scenarios;
- ATT&CK/D3FEND coverage;
- credential/session containment in synthetic identities;
- multi-service blast-radius analysis.

### Phase 4 — AegisBench v0.1

- 3–5 end-to-end scenarios;
- hidden evaluator service;
- standardized observation/action API;
- capability/control/efficiency scoring;
- baseline agents and reproducibility bundle.

### Phase 5 — Model/control research

- hosted vs self-hosted GLM comparison;
- hybrid model routing;
- trajectory monitor;
- hidden-state probe study on an open model;
- monolithic vs specialized-agent experiment.

### Phase 6 — Hardened research deployment

- gVisor/Kata or microVM workers;
- external policy engine if justified;
- object-store integrity/versioning;
- formal operator approval service;
- dashboard only after stable APIs.

## Stop/go gates

Do not advance to the next phase when:

- control conformance is below the phase threshold;
- the benchmark cannot distinguish agent and infrastructure failure;
- the verifier shares mutable state or identity with the patch worker;
- results cannot be reproduced from pinned artifacts;
- the new phase needs permissions not covered by the threat model;
- the current phase has no written failure analysis.
