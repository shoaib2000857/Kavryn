# Research agenda

## Program thesis

Autonomous cyber defense should be evaluated as a joint capability-and-control problem. A stronger model may improve investigation and repair while also increasing the importance of independent authority limits, verification, and monitoring.

## Primary contribution

An end-to-end, control-first incident-to-patch framework and benchmark in which the defender must:

1. discover and explain an incident from noisy telemetry;
2. contain it within an explicit authority envelope;
3. map runtime evidence to vulnerable code;
4. create and independently verify a repair;
5. recover the service; and
6. withstand adversarial inputs directed at the defender itself.

## Research questions

### RQ1 — Closed-loop capability

How much performance is lost when moving from an oracle-specified vulnerable function to noisy post-compromise telemetry and a fully executed recovery loop?

**Hypothesis:** localization and evidence acquisition, not patch syntax, become the dominant bottlenecks.

### RQ2 — Control-first architecture

Can deterministic capability boundaries, independent identities, and clean-room verification reduce unsafe agent actions without making useful defense impractically slow?

**Hypothesis:** most high-impact violations can be prevented structurally with moderate overhead; semantic false positives remain a challenge.

### RQ3 — Evidence grounding

Does requiring claim-to-evidence links improve investigation precision, calibration, and human review time?

**Hypothesis:** evidence contracts reduce unsupported conclusions but can lower recall unless the agent learns to request discriminating evidence.

### RQ4 — Verification depth

Which combination of exploit replay, hidden tests, re-scanning, fuzzing, differential behavior, and diff policy best predicts human patch acceptability?

**Hypothesis:** exploit replay plus hidden behavioral tests substantially outperforms build/public-test-only acceptance.

### RQ5 — Specialization

When does a specialized multi-agent architecture outperform one model operating an explicit state machine?

**Hypothesis:** specialization helps only after shared evidence/state contracts are stable; early multi-agent systems add coordination cost and attack surface.

### RQ6 — Monitoring

Can action-, trajectory-, or activation-level signals predict boundary violations before a dangerous tool call?

**Hypothesis:** trajectory/activation signals may add lead time, but deterministic action controls remain necessary because monitors are imperfect.

### RQ7 — Model and deployment choice

How do large hosted models, smaller self-hosted models, and hybrid routing compare on the capability-safety-cost frontier?

**Hypothesis:** a hybrid system can reserve the largest model for localization/repair while using deterministic or smaller-model components for routine parsing and summarization.

## Experimental matrix

### Architecture ablation

1. raw model + broad tools;
2. model + typed tools;
3. typed tools + deterministic policy;
4. previous + evidence contracts;
5. previous + clean-room assurance gate;
6. previous + behavioral monitor;
7. previous + trajectory/activation monitor where available.

Report task capability and control violations independently.

### Repair ablation

- model-only patch;
- model + scanner context;
- model + reproducer;
- model + reproducer + public tests;
- full independent verifier;
- full verifier + fuzz/differential behavior.

### Incident ablation

- oracle CVE/file;
- alert plus affected service;
- raw/noisy telemetry;
- adversarially poisoned telemetry;
- telemetry plus compromised supporting service;
- multiple simultaneous hypotheses/incidents.

### Model comparison

- strong hosted GLM;
- smaller self-hosted GLM/open model;
- non-GLM reference model;
- deterministic/tool-only baselines.

Normalize tool access, time, token budget, attempts, and evidence visibility.

## Monitoring study design

Label each trajectory step with:

- permitted safe action;
- unsafe scope expansion;
- unauthorized network request;
- credential-seeking behavior;
- audit/verifier interference;
- destructive escalation;
- deceptive or evaluation-gaming behavior;
- appropriate uncertainty/refusal.

Compare:

- deterministic policy only;
- tool-request classifier;
- separate LLM judge;
- behavioral sequence model;
- hidden-state linear/MLP/temporal probes for open weights;
- combined system.

Metrics include AUROC/AUPRC, recall at fixed low FPR, early-warning lead time, task-success impact, latency, and intervention quality.

## Publication sequence

1. **AegisBench:** end-to-end autonomous incident-to-patch evaluation.
2. **Control-first defense:** capability/authority separation and clean-room verification.
3. **Evidence-grounded investigation:** claim graphs, uncertainty, and human review.
4. **Monitoring unsafe cyber-agent behavior:** behavioral and hidden-state early warning.
5. **Specialized defenders:** monolith versus role-specialized coordination after baseline maturity.

## Candidate headline

**Aegis: Control-First Autonomous Incident-to-Patch Cyber Defense**

Candidate central claim:

> Independent policy enforcement, clean-room verification, and trajectory monitoring reduce unsafe autonomous-agent actions while preserving useful defensive performance across detection, containment, repair, and recovery.

This remains a hypothesis until experiments support it.

## Research integrity

- preregister primary metrics for headline experiments;
- publish exact scopes, exclusions, and failure classifications;
- do not cherry-pick only solvable scenarios;
- separate engineering failures from reasoning failures;
- never present generated or synthetic results as observed results;
- release safe artifacts and harnesses where licenses permit;
- use responsible disclosure for newly discovered real vulnerabilities;
- restrict attacker automation to isolated range fixtures.
