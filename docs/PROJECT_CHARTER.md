# Project charter

## Working identity

- **Public name:** Kavryn (formerly Aegis Defender), owner-approved 2026-10-01
- **Nature:** independent, non-hackathon research and engineering project
- **Not:** a hackathon submission, a generic pentesting bot, or an unrestricted autonomous operator
- **One-line thesis:** a reusable runtime should let autonomous agents propose consequential work without granting unconditional authority; actions must be scoped, policy-checked, isolated, independently verified, reversible where possible, and evidence-bearing. Cyber defense is the first demanding reference application.

The project governs execution, not cognition. It is not intended to replace LangGraph, OpenAI/Anthropic agent SDKs, or other agent loops. Those may submit typed actions to the runtime through the experimental Kavryn SDK. Historical Aegis evidence/schema identifiers remain unchanged.

Kavryn replaces the provisional name. “ASTRA” remains a separate reference project, not a second architecture.

## Mission

Build and evaluate a defensive agent framework that can:

1. identify attacks, compromises, vulnerable components, and likely root causes;
2. take bounded, reversible defensive actions during an incident;
3. generate minimal repairs in isolated workspaces;
4. independently establish whether the incident is contained and the vulnerability is removed without unacceptable regression;
5. recover the service and monitor for recurrence; and
6. refuse or escalate when evidence or authority is insufficient.

## Research question

Can an execution runtime make consequential agent actions bounded, inspectable, reversible where possible, and independently verifiable—and can that improve safe end-to-end cyber defense under adversarial inputs?

The target action lifecycle is:

```text
PROPOSE -> AUTHORIZE -> EXECUTE -> OBSERVE -> VERIFY -> COMMIT / ROLL BACK -> RECEIPT
```

This is the research target, not a claim that generic transaction coordination is complete today.

## Product pillars

### 1. Evidence-grounded investigation

Claims must reference normalized events, artifacts, source locations, tool runs, and provenance. Unsupported conclusions remain hypotheses.

### 2. Bounded response

Containment is risk-tiered and preferably reversible. The agent receives capabilities for a specific case rather than ambient administrator access.

### 3. Verified repair

The patching loop runs in disposable sandboxes and produces an evidence-carrying patch. The agent cannot approve its own candidate.

### 4. Independent control

Identity, permission, network, budget, audit, approval, and emergency-stop enforcement live outside the reasoning model's authority.

### 5. Measurable safety

The system reports defensive capability and control failures separately. High task success cannot compensate for unauthorized behavior.

## Primary users

- security researchers studying autonomous defense and AI control;
- software-security teams evaluating assisted remediation;
- SOC/incident-response teams experimenting in authorized ranges;
- maintainers evaluating evidence-backed vulnerability patches; and
- benchmark authors studying end-to-end cyber-defense agents.

The first release is a research harness for operators, not an unattended production SOC replacement.

## In scope

- static, dependency, dynamic, and telemetry-based evidence ingestion;
- attack detection and incident hypothesis formation;
- evidence-chain construction and ATT&CK/D3FEND mapping;
- reversible containment in an isolated range;
- runtime-to-source localization;
- repository patch generation and verification;
- clean rebuild, redeployment, exploit replay, benign-workload replay, and recurrence monitoring;
- agent-policy enforcement, prompt-injection resistance, immutable audit, and kill switches;
- external benchmarks and a new end-to-end benchmark layer;
- provider-neutral use of hosted or self-hosted language models.

## Explicit non-goals for the first program

- defending “any system from any threat”;
- automatic destructive or irreversible production changes;
- mass scanning or testing of arbitrary internet targets;
- stealth, persistence, credential collection, or autonomous exploitation as product features;
- a catalogue of thousands of loosely wrapped security tools;
- a large multi-agent swarm before a single-agent state machine is understood;
- claiming formal proof from a finite test suite;
- training a foundation model from scratch;
- a dashboard before the core evidence loop works.

## Success definition

The first meaningful success is a reproducible isolated scenario in which Aegis:

1. observes a live attack through telemetry;
2. identifies the affected service and evidence chain;
3. applies a pre-authorized reversible containment action;
4. maps the incident to vulnerable source;
5. generates a minimal candidate patch in a disposable workspace;
6. passes an independent build, security replay, hidden regression suite, and policy review;
7. requests approval before rollout;
8. redeploys and demonstrates service recovery; and
9. produces an immutable assurance bundle and complete audit timeline.

No success claim is valid if the agent violates scope, tampers with evidence, acquires ungranted authority, or escapes its sandbox.

## Guiding principles

- **Model intelligence is not model authority.**
- **Tools provide observations; they do not automatically establish truth.**
- **No adequate evidence means no autonomous deployment.**
- **Safe refusal is part of capability.**
- **Every action must be attributable, scoped, replayable, and reviewable.**
- **The verifier must be cleaner and less mutable than the actor it evaluates.**
- **Start with one narrow closed loop, then expand by measured evidence.**
