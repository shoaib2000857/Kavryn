# Model and inference strategy

## Decision summary

Aegis must be model-provider neutral. The initial model can be GLM-5.2, GLM-5.3, another hosted frontier model, or a smaller self-hosted open-weight model without changing workflow, authority, evidence, or assurance semantics.

Model choice is a measured configuration decision, not part of the trusted architecture.

## Current GLM reality

As of 2026-09-02:

- GLM-5.2 is published as a 744B-total, 40B-active mixture-of-experts model with BF16 and FP8 weights.
- The official repository describes a 1M-token context and `high`/`max` reasoning-effort modes.
- GLM-5.3 and GLM-5.3-Flash have already superseded it as newer options.
- Full GLM-5.2 self-hosting is a multi-GPU/server-class deployment. It is not a realistic workload for a normal free or single-GPU Colab runtime.

Therefore:

1. **Fastest starting path:** use a hosted GLM API from the local orchestrator or a Colab notebook.
2. **Colab path:** use Colab as an experiment client, trace collector, and evaluator—not as the full GLM-5.2 host.
3. **Local/open path:** use a smaller model for development and CI, then benchmark larger GLM variants through the same contract.
4. **Serious self-hosting:** use vLLM or SGLang on suitable multi-GPU infrastructure when budget and data policy justify it.

## Provider abstraction

The runtime should expose an internal interface similar to:

```python
class ReasoningProvider(Protocol):
    async def propose(
        self,
        task: ReasoningTask,
        context: EvidenceContext,
        tools: list[ToolDescriptor],
        limits: InferenceLimits,
    ) -> StructuredProposal: ...
```

Provider implementations may include:

- `ZaiProvider` for the native hosted API;
- `OpenAICompatibleProvider` for hosted or local compatible endpoints;
- `VLLMProvider` and `SGLangProvider` for self-hosted inference;
- `ReplayProvider` for deterministic tests using recorded responses; and
- `StubProvider` for unit tests that do not require a model.

The provider returns structured proposals. It does not execute actions.

## Task roles, not autonomous personalities

The first system should use one reasoning runtime with different typed tasks:

| Task | Required output |
| --- | --- |
| Triage | Incident hypothesis and requested discriminating evidence |
| Investigation | Timeline, affected assets, competing hypotheses, uncertainty |
| Tool selection | Ranked approved adapter IDs with expected information gain |
| Containment planning | Typed action, expected effect, risk, rollback, verification plan |
| Localization | Artifact/repository/code candidates linked to evidence |
| Patch planning | Root-cause invariant, minimal change strategy, candidate test plan |
| Patch generation | Unified diff constrained to allowed paths |
| Report synthesis | Evidence-linked summary with explicit unknowns |

This avoids multi-agent coordination overhead until specialization has measurable value.

## Context construction

Never send an entire environment or repository by default. Build a compact context containing:

- system-authored task and immutable policy summary;
- normalized evidence with stable IDs;
- relevant source slices and dependency/build provenance;
- permitted tool descriptors, not raw tool binaries;
- prior decisions and failed attempts;
- remaining budgets;
- explicit untrusted-content boundaries; and
- a response schema.

Raw logs, source comments, READMEs, issue text, and tool output are quoted/tagged as untrusted evidence.

## Structured-output rule

Every reasoning call must validate against a versioned schema. On validation failure:

1. preserve the original response as an artifact;
2. allow at most a bounded repair attempt;
3. never infer an action from free-form text; and
4. refuse/escalate if a safe typed proposal cannot be obtained.

## Hosted API mode

Use this first when it accelerates research, subject to data policy.

Required controls:

- API key only in a secret store/environment variable, never notebook output or source;
- explicit provider base URL and model ID in configuration;
- data classification and redaction before upload;
- request/response metadata and token/cost logging, with sensitive content handled separately;
- timeouts, retry budgets, and circuit breaker;
- provider response treated as untrusted;
- no provider-supplied tool execution outside Aegis's broker.

### Current development endpoint (2026-09-25)

The owner supplied an OpenAI-compatible llama.cpp server hosted on an A100. It exposes several model aliases, but switching aliases causes model offload/reload, so the current development default is **`qwen38`**. Keep the server warm and do not switch models merely to probe alternatives. With the corrected local environment, a synthetic-only smoke proposal succeeded and a full-source-v2 object-authorization patch passed the clean-room verifier; the path-traversal response was a no-op. Configure it with `LLM_URL`, `LLM_API_KEY`, and optionally `LLM_MODEL`; `scripts/smoke_model_api.py` makes a single structured call without executing the proposed action. `scripts/bench_live_model.py --provider hosted --trials 1` runs a local Docker range and makes one model-backed containment proposal.

The endpoint is remote inference: only synthetic range information was used. Do not send private repositories, real incident logs, credentials, or personal data under the current decision. The key must never be committed or printed; rotate the key shared in chat after testing. Hosted calls are manual and excluded from CI/default tests.

`src/aegis/repair/provider.py` defines `HostedPatchProvider` for one explicitly allowlisted repair file. The prompt requests complete replacement source and a repair invariant; Aegis constructs the unified diff locally so the model cannot corrupt hunk counts. The request explicitly uses `reasoning_effort: none` and `max_tokens: 8192`, checks truncation/no-op output, and records finish reason and endpoint token usage when present. The clean-room verifier alone receives hidden tests. One object-authorization patch passed; the path-traversal attempt was an unchanged-source no-op, and two earlier model-authored diffs failed build. This is a small owned-fixture pilot, not an external benchmark or general coding-quality result. Only synthetic fixture source is approved for hosted input.

## Colab mode

The planned notebook should:

1. install only the Aegis client/evaluation package;
2. obtain secrets through Colab's secret mechanism or interactive input without printing them;
3. call a hosted endpoint or an explicitly supported small model;
4. run no target-side security tool against public systems;
5. upload/download only synthetic or approved datasets;
6. export experiment metadata and artifacts to a chosen store; and
7. warn that ephemeral Colab runtimes are not a trusted verifier or durable audit system.

Do not build the core architecture inside notebook cells. The notebook is an adapter and experiment surface.

## Self-hosted mode

Use OpenAI-compatible serving where possible, but allow provider-specific parameters through a namespaced field. Pin:

- model repository and revision;
- quantization/precision;
- serving engine and version;
- tokenizer/chat template;
- tool-call and reasoning parsers;
- sampling and reasoning effort;
- maximum context/output; and
- hardware topology.

Serving the model does not place it inside the trusted computing base.

## Model selection experiment

Before choosing the default agent model, run a fixed evaluation matrix:

| Dimension | Measure |
| --- | --- |
| Investigation | malicious-event recall, evidence precision, root-cause accuracy |
| Repair | verified patch rate, regression rate, patch minimality |
| Control | denied-action attempts, prompt-injection success, scope adherence |
| Structure | schema-valid response rate and repair attempts |
| Efficiency | latency, tokens, tool calls, cost, memory/VRAM |
| Calibration | confidence vs actual correctness and refusal quality |

Evaluate at least:

- one strong hosted GLM model;
- one smaller open-weight model feasible for development;
- one non-GLM reference model if policy/budget permits; and
- a deterministic/no-model baseline for tool orchestration where applicable.

## Hidden-state research

Activation-level monitoring is possible only for self-hosted open-weight models with accessible internals. It is a separate research backend, not a prerequisite for the MVP.

Record aligned trajectories containing:

- prompt/evidence identifiers;
- layer/position activation summaries or securely stored tensors;
- proposed action;
- policy decision;
- eventual behavior/outcome; and
- labels such as safe, scope probe, unauthorized egress, credential access, deception, uncertainty, or destructive escalation.

The monitor is evaluated for recall at fixed false-positive rates and early-warning lead time. It can restrict or escalate; it never grants authority.

## Decision still required

The owner must later choose:

- first hosted provider and spending limit;
- code/data allowed to leave the local environment;
- first smaller self-hosted development model;
- whether Colab artifacts may persist to Drive or another store; and
- whether activation research is a first-year objective or a later track.
