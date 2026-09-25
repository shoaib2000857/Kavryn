# Synthesis of the supplied ASTRA reference material

The user's ASTRA-Kavach material was provided as design inspiration only. Aegis Defender is an independent project and is not scoped to the hackathon or competition described by that material.

## Ideas retained

| Reference idea | Aegis treatment |
| --- | --- |
| AI proposes; tools verify; evidence decides | Retained as a core principle |
| Scope guard | Expanded into a deterministic control plane and capability broker |
| Explicit state machine | Retained; used for both incident and repair lifecycles |
| Normalized findings/evidence store | Expanded into provenance-linked case evidence and append-only audit |
| Minimal-diff patching | Retained as a repair constraint and metric |
| Vulnerability reproduction before repair | Retained where technically feasible |
| Verification/proof gate | Renamed assurance gate by default; made clean-room and independent |
| Refusal as a feature | Retained and included in evaluation metrics |
| Local/air-gapped direction | Retained as a provider and deployment mode |
| Sandboxed tool execution | Retained, with stronger separation by worker class and maturity level |
| Human escalation | Retained for high-risk/uncertain operations |

## Ideas expanded

ASTRA primarily framed repository vulnerability repair. Aegis adds:

- live telemetry and open-ended attack discovery;
- incident timelines and affected-asset reasoning;
- reversible containment and rollback;
- runtime-to-build-to-source provenance;
- clean redeployment and recurrence monitoring;
- adversarial testing of the defender itself;
- independent identities and short-lived capabilities;
- out-of-band audit and emergency stop;
- an end-to-end benchmark connecting response and repair;
- action-, trajectory-, and optional activation-level monitoring.

## Ideas changed

### “Proof-carrying repair”

Finite tests provide strong evidence but normally do not prove general security. Aegis uses “evidence-carrying patch” and “assurance gate” unless a property is genuinely machine-checked under explicit assumptions.

### Docker as the sandbox

Rootless Docker is acceptable for early low-risk fixtures. Hostile builds and high-risk exploit evaluation require a path toward gVisor/Kata or ephemeral VMs/microVMs.

### BlackArch tool router

A massive tool catalogue is deferred. The first system uses a curated adapter registry because every adapter expands the trusted computing base, maintenance burden, and attack surface.

### Multi-agent architecture

Multiple named agents are deferred. First establish a single reasoning runtime with specialized typed states and permissions. Later experiments can determine whether specialization earns its cost.

### Model choice

No model is embedded in the architecture. GLM is a strong candidate, but the system remains provider-neutral and benchmarks alternatives.

## Ideas explicitly rejected for now

- “full defense against any threat” as an engineering claim;
- unrestricted autonomous shell access;
- autonomous destructive/irreversible production response;
- model self-approval;
- thousands of tools for appearance;
- a graph database before evidence queries require one;
- frontend work before the closed loop functions;
- fabricated capabilities, benchmarks, or implementation status.

## Resulting project identity

Aegis is not simply an enlarged ASTRA repair agent. Its defining contribution is the combination of:

```text
end-to-end incident response and repair
+ independent authority control
+ clean-room assurance
+ adversarial evaluation of the defender
```
