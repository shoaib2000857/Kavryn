# Tooling, routing, and sandbox design

## Tool philosophy

The model is an orchestrator and interpreter, not an oracle. Deterministic tools should perform scanning, execution, build, replay, and verification. However, tool output is also untrusted and must be parsed, attributed, and corroborated.

Do not expose an entire BlackArch catalogue to the model. Begin with a curated set of high-value adapters and add tools only when a requirement and evaluation scenario justify them.

## Initial adapter set

| Category | Initial candidates | Purpose |
| --- | --- | --- |
| Source inspection | ripgrep, language parser/tree-sitter | Locate relevant code without full-repo prompting |
| Static analysis | Semgrep; Bandit for Python | Candidate findings and localization |
| Dependencies | Syft + Grype or OSV-Scanner | SBOM and known-vulnerability evidence |
| Secrets | Gitleaks in non-destructive scan mode | Secret exposure evidence |
| Tests | pytest | Reproducer, regression, and behavioral checks |
| HTTP replay | purpose-built fixed adapter | Replay only scenario-defined requests |
| Build | fixture-specific typed adapter | Clean build from pinned source |
| Container telemetry | Docker/OTel/structured app events | MVP runtime evidence |

C/C++ fuzzers and sanitizers belong in the next language-specific phase, not the first Python runtime slice.

## Tool descriptor

```yaml
id: semgrep.scan
version: 1
category: static-analysis
inputs:
  target_ref: workspace
  ruleset_ref: immutable-artifact
outputs:
  - sarif
  - bounded-log
permissions:
  filesystem: read-target
  network: none
  secrets: none
risk_tier: R1
limits:
  timeout_seconds: 300
  cpu: 2
  memory_mb: 2048
adapter_image: registry.example/aegis-semgrep@sha256:...
parser: semgrep-sarif-v1
```

The model sees a filtered description. Only the broker sees the full execution descriptor.

## Retrieval and selection

```text
Evidence and hypothesis
  -> deterministic compatibility filter
  -> policy and availability filter
  -> rank by expected information gain, cost, and risk
  -> expose top-K descriptors to model
  -> model requests one typed action
  -> broker re-evaluates policy
```

Do not let model-selected relevance bypass deterministic compatibility or authorization.

## Worker classes

### Read-only analysis worker

- read-only source mount;
- no network;
- no secrets;
- strict CPU/memory/time/process limits;
- output only through artifact API.

### Dynamic validation worker

- copy-on-write target workspace;
- isolated network containing only the target fixture;
- scenario-defined request/replay adapters;
- no control-plane credentials;
- stronger containment than the analysis worker.

### Patch worker

- writable disposable repository copy;
- no hidden tests, evaluator ground truth, deployment credentials, or audit access;
- patch application through a library/adapter, not arbitrary host commands.

### Clean-room verifier

- fresh trusted base source and candidate diff only;
- immutable public and hidden test mounts;
- no model access;
- no external network;
- dedicated verifier identity;
- signed result upload.

### Response worker

- exact target and typed reversible action only;
- short-lived single-use capability;
- mandatory before-state and after-state capture;
- predefined rollback where possible.

## Isolation maturity

| Level | Boundary | Suitable use |
| --- | --- | --- |
| L0 | In-process mock | Unit tests only |
| L1 | Rootless container, no network | Low-risk static/dev fixtures |
| L2 | Rootless container + hardened profile + isolated target network | Early controlled range experiments |
| L3 | gVisor/Kata or comparable stronger container sandbox | Hostile builds and dynamic tools |
| L4 | Ephemeral VM/microVM with dedicated network and identity | High-risk agent/exploit evaluation |

The MVP may start at L1/L2 but must not misrepresent those levels as a complete hostile-code boundary.

## Network design

Network denial must cover:

- worker interfaces;
- artifact and package services;
- DNS resolvers;
- metadata endpoints;
- proxies and service meshes;
- CI/build services;
- sidecars;
- logging exporters; and
- target services capable of server-side requests.

Allowed egress is a declared graph, not a boolean `internet: false` flag.

## Command construction

Adapters must:

- validate paths as canonical references inside the mounted workspace;
- use argument arrays rather than string concatenation;
- reject unknown options;
- cap output and artifact size;
- set a clean environment;
- avoid shell expansion unless the adapter itself has a reviewed fixed script;
- capture exit code, timeout, signal, and resource usage; and
- redact secrets before logs enter model context.

## Supply-chain controls

- pin worker images by digest;
- record SBOM and source of images;
- pin rule/test corpora by version/hash;
- separate build cache per trust domain;
- verify downloaded benchmark artifacts;
- never let a target repository choose the verifier image;
- rebuild trusted worker images through a documented pipeline.

## Tool expansion criteria

Add a tool only when:

1. a requirement or benchmark scenario needs it;
2. its inputs, outputs, privileges, network behavior, and resource profile are known;
3. a narrow adapter and parser exist;
4. failure and malicious-output tests exist;
5. its image/package can be pinned; and
6. the threat model and documentation are updated.
