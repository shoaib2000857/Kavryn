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
- Docker `--internal` network containing only the target fixture, with effective network configuration checked before use;
- scenario-defined request/replay adapters;
- no control-plane credentials;
- stronger containment than the analysis worker.

The current path-traversal range uses that internal-network setting: app and proxy
containers may communicate with each other but do not receive ordinary external
network connectivity. Neither container has a published port; local tests contact
the configured proxy IP from the trusted host. Docker internal mode can still permit
host/gateway communication, so container-to-host access is not proven blocked. The
rootful Docker host remains trusted.

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

### Local range deployment adapter

The path-traversal reference scenario now has a typed `deployment.rollout` adapter and paired `deployment.rollback` adapter. They accept a target reference, candidate diff, and content digests—not arbitrary commands, image names, or container names from the model. The adapter is configured with one fixture, service, network, and allowed source file; builds with Docker networking disabled; checks the running service; and retains prior image/containment state for a brokered rollback. The broker descriptor explicitly declares `docker_control="authorized-range"`.

The local proxy containment adapter can also be configured with a bounded set
of fixed regular expressions and an owner-selected rule-set identifier. These
values are trusted deployment configuration, never model-supplied action
parameters. For the synthetic object-authorization case, it temporarily blocks
one synthetic bearer token while preserving the other test principal's document
access. The proxy forwards only the `Authorization` header to its configured
backend and never logs its value. This remains a fixture-specific test primitive,
not a production authentication proxy; see ADR-052 and T24.

The scenario's evidence investigator also reads proxy logs through the registered
`range.proxy.logs` adapter (`telemetry.read`). The adapter fixes the container and
target at construction, accepts no parameters, limits the Docker-log tail to 200
lines and at most 512 KiB, and records the call/result through the broker. The model
does not receive a container selector or Docker command. The operation is an
observation, classified as R0 by deterministic policy; malformed or out-of-scope
requests are rejected before Docker is invoked.

This is a local test-range integration, not a general deployment API. Docker control still has host-level trust implications, current execution is rootful, and the adapter's resource declarations are not a hardened hostile-build limit. Do not use it against production or arbitrary repositories. See ADR-043 and the residual risks in the threat model.

### Range service launch configuration

`ServiceSpec` validates image references and container/network identifiers before
constructing Docker arguments; stop, log, and inspect helpers also validate
container names. Host mounts must be absolute and traversal-free,
container destinations normalized absolute paths, and host mount mode is
read-only. Explicit published ports remain representable for separately reviewed
scenarios, but each port must be in `1..65535`; the current reference range
publishes none. These checks reduce configuration mistakes and argument/volume
abuse. They do not strengthen rootful Docker isolation, authenticate image
contents, or authorize a range operation; policy and broker checks remain
separate.

## Isolation maturity

The reusable runtime core defines `SandboxBackend.execute(request)` with typed request/result models. The current `DockerSandboxBackend` implements that protocol for one-shot analysis workers only; tests also inject a fake backend to verify the dependency inversion. No rootless, gVisor, Firecracker, or remote implementation exists. Range deployment and network/service lifecycle remain separate Docker-specific code paths. A backend interface does not itself strengthen the isolation level.

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
