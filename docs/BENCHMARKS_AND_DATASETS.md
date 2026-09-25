# Benchmarks and datasets

Snapshot date: 2026-09-02. Re-check upstream versions before experiments.

## Dataset roles

No single existing benchmark measures the full Aegis objective. Use different resources for training/mining, component evaluation, end-to-end repair, SOC investigation, post-compromise response, and control safety.

## Evaluation ladder

### Layer 0: deterministic fixtures

Tiny synthetic repositories and services designed to test policy, evidence, workflow, and verifier behavior. These are not headline capability results, but they make failures reproducible.

### Layer 1: repository repair

| Resource | Role | Notes |
| --- | --- | --- |
| Vul4J | Reproducible Java vulnerability repair | Vulnerable projects, human patches, proof-of-vulnerability tests |
| AutoPatchBench | Real C/C++ fuzz-found patching | 20 sample, 120 lite, 142 full in current docs; operationally large |
| PatchEval / PatchEval-Verified | Executable real-world vulnerability patching | Use pinned release and report exact subset/configuration |
| VulnLoc | Reproduction/localization/repair | Sanitizer-oriented reproducible cases |
| San2Patch | Crash-log-to-patch evaluation | Extends vulnerability repair with functional checks |
| SEC-bench | Real-world software-security agent tasks | Useful external comparison; pin task subset |

### Layer 2: detection and data mining

| Resource | Role | Limitation |
| --- | --- | --- |
| CVEfixes | Large vulnerable/fix commit corpus | Not uniformly executable |
| PrimeVul | Function-level C/C++ vulnerability detection | Classification/localization is not end-to-end repair |
| OTRF Security Datasets | Reproducible security telemetry | Coverage varies by scenario |
| Cyber Defense Benchmark | Open-ended threat hunting in large Windows logs | Investigation only, no repair/recovery loop |

Current reference facts to verify at run time:

- CVEfixes v1.0.8 reports 11,873 CVEs, 12,107 fixes, 4,249 projects, and 272 CWE types through its stated collection date.
- PrimeVul reports roughly 7,000 vulnerable and 229,000 benign C/C++ functions across more than 140 CWEs.
- The Cyber Defense Benchmark contains 106 procedures across 26 campaigns; its initial report found low malicious-event recall and no tested model met the authors' autonomous-deployment threshold.

### Layer 3: cyber ranges and response

| Resource | Role |
| --- | --- |
| Splunk Attack Range | Build instrumented environments and generate telemetry |
| MITRE CALDERA | Controlled adversary emulation mapped to ATT&CK |
| SecRespond | Post-compromise detection and remediation in realistic ranges |
| CyberGym-E2E | Vulnerability discovery through PoC and patching across many projects |

CyberGym-E2E and SecRespond are especially important: they cover substantial but different portions of the desired loop. The proposed Aegis benchmark contribution should connect those halves rather than duplicate either one.

### Layer 4: agent-control safety

| Resource | Role |
| --- | --- |
| BashArena | Capability/control evaluation in terminal tasks with sabotage objectives |
| SHADE-Arena | Long-horizon sabotage monitoring |
| NIST agent hijacking evaluations/competition | Prompt-injection and tool-use hijacking robustness |
| Project-specific control suite | Scope, egress, audit, verifier, identity, and budget attacks unique to Aegis |

## Proposed AegisBench

### Research gap

Existing work usually evaluates one or more of:

- threat hunting from telemetry;
- post-compromise remediation;
- repository vulnerability discovery and patching;
- agent control/sabotage.

AegisBench should evaluate the executed closed loop:

```text
noisy telemetry -> incident discovery -> containment -> runtime-to-source
-> patch -> independent verification -> redeployment -> attack replay -> recovery
```

while also testing whether the defender violates its control protocol.

### Scenario package

```text
AB-0001/
|- manifest.yaml
|- range/
|  |- infrastructure/
|  `- pinned-images.lock
|- source/
|  |- vulnerable-repo.bundle
|  `- build-provenance.json
|- telemetry/
|  |- benign-generator/
|  `- schema-mapping/
|- attack/
|  |- controller/
|  `- expected-observables.json
|- public/
|  |- operator-brief.md
|  `- allowed-interfaces.json
|- evaluator-private/
|  |- ground-truth.json
|  |- hidden-security-tests/
|  |- hidden-regression-tests/
|  `- scoring-policy.yaml
`- license-and-provenance.md
```

The defender receives only the public brief, scoped interfaces, and observations it earns. It does not receive the CVE, vulnerable file, developer patch, hidden tests, or ground truth.

## Metrics

Do not collapse all results into one score.

### Defensive capability

- malicious-event and technique recall;
- false-positive rate and analyst burden;
- root-cause and affected-asset accuracy;
- mean time to detect, contain, recover;
- containment effectiveness and collateral availability loss;
- recurrence after recovery.

### Repair quality

- verified-patch rate;
- original exploit removal;
- hidden security and regression pass rates;
- new-warning rate;
- patch minimality and unrelated-change rate;
- number of repair attempts.

### Control safety

- attempted and successful scope violations;
- unauthorized egress;
- credential access/exposure;
- prompt-injection success;
- shared-state/identity misuse;
- audit or verifier tampering;
- unauthorized production-like changes;
- safe-stop/refusal correctness;
- monitor recall at fixed false-positive rate.

### Operational efficiency

- model tokens and cost;
- tool calls and redundant actions;
- CPU/GPU time and memory;
- wall time and downtime;
- human approvals and active human minutes;
- evidence completeness and reproducibility.

## Benchmark hygiene

- pin repository commits, dataset versions, images, rules, and harness versions;
- report pass@k/attempt budgets and retries;
- separate public-test tuning from hidden evaluation;
- check training-data contamination where possible;
- avoid using human patches in model context;
- record model/provider version and sampling parameters;
- repeat stochastic runs and publish confidence intervals;
- distinguish infrastructure failures from agent failures;
- publish negative results and control violations;
- comply with dataset and repository licenses.

## Recommended order

1. project fixtures for control correctness;
2. Vul4J or a small PatchEval subset for the repository repair loop;
3. AutoPatchBench sample when C/C++ support exists;
4. one controlled telemetry/range scenario;
5. a SecRespond/CyberGym-E2E adapter if practical;
6. AegisBench v0.1 with 3–5 end-to-end cases;
7. only then broader benchmark runs.
