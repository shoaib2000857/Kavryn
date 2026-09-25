# Benchmarks and datasets

Snapshot date: 2026-09-25. Re-check upstream versions before experiments.

## Actual evaluation status (2026-09-25)

The repository has **not** run SWE-bench, Vul4J, AutoPatchBench, Cyber Defense Benchmark,
or another external benchmark. The prior live qwen38 run exercised only a containment
proposal in one local Docker range; its repair patch was pre-authored by the fixture test.
Do not report that run as patching or detection performance.

A real model-patch path and runner exist for two owned Python fixtures. The owner corrected
the local ignored `.env.local` after earlier checks used a stale credential; a synthetic-only
qwen38 smoke request then succeeded. Four controlled repair attempts were made across two
prompt protocols. The first two model-authored unified diffs had malformed hunk counts and
failed clean build. With `full-source-v2`, the model returned an unchanged path-traversal file
(rejected before verifier execution), while its object-authorization candidate passed clean-room
source/diff checks, two public tests, exploit replay, and two regression tests. See the
machine-readable records:
[`path traversal v1`](../artifacts/benchmark_runs/qwen38-path-traversal-repair-corrected-key.json),
[`object authorization v1`](../artifacts/benchmark_runs/qwen38-object-authorization-repair-corrected-key.json),
[`path traversal v2`](../artifacts/benchmark_runs/qwen38-path-traversal-full-source-v2.json), and
[`object authorization v2`](../artifacts/benchmark_runs/qwen38-object-authorization-full-source-v2.json).
This is **one verified model-generated repair on one owned synthetic case**, not an external
benchmark score, broad coding-quality result, production patch, or evidence the other case works.
The credential remains only in the ignored local environment file and must not be copied here.

### Run records and metric separation

The repair pilot emits a versioned [`aegis.benchmark_run/v1`](../schemas/aegis.benchmark_run.v1.json)
record in its `evaluation` field. It keeps **capability**, **control/safety**, and **efficiency**
metrics in separate axes and does not calculate a composite score. Each metric includes its
measurement method; unavailable measurements carry a reason rather than being reported as zero.
The record also captures the scenario version, source digest, repository revision/dirty state,
agent mode, provider/model, prompt version, finish reason, outcome, elapsed time, and token usage
when the compatible endpoint returns it. Missing measurements retain an explicit reason.

This record format is currently wired only to the two-case synthetic repair pilot. It is not yet
a general AegisBench runner, does not turn the local integration tests into standard benchmark
scores, and does not imply any external dataset has been run. Failed/no-op generations are recorded
without attributing a verifier score; the one verified fixture result remains a tiny pilot sample.

### External benchmark preflight

Upstream references checked on 2026-09-25: [SWE-bench Docker guide](https://github.com/SWE-bench/SWE-bench/blob/main/docs/guides/docker_setup.md), [Meta AutoPatchBench requirements](https://meta-llama.github.io/PurpleLlama/CyberSecEval/docs/benchmarks/autopatch), [Vul4J setup, licensing, Docker image, and evaluator](https://github.com/tuhh-softsec/vul4j/blob/main/README.md), [Cyber Defense Benchmark harness/data availability](https://github.com/simbianai/cyber_defense_benchmark), and [Microsoft DefenderBench](https://github.com/microsoft/DefenderBench).

Additional benchmark review (2026-09-25): [Vul4Py](https://arxiv.org/abs/2608.00692) is a strong language match: its paper describes 100 Python vulnerabilities with paired exploit and project-functional test oracles and states the harness is released. A candidate [GitHub repository](https://github.com/tabudz/vul4py) was located at commit `2649d7b89e796738ebc2bc3fa9480dff5ae15898`; its README describes the same 100-case design, but the paper/publication page does not link this repository, so artifact provenance is not confirmed. GitHub reports no declared license (the license endpoint returns 404). Static inspection found the runner can execute metadata-provided install/test commands via `shell=True`, clone listed repositories, and download micromamba. It has no evident per-case isolation boundary. Do not execute this harness or redistribute/adapt its code until provenance/terms are confirmed and a suitable isolation design exists. These are artifact/harness issues, not a reason to discard the benchmark design; any Aegis integration should implement a separately reviewed runner against pinned data and paired oracles. No Vul4Py case was downloaded or executed and no paper baseline is an Aegis result. [VulnGym v0.1.4](https://github.com/Tencent/VulnGym) offers 408 project-level detection entries (393 human-audited) and an official prediction evaluator under a CC-BY-4.0 dataset license. Its evaluator is recall/coverage-only and cannot penalize false positives, so any result must be labelled coverage, not precision or overall detection quality. VulnGym data provides repository URLs/commits and annotations, not a ready-made Aegis execution environment.

#### VulnGym evaluator compatibility check (not an Aegis score)

On 2026-09-25, the official v0.1.4 evaluator was run from upstream commit
`cd69f7e163e08485ab5496115ae03439cda6e27e` against its own example output and a
metadata-only oracle file constructed directly from `data/entries.jsonl`. No project
repositories were cloned or executed, and no model was called. Inspection of the
released data found **44/408 entries** where either `entry_point.line` or
`critical_operation.line` is a documented range string (for example, `199-203`). The
official matcher converts each ground-truth line with `int(...)` and treats conversion
failure as a non-match. Consequently, exact oracle locations scored only **364/408
entries (89.22%)** and **171/184 advisories (92.93%)**; all 44 range-form entries were
reported unmatched. This is an evaluator/schema compatibility defect, not Aegis
performance and not a valid ceiling for an agent.

Before using VulnGym for a headline number, pin the release and evaluator, preserve an
unchanged official-compatible run, and add a separately labelled range-aware analysis
or obtain an upstream correction. Report the evaluator limitation and its effect
explicitly; do not silently rewrite ground truth or present the oracle sanity check as a
model result. Aegis has a metadata-only supplemental metric adapter, but it still has
no VulnGym-capable detector/prediction producer and has produced no VulnGym score.

The reproducible metadata-only check is recorded in
[`artifacts/benchmark_runs/vulngym-v014-evaluator-oracle-compat-20260925.json`](../artifacts/benchmark_runs/vulngym-v014-evaluator-oracle-compat-20260925.json).
It is a harness compatibility diagnostic, not an agent evaluation.

To avoid losing range-form annotations in a future analysis, Aegis now provides
`aegis.benchmarks.vulngym` and
[`scripts/evaluate_vulngym_range_aware.py`](../scripts/evaluate_vulngym_range_aware.py).
It validates JSONL fields and computes an explicitly **supplemental, non-official**
range-aware recall report, matching repository, commit, strict endpoint roles, exact
normalized paths, and line intervals within the selected tolerance. It deliberately
does not compute precision from this recall-oriented annotation set. It reads metadata
only and does not clone or execute benchmark repositories. A ground-truth-copy parser
sanity check returned 408/408 entries and 184/184 advisories; this checks the evaluator
only and is **not an Aegis score**. The implementation remains a metrics/data adapter,
not a repository-level detection agent: Aegis must still produce actual localized
predictions before a model benchmark can run.

```bash
.venv/bin/python scripts/evaluate_vulngym_range_aware.py \
  --entries /path/to/VulnGym/data/entries.jsonl \
  --predictions predictions.jsonl \
  --dataset-release v0.1.4 \
  --json-out artifacts/benchmark_runs/vulngym-range-aware.json
```

At the time of preflight this filesystem had approximately **52 GB free**. SWE-bench's
official Docker guide recommends at least 120 GB free, so its standard local harness was
not started. Meta's AutoPatchBench recommends about 500 GB for even its 20-case sample,
about 2 TB for Lite, and about 3 TB for Full; that suite is not feasible on this machine.
Vul4J is the most plausible first external repair benchmark. The upstream repository now
documents a standalone Docker image bundling JDK 7/8/11/16 and an evaluator that accepts
unified diffs, recompiles clean checkouts, runs PoV tests, and checks fixed SpotBugs
warnings where defined. Its May 20, 2026 reproduction note reports 129 entries (79 PoV,
50 SpotBugs-only) passing its stated checks. This improves on the earlier host-Java
preflight, but does not remove Aegis's gaps: no Aegis Vul4J adapter exists, and the current host offers
only rootful runc rather than a hardened sandbox. Docker Hub lists the upstream image at
about 11.8 GB compressed; the current 52 GB free is enough for the nominal pull but does
not make running historical project builds/PoVs acceptable under the current threat model.
Do not pull/run it until an appropriate isolation boundary and inference access are
available. No Vul4J score is claimed. The upstream README documents dataset CC-BY-4.0
separately from tooling GPL-3.0; preserve that distinction in any adapter/release.

Current container preflight: Docker exposes `runc` only; `runsc`, Firecracker, Kata, and
Podman were not found. The upstream image/tag currently reports digest
`sha256:9e66a0646dc82eaf6cca98001c643cee377207fa5b64a6517ecb529224839404` and compressed
size 11.77 GB on [Docker Hub](https://hub.docker.com/r/tuhhsoftsec/vul4j). This digest/size
is planning evidence only; the image has not been pulled or executed.

The Cyber Defense Benchmark evaluates open-ended hunting in Windows event logs, not patch
generation or response. Its authors report 106 attack procedures and low malicious-event
recall in their tested models; that is motivation for a future telemetry evaluation, not
a result for Aegis or qwen38. Its public repository bundles a small sample payload, while
the full dataset is distributed separately; a standard sample run still needs authorized
inference. Microsoft DefenderBench is another candidate component suite described by its
maintainers as affordable and accessible; task licenses, local runtime requirements, and
Aegis-adapter scope must be audited before selecting a reproducible subset.

Exact latest unit/static/schema/Docker results are maintained in
[`docs/ACTIVE_TASKS.md`](ACTIVE_TASKS.md). These are project control/integration tests,
not benchmark-dataset scores. No external dataset was downloaded and no standard benchmark
agent run was executed. The corrected-key local qwen38 repair pilot produced one verified
object-authorization patch and one unchanged path-traversal response; see records above.

The range investigator is now application code and both its static scan and telemetry
read are brokered. This strengthens the locally tested evidence-collection path but does
not change external benchmark readiness or constitute an attack-detection score.

### Current reproducible evaluation ladder

1. **Unit / control tests:** model output schema, diff allowlist, and candidate digest tests
   run without network. These test controls, not coding skill.
2. **Layer-0 clean-room repair pilot:** qwen38 proposes replacement source for the one allowlisted
   fixture file; Aegis constructs the unified diff locally and evaluates it with source-integrity,
   path-policy, public tests, hidden exploit replay, and regression checks in the verifier. To
   reproduce a controlled pilot:

   ```bash
   set -a; source .env.local; set +a
   .venv/bin/python scripts/bench_patch_repair.py --scenario path-traversal-v1 --out artifacts/benchmark_runs/qwen38-path-traversal.json
   ```

The second fixture has an independent verifier acceptance pair for a locally constructed
known-good patch and a comment-only exploit-preserving change. A separate Docker integration
exercises its full deterministic case workflow using a stub containment proposal and an oracle
patch; this validates integration plumbing across CWE-862/CWE-639, not a standard benchmark
score. The live pilot's only verified model candidate is also on this synthetic fixture. Only
synthetic source and vulnerability context are sent to the configured provider.

The separate `scripts/bench_live_model.py` proposal-reliability runner uses real
local proxy telemetry but supplies the known fixture finding as an oracle. It does
not measure attack detection, source localization, scanner quality, or general repair
capability; trial records identify this mode explicitly.

3. **First external patch benchmark:** prioritize Vul4Py's Python language and paired
   security/functional oracles, but treat `tabudz/vul4py` as an unconfirmed candidate artifact.
   Before any run: establish author provenance and data/code terms; design a clean-room case
   runner that does not execute metadata commands on the host and meets the project isolation
   policy; validate each case's vulnerable/fixed paired oracle; and keep fixed patches and
   hidden tests outside the model boundary. The inspected harness itself must not be run under
   current rootful-Docker-only constraints. Pin repository/dataset versions, case IDs, evaluator,
   and terms; otherwise select a benchmark with compatible licensing and isolation.
4. **First external detection benchmark:** evaluate the human-audited VulnGym subset after
   adding repository-level localization/investigation input and exporting predictions in its
   official schema. Report its recall-only metric with the explicit false-positive limitation.
   The current synthetic range investigator is not yet a VulnGym-capable agent.
5. **Broader suite:** SWE-bench and AutoPatchBench only on suitable storage/compute; threat
   hunting only after Aegis has a telemetry-driven investigator, not just a patcher.

## Dataset roles

No single existing benchmark measures the full Aegis objective. Use different resources for training/mining, component evaluation, end-to-end repair, SOC investigation, post-compromise response, and control safety.

## Evaluation ladder

### Layer 0: deterministic fixtures

Tiny synthetic repositories and services designed to test policy, evidence, workflow, and verifier behavior. These are not headline capability results, but they make failures reproducible. The owned `ranges/object-authorization-v1` fixture adds a CWE-862/CWE-639 cross-user document-access case and now passes a deterministic full-case integration with brokered investigation, containment, oracle-patch verification, deployment, and recovery. It has no live model repair result and is not a standard benchmark task.

### Layer 1: repository repair

| Resource | Role | Notes |
| --- | --- | --- |
| Vul4Py | Python vulnerability repair | Paper describes 100 paired-oracle cases. Candidate repo `tabudz/vul4py` located at pinned commit, but link/provenance and license are unverified; runner contains host-side shell execution and dynamic checkout. Do not run before provenance, terms, and isolation gates pass. |
| Vul4J | Reproducible Java vulnerability repair | Vulnerable projects, human patches, proof-of-vulnerability tests |
| AutoPatchBench | Real C/C++ fuzz-found patching | 20 sample, 120 lite, 142 full in current docs; operationally large |
| PatchEval / PatchEval-Verified | Executable real-world vulnerability patching | Use pinned release and report exact subset/configuration |
| VulnLoc | Reproduction/localization/repair | Sanitizer-oriented reproducible cases |
| San2Patch | Crash-log-to-patch evaluation | Extends vulnerability repair with functional checks |
| SEC-bench | Real-world software-security agent tasks | Useful external comparison; pin task subset |

### Layer 2: detection and data mining

| Resource | Role | Limitation |
| --- | --- | --- |
| VulnGym | Repository-level vulnerability hunting/localization | 408 entries in v0.1.4; official evaluator measures recall/coverage only; project checkouts and Aegis adapter still required |
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
