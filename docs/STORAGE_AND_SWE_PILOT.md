# Storage audit and offline SWE-bench pilot

Date: 2026-09-30. This is a bounded engineering pilot, not a leaderboard submission.

## Results and limits

Predeclared selection: the first three `psf/requests` tasks sorted by instance ID
in the original SWE-bench test split: **1142, 1327, 1339**. Two task environments
were downloaded and exercised. **1327 was not downloaded or run**; do not silently
drop it from the selection or present two convenient tasks as a representative score.

| Task | Unpatched checks | Human-reference checks | Local Qwen candidate |
| --- | --- | --- | --- |
| 1142 | Target fails; 5 regressions pass | All 6 required tests pass | All 6 required tests pass |
| 1339 | 7 targets fail; 24 regressions pass | All 31 required tests pass | Diff does not apply; no candidate tests ran |
| 1327 | Not run | Not run | Not run |

One candidate passed and one failed at patch application. This is **not** a full
SWE-bench score, proof of general coding quality, or a measured harness advantage
over a basic agent. The 1339 failure also exposes a framework limitation:
class-fragment diffs can treat a changed fragment boundary as file EOF. The
candidate also makes a simplistic key-lowercasing change, but its functional
correctness was not measured. No hidden-test-guided repair retry was made.
Future work must reconstruct whole-file canonical diffs from localized context.

Every executed test ID is an unchanged official `FAIL_TO_PASS` or `PASS_TO_PASS`
ID. The upstream test patch, parser and grader are unchanged. The test command
is narrowed to the complete required-ID lists rather than the full repository
suite, which contains unrelated external-network tests. Reports explicitly set
`official_full_harness_run: false`. This is a **localized, offline required-test
pilot**, not the standard full execution harness.

### Evidence

All paths below are under `artifacts/benchmark_runs/`, with logs and hash-chained
broker audit records alongside the reports:

- 1142 unpatched: `swe-offline-psf__requests-1142-unpatched-9afec66e0bd9/report.json`.
- 1142 reference: `swe-offline-psf__requests-1142-oracle-e61ab64ce308/report.json`.
- 1142 model candidate: `swe-offline-psf__requests-1142-model-8ae823b9aee8/report.json`;
  unchanged source hash confirmed after execution. Earlier same-candidate pass:
  `swe-offline-psf__requests-1142-model-dbe338f7ebb4/report.json`.
- 1339 unpatched: `swe-offline-psf__requests-1339-unpatched-a4c2a313a595/report.json`.
- 1339 reference: `swe-offline-psf__requests-1339-oracle-b74124eec039/report.json`.
- 1339 model: `swe-offline-psf__requests-1339-model-6f6fa900be40/report.json`.

The initial 1142 generated candidate encountered an evaluator output-contract
error. Its unchanged patch was recovered from the prepared script and replayed
with `--candidate-file`; the report honestly labels operator-supplied replay and
zero **new** model requests. The original generation used local `qwen2.5:7b`,
not the human patch. Original token usage was lost during that evaluator failure
and is unavailable. The 1339 generation used one request / 1,208 tokens.

Setup failures are retained rather than scored as model failures: zero-spend
budget denial, incorrect runsc working-directory assumption, host file-size
limit conflicting with gVisor memory backing, official image housekeeping HEAD
not matching the base commit despite unchanged application source, output-contract
mismatch, and mixed stdout/stderr corrupting parser markers. The final adapter
declares its output contract and serializes guest output before parsing. The
runner now persists candidate/generation metadata before execution.

## Storage: two different disks

Docker uses `/var/lib/docker` on the **91 GB system partition**, not the project's
502 GB data partition. Checking only `df -h .` missed the limiting disk. The two
pilot image downloads temporarily filled the system partition. Their filesystems
were exported to the data partition, then **only these newly downloaded images
and our three temporary export/smoke containers were removed**. System free
space returned to **4.3 GB**, with **40 GB** free on the data partition.
Extracted filesystems remain available in ignored `.bench/` (~5.9 GB total cache).
Removed images can be downloaded again by digest. Existing user containers,
images, model stores, projects, and caches were untouched.

Read-only audit identified these optional cleanup candidates; none was deleted:

| Candidate | Observed size / realistic savings | Caution |
| --- | --- | --- |
| Docker unused image data | About 10.02 GB reported reclaimable | Inspect exact images; no blanket prune |
| Unused CUDA devel image `520292dbb4f7` | About 9.02 GB unique layers | Keep if used for builds; shared layers are not additional savings |
| `HF_CACHE/xet` transfer cache | About 11 GB, data partition | Does not free system disk; confirm no active downloads |
| Gradle caches | About 8.2 GB, data partition | Rebuild/re-download cost; preserve wrappers/JDKs/source |
| CerynthOS `kernel/build.stale-arch-rebuild` | About 31 GB, data partition | User-owned build tree; owner must confirm obsolete |
| `.cache/uv` | About 350 MB, system partition | Small compared with Docker; use a data-drive cache instead |

`HALLU_MODEL` (~89 GB), `OllamaModels` (~71 GB), VM disks, recordings, and the
99 GB HF model hub are not assumed disposable. Many Aegis images share nearly
all their layers: summing virtual sizes exaggerates potential savings.

## Downloads and provenance

- Original SWE-bench metadata revision:
  `e48e2bd1e9fecd5bbd641e9414ac59da9f2e69f6`. The small Parquet file includes
  2,294 task rows, not 2,294 environments. Gold/test fields stay evaluator-side.
- Harness v4.1.0 commit: `726c5461e2ef52d83cf1ea2107870a8bb3328d57`.
  Latest v5 has a different dataset contract and was inspected, not used.
- 1142 image: `swebench/sweb.eval.x86_64.psf_1776_requests-1142` at
  `sha256:b2733e57feb4cfaeac24ab5ec496d4cb89a37db53bd0ca72eaededdb2ce19d1c`.
- 1339 image: `swebench/sweb.eval.x86_64.psf_1776_requests-1339` at
  `sha256:e47079ea07cc6b2c1781ff0c9192845a6e2eee0b04271364ddef5930653dabed`.
- Official gVisor archive checksum verified with SHA-512; runtime reports
  `release-20260921.0`. Runtime and sibling binaries remain together in `.bench/gvisor`.
- Benchmark dependencies use `.bench/venv`, not the main project environment.

## Security and execution

The model receives at most the first 800 characters of the public issue and an
operator-localized source class. No gold patch, hidden tests, credentials, host
paths, or shell tool is supplied. This tests localized repair, not autonomous
source search. Reference-patch runs validate infrastructure only; they are never
a fallback candidate for model generation.

Execution crosses the existing typed `ActionBroker`, deterministic policy and
single-use capability. `benchmark.gvisor` accepts only a known `plan_id`.
It validates target and evaluator-script hash; no arbitrary command/path/flag
parameters are accepted. Commands are constructed only in this narrow adapter.

Rootless gVisor runs with network **none**, no host mounts/socket/credentials,
a cleared environment, and fresh memory overlay. A user-systemd unit enforces
3 GiB memory, 200% CPU quota, 256 tasks, and 300 seconds. Output is bounded;
there is no host fallback. Boundary checks confirm no project/home/Docker socket
inside the guest. Package hashes are checked after execution in the current runner.
Evaluator scripts for other variants are removed inside the ephemeral guest
before applying a candidate. No patch is deployed outside the sandbox.

This backend is **benchmark-only**, not a global upgrade of Docker fixture workers.
Controller/evaluator storage is trusted and locally mutable. Hashes do not
authenticate images or prevent an owner from replacing a complete evidence chain.
Hidden-test access by code during evaluation/test gaming remains a research risk;
absence of tests from inference context is not a complete noninterference proof.

## Reproduction

Requires Linux user namespaces, delegated user-systemd cgroups, verified gVisor
binaries, extracted pinned task images, and installed local Ollama. Check space
on both partitions before pulling. Do not execute upstream builds/tests on the
host or start a rootful benchmark container. Image export is operator setup;
the agent never receives Docker control.

```bash
git clone --depth 1 --branch v4.1.0 https://github.com/SWE-bench/SWE-bench.git /tmp/aegis-swe-v410-20260930
uv venv --python 3.12 .bench/venv
uv pip install --no-cache --python .bench/venv/bin/python -e /tmp/aegis-swe-v410-20260930 'pydantic>=2.11,<3'
curl -fL 'https://huggingface.co/datasets/princeton-nlp/SWE-bench/resolve/e48e2bd1e9fecd5bbd641e9414ac59da9f2e69f6/data/test-00000-of-00001.parquet' -o .bench/swe-test.parquet
```

Prepare `.bench/gvisor/runsc`, its sibling binaries and `.bench/runsc-state` per
the official installation guide. Pull each pinned image, create a **stopped**
temporary container, and export its filesystem to `.bench/<instance>/rootfs`.
This session's two filesystems are already prepared. Never use `runsc do`'s
default host root `/`, host networking, writable-host mode, or arbitrary volumes.

```bash
.bench/venv/bin/python scripts/run_swe_offline_pilot.py --instance psf__requests-1142 --variant unpatched
.bench/venv/bin/python scripts/run_swe_offline_pilot.py --instance psf__requests-1142 --variant oracle
.bench/venv/bin/python scripts/run_swe_offline_pilot.py --instance psf__requests-1142 --variant model
```

`--candidate-file PATH` evaluates an unchanged precomputed candidate without a
model call; attribution is labelled operator-supplied replay, not authenticated
model provenance. Do not regenerate repeatedly until a task passes.

Still needed: whole-file diff reconstruction, the third selected task, more
representative samples, a truly executed equal-budget basic-agent comparator,
external cyber-repair suites, production hardening and contributor/release readiness.

Primary sources: [official harness](https://www.swebench.com/SWE-bench/reference/harness/),
[v4.1.0 code](https://github.com/SWE-bench/SWE-bench/tree/v4.1.0),
[pinned dataset](https://huggingface.co/datasets/princeton-nlp/SWE-bench/tree/e48e2bd1e9fecd5bbd641e9414ac59da9f2e69f6),
[gVisor install](https://gvisor.dev/docs/user_guide/install/),
[rootless execution](https://gvisor.dev/docs/user_guide/rootless/).
