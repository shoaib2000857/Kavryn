# Local-model evaluation and current flagship evidence

Updated 2026-09-30. This is a reproducible research checkpoint, not a production release.

## What now works

The installed read-only CLI also supports portable integrity inspection:

```bash
uv run aegis audit verify /path/to/audit.jsonl
uv run aegis receipt verify /path/to/receipt.json --audit /path/to/audit.jsonl
```

Supply `--expected-head HEX_SHA256` from an independently trusted source to check
the audit root. Without such an anchor, complete rewriting/re-hashing remains
possible. The CLI does not authenticate the origin, execute actions, rerun tests,
or prove safety; its output explicitly distinguishes those limits. Inputs are
bounded to 8 MiB, and invalid receipt contents are not echoed in error output.

The installed Ollama `qwen2.5:7b` model completed the owned object-authorization
incident-to-recovery integration: telemetry/static investigation, model containment
proposal, attributed synthetic operator approval, brokered containment, generated
repair, independent clean-room tests, brokered deployment, attack replay, recovery,
and case closure. No oracle patch fallback was used. Source localization and the
repair task's vulnerability summary remain fixture-specific trusted inputs.

The successful [full-case record](../artifacts/benchmark_runs/live-object-auth-case-19032e891ab24a169e56558178a28a32.json)
contains candidates, checks, audit events, source/image/policy hashes, Git revision,
dirty-tree status, and trace. The [failed preceding run](../artifacts/benchmark_runs/live-object-auth-case-48c27753993a49a3bcc2f20be72d6693.json)
is retained: it exposed inconsistent rollout/rollback probes demanding 404 while
the established security tests accepted 403 or 404. Both valid response contracts
are now covered by deterministic full-case integration tests; legitimate owner
access must still succeed.

Separate local repair pilots verified path traversal (10 public/security/regression
tests) and object authorization (5 tests). These are separate attempts under
different protocol flags, **not a combined benchmark pass rate**. The first
unconstrained local attempt omitted required metadata; the first schema-constrained
object patch broke Python string quoting. All failures remain failures.

Some earliest local pilot records retain the compatible client's legacy
`hosted_model`/provider label despite using loopback Ollama. Current runner output
distinguishes local mode and schema/retry protocol flags; historical raw records
were not silently rewritten. Their commands, model ID, and experiment descriptions
establish that these were local calls, not additional hosted-server runs.

## Reproduce the owned-fixture work

Prerequisites: project development environment, local Docker, Ollama listening on
`127.0.0.1:11434`, and `qwen2.5:7b` installed. There is no hosted API credential requirement.
The selected model fits this machine's 8 GB GPU; no claim is made that it is the
best available coding model. No models were downloaded or switched during this work.

```bash
ollama list
uv run python scripts/bench_patch_repair.py --ollama --structured-output \
  --public-syntax-retry --scenario path-traversal-v1
uv run python scripts/compare_repair_gate.py --model qwen2.5:7b --repeats 1
```

The comparison emits fresh JSON records and logs under `artifacts/benchmark_runs/`.
It uses exactly the same generated candidates for both admission policies, with
no hidden-test feedback and no deployment. The optional syntax-retry flag in the
individual repair pilot allows at most one retry from `ast.parse` diagnostics;
it never executes the proposed source on the host. Schema enforcement does not
replace local validation or independent verification.

Run the live incident/repair integration explicitly:

```bash
AEGIS_LIVE_MODEL_REPAIR=1 AEGIS_MODEL_JSON_SCHEMA=1 AEGIS_PUBLIC_SYNTAX_RETRY=1 \
LLM_URL=http://127.0.0.1:11434 LLM_API_KEY=ollama LLM_MODEL=qwen2.5:7b \
uv run pytest -q -s -m integration \
  tests/integration/test_full_object_authorization_case.py
```

`ollama` above is a non-secret placeholder for the compatible client. The command
does not load or overwrite `.env.local`. Approvals are labelled synthetic test
operator approvals, not a deployed human-approval product. Docker lifecycle still
uses the fixed fixture infrastructure, not a generalized production backend.

## Same-candidate gate ablation

The [paired record](../artifacts/benchmark_runs/ollama-ablation-ac9b5cf9e40c42499a40fcbb2a4786c7/summary.json)
contains two candidates from one model: a verified path repair and a syntax-broken
object-authorization repair. An in-scope parsed-candidate baseline would admit
both; Aegis admits only the independently verified candidate. Known failed
admissions go from 1/2 to 0/2: **50 percentage points in this tiny counterfactual
admission experiment**, not 50% better coding, an external benchmark gain, a
comparison with a test-aware CLI, or evidence of statistical significance.

Generation quality is unchanged because candidates are shared. No actual baseline
deployment occurs. The summary is an offline calculation over observed evidence,
not an authenticated safety receipt. Failures of evidence integrity, incomplete
required checks, and infrastructure uncertainty cannot become verified outcomes.

## Official Cyber Defense Benchmark sample measurement

The [upstream MIT-licensed sample/scorer](https://github.com/simbianai/cyber_defense_benchmark)
was pinned at `e8b86d01ccefe338d455e61505ca285943635b27`. Detection reads only
`sample.json`; the separate scorer reads flags after predictions are saved.

| Component on seed 176 | Official coverage | Flags detected | Submitted timestamps |
| --- | ---: | ---: | ---: |
| Deterministic command-rule shortlist | 5.0577% | 80/3,912 | 250 |
| Same shortlist followed by local Qwen triage | 3.2621% | 28/3,912 | 126 |

The model filter **reduced** coverage by 1.7956 percentage points. It ran ten bounded
batches in 85.90 seconds, reporting 55,398 native prompt/completion tokens. At most
two events per shortlisted timestamp and 300 characters per field were supplied;
this context truncation and the shortlist constrain the result. This is not an
open-ended agent hunt, the full multi-seed benchmark, detection precision, or a
repair benchmark. The coverage-only scorer cannot establish whether discarded
timestamps were false positives. Its default `cost_usd=0` is not measured zero
electricity/hardware cost.

[Predictions](../artifacts/benchmark_runs/cdb-public-sample-ollama-triage-v1.json) and
[unmodified upstream scoring results](../artifacts/benchmark_runs/cdb-public-sample-ollama-triage-v1-official-score.json)
are preserved. To reproduce, clone the pinned upstream repository into a separate
directory and use fresh output filenames:

```bash
uv run python scripts/run_cdb_ollama_triage.py \
  --sample-zip /path/to/cyber_defense_benchmark/datasets/sample.zip \
  --out artifacts/benchmark_runs/cdb-local-fresh.json
uv run python scripts/score_cdb_sample.py \
  --upstream /path/to/cyber_defense_benchmark \
  --commit e8b86d01ccefe338d455e61505ca285943635b27 \
  --sample-zip /path/to/cyber_defense_benchmark/datasets/sample.zip \
  --predictions artifacts/benchmark_runs/cdb-local-fresh.json \
  --out artifacts/benchmark_runs/cdb-local-fresh-score.json
```

The local model emits batch IDs only. Strict validation rejects invented IDs,
duplicates, coercion from strings/booleans, and executable/extra fields. There is
no model-to-SQL, shell, network-target, or command execution path in this evaluator.

## What makes this worth pursuing as a flagship

Your [public resume](https://shoaibssm.me/resume/Shoaib_Sadiq_Salehmohamed_Resume.pdf)
already describes applied AI/security systems and representation-level reliability
research. Those are self-reported portfolio details, not independently audited
performance evidence. Aegis's strongest distinct contribution is reusable,
independently verified execution infrastructure, demonstrated by genuine model
repair and recovery—not another collection of agent personas or inflated scores.

The next release requirements remain:

1. A stable public action SDK and domain-neutral worked example outside test helpers;
   the new read-only inspection CLI is not yet an action-running product interface.
2. Durable approval/capability/receipt recovery, authenticated authority boundaries,
   and independently verified quarantine reconciliation.
3. An isolation boundary acceptable for hostile external repository builds, then
   a pinned external repair benchmark with genuine functional/security outcomes.
4. A stronger same-model basic-agent baseline, equal task access and predeclared
   budgets, held-out cases, raw failures, confidence intervals, and overhead reporting.
5. Owner-selected license/disclosure channel and repeatable contributor/release setup.

Update: a localized offline SWE-bench required-test pilot now ran on two Requests
tasks through brokered rootless gVisor. One Qwen candidate passed all six required
tests; the other failed patch application. Both reference patches passed. Third
selected task not run; this is not the full official harness or a leaderboard
score. See [storage, results and reproduction](STORAGE_AND_SWE_PILOT.md).
System/data free space is 4.3 GB/40 GB; Docker uses the system partition.
Full-suite evaluation and stronger fair comparisons remain release requirements.

Behavioral monitoring is advisory and experimental. Learned/hidden-state safety
monitoring, production deployment, complete crash recovery, and broad threat
coverage are not implemented or validated by this checkpoint.
