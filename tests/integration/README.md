# Integration tests

These tests require a working Docker daemon and the pinned analysis
worker image built from `docker/analysis-worker/Dockerfile` and verifier image
built from `docker/verifier/Dockerfile`. The owned object-authorization fixture
test also builds its local pinned Python image;
that image build installs the pinned Flask dependency from the configured
package index. They are
excluded from the default `pytest -q` run (`tool.pytest.ini_options.testpaths`
is `tests/unit`) because they are slower and depend on host
infrastructure that a fast unit-test loop or CI-without-Docker should
not require.

## Building the pinned image

```bash
docker build -t aegis-analysis-worker:local -f docker/analysis-worker/Dockerfile docker/analysis-worker
docker inspect aegis-analysis-worker:local --format='{{.Id}}'
```

Pass the resulting `sha256:...` id as `AEGIS_ANALYSIS_WORKER_IMAGE` when
running these tests, or the tests will build/inspect it themselves.

## Running

```bash
pytest tests/integration -q -m integration
```

See `docs/DECISIONS.md` ADR-023 for why this project currently uses
standard rootful Docker rather than a rootless backend.

## Live model incident and repair case

The current local Ollama command and successful model-generated full-case record
are documented in [Local evaluation](../../docs/LOCAL_EVALUATION.md).
Set `AEGIS_MODEL_JSON_SCHEMA=1` for compatible schema-constrained patch output;
`AEGIS_PUBLIC_SYNTAX_RETRY=1` permits at most one public Python syntax-feedback
retry, never feedback from hidden security/regression tests. The default scenario
also tests both valid authorization-denial response codes (403/404).

This explicitly enabled test uses the configured model for containment reasoning
and a generated object-authorization patch, then requires clean-room verification,
brokered rollout, and runtime recovery probes. It sends only owned synthetic
fixture context to the endpoint and labels its approvals as simulated test
operator approvals. It is not a standard benchmark.

From the repository root, with the owner-configured ignored environment file:

```bash
set -a
source .env.local
set +a
AEGIS_LIVE_MODEL_REPAIR=1 LLM_MODEL=qwen38 uv run pytest -q -s -m integration \
  tests/integration/test_full_object_authorization_case.py::test_object_authorization_case_with_live_model_reasoning_and_repair
```

The test saves a uniquely named `artifacts/benchmark_runs/live-object-auth-case-*.json`
record before asserting completion, including failed provider/repair traces when
the runner returns them. It attempts one case without a prepared-patch fallback.
Infrastructure failures remain failures. The default suite/CI skips this test.
Do not run two copies simultaneously: the reference case uses fixed container
and network names. The 2026-09-30 attempt returned ngrok HTTP 404/`ERR_NGROK_3200`
before containment; it did not establish hosted full live-model recovery.
The later local Ollama run completed the full case without prepared-patch fallback.
