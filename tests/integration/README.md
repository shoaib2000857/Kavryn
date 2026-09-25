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
