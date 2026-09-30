# Kavryn SDK: install, run, and integrate

Kavryn is an **experimental** transactional execution toolkit for AI agents.
Created and maintained by **Shoaib Sadiq Salehmohamed**. Cyber defense is its
reference application. It is not a production security boundary or an agent loop.

## Install from the repository

Python 3.12+ is required. No model, GPU, credentials, or Docker is needed for the
SDK simulation and diagnostics.

```bash
git clone https://github.com/shoaib2000857/Kavryn.git
cd Kavryn
bash scripts/install.sh
bash scripts/run_demo.sh
bash scripts/run_demo.sh --fail-verification
```

The installer creates `.kavryn-venv`, refuses an existing destination, and uses
pip to install the local checkout and dependencies. Package/build dependency
downloads may contact the configured package index. It does not install system
tools, use sudo, grant Docker access, source environment files, or fetch models.
Override `KAVRYN_PYTHON` or `KAVRYN_VENV` when appropriate. Review scripts locally;
there is no curl-to-shell installation path.

Alternatively, inside your own environment:

```bash
python -m pip install .
kavryn --version
kavryn doctor
kavryn demo
kavryn demo --fail-verification
python -m kavryn --help
```

These commands assume this repository has been downloaded. **`pip install kavryn`
from PyPI is not supported until an actual registry release is published.**

## Public Python API

```python
from kavryn import run_transaction_demo, verify_execution_receipt

receipt = run_transaction_demo()
assert verify_execution_receipt(receipt)
print(receipt.disposition)  # committed

restored = run_transaction_demo(fail_verification=True)
print(restored.disposition)  # rolled_back
```

This demo changes only an in-memory simulation. Approvals, service probes, and
verification are simulated; it proves neither real defense nor sandbox isolation.
`examples/transaction_demo.py` exercises both outcomes through the public facade.

For custom integrations, import `ActionBroker`, `AdapterRegistry`,
`ActionDefinition`, `ActionRequest`, `ActionTransactionCoordinator`, `Verifier`,
and the scope/receipt types from `kavryn`. Register a narrow typed adapter and
action definition. Supply operator-owned case/scope, policy version, approvals,
and an independent verifier to `coordinator.execute(...)`. The existing concrete
example lives in `src/aegis/demo.py`. Do not grant the cognition layer direct
access to the broker's mutable internals, host shell, credentials, or Docker socket.

The public facade delegates to existing tested runtime implementations. Legacy
`aegis` imports/CLI remain compatible; versioned `aegis.*` schema IDs and past
evidence records are unchanged. Packaging a Python library does not turn its
in-process authority into an isolated service. The API is alpha and may evolve.

## Inspection commands

```bash
kavryn journal inspect /operator/evidence.sqlite3 --case AGE-0001
kavryn audit verify /operator/audit.jsonl
kavryn receipt verify /operator/receipt.json --audit /operator/audit.jsonl
```

Journal inspection cannot restore authority, replay actions, reconcile target
state, or clear quarantine. Hash checks are not origin authentication or safety
proof. See [Reliability and operations](RELIABILITY_AND_OPERATIONS.md).

## Build downloadable artifacts

```bash
uv sync --locked --extra dev
uv build --out-dir dist
uv run python scripts/check_release.py dist
```

Outputs: `dist/kavryn-0.1.0-py3-none-any.whl` and `dist/kavryn-0.1.0.tar.gz`.
Install a downloaded wheel using `python -m pip install /path/to/kavryn-0.1.0-py3-none-any.whl`.
Build inclusion rules exclude environment files, benchmark caches and result
artifacts. Package archives contain runtime code, not the full Docker range;
use the Git repository for range integration and benchmark tooling. CI builds,
inspects and fresh-installs the wheel without model credentials. Public artifact
hosting/upload is a separate release step; do not invent download links.

## Attribution and contribution

Apache-2.0 permits broad reuse subject to its terms, including preservation of
applicable notices. LICENSE and NOTICE travel in both distributions. Optional
research citation is in CITATION.cff and the README; it is encouraged, not an
extra legal restriction or a guaranteed portfolio link. Third-party tools and
benchmark data keep their own terms and are not relicensed by Kavryn.

See [Contributing](../CONTRIBUTING.md), [Security](../SECURITY.md), and current
[tasks](ACTIVE_TASKS.md) before extending authorization or worker behavior.
