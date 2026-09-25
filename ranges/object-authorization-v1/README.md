# Fixture: object-authorization-v1

An owned, intentionally vulnerable Python/Flask fixture for isolated defensive
research. It now has a deterministic full-case integration through Aegis's
brokered investigation, synthetic-session containment, clean-room repair
verification, deployment, and recovery checks. The integration uses a stub
containment proposal and a pre-authored oracle patch; it does not establish
successful model-generated repair or standard benchmark performance.

Shared range hooks allow owner-configured fixed containment patterns,
route-to-source bindings, and scenario-specific investigation summaries. For
this fixture the fixed proxy blocks only the synthetic Bob test token; it does
not log the Authorization value. The route-prefix telemetry label is a
heuristic candidate signal, not proof of unauthorized access by itself.

## Scenario

The service binds one of two fixed synthetic bearer tokens to an authenticated
principal. It serves each document without comparing that principal to the
document owner (CWE-862 / CWE-639). As a result, Bob can read Alice's synthetic
document. The token map is test scaffolding, not production authentication.

The intended repair is an object-level authorization check before returning the
document. A repaired version must preserve owner access, return 401 for absent or
unknown identities, keep unknown documents at 404, and deny cross-owner reads.

## Test boundaries

- `public_tests/` contains owner-access and missing-document behavior.
- `hidden_tests/` contains cross-owner and invalid-identity checks. Keep it out
  of any future model-writable patch workspace.
- The vulnerable source is immutable benchmark input; patch a disposable copy.

To request a hosted candidate after endpoint authorization is restored, use the
explicitly allowlisted Layer-0 pilot:

```bash
set -a; source .env.local; set +a
uv run python scripts/bench_patch_repair.py --scenario object-authorization-v1 --out artifacts/benchmark_runs/object-authorization-v1.json
```

Only the synthetic `src/app.py` and scenario summary are included in that model
request. Hidden tests are supplied only to the independent verifier.

## Safe fixture check

The optional integration test builds this owned fixture image, then runs Flask's
in-process test client in a disposable container with no network, a read-only
root filesystem, dropped capabilities, resource limits, and no host mounts. The
baseline is expected to demonstrate the cross-owner access flaw; it is not an
Aegis patch-success score.

```bash
uv run pytest tests/integration/test_object_authorization_fixture.py -q -m integration
```

Only use this fixture locally or in an explicitly authorized isolated range.
