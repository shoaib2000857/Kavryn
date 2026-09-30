# Repair reliability and local operations

Checkpoint: 2026-09-30. This round deliberately makes no inference calls and
does not report new model scores. The stronger-model evaluation is deferred at
the owner's request. Tests of deterministic controls are not model capability
measurements or proof of production safety.

## Try it without a model or Docker

From an installed checkout (`uv sync --extra dev`):

```bash
uv run aegis doctor
uv run aegis demo
uv run aegis demo --fail-verification
```

The demo is an **in-memory simulation** using the actual typed broker,
approval checks, capability issuance, transaction coordinator, postcondition
verification, and receipt construction. The first run commits; the second
fails the simulated benign-availability check and verifies rollback. Approvals
and probes are simulated. No endpoint is contacted, no container is launched,
and no real service is defended. Do not present these runs as cyber benchmarks.

The SDK example is `src/aegis/demo.py`; `run_transaction_demo()` returns a typed
`ExecutionReceipt`. It demonstrates the existing coordinator API rather than
introducing a competing agent framework.

`doctor` reports executable presence and free space on both the system and
workspace filesystems. It does not query providers, test Docker, certify
isolation, install tools, or clear space. This matters because Docker image
layers can fill the system partition even when the dataset partition is free.

## Canonical repair transport

`PatchGenerationRequest.source` is trusted full-file text. For localized repair,
also set `source_span=SourceSpan(start_line=..., end_line=...)`, using one-based,
inclusive lines. Only the selected span is sent to the provider. The control
plane splices the returned replacement into the trusted original full file,
preserving unexposed prefix/suffix text, before constructing the unified diff.
Without a span, the existing whole-file replacement protocol still applies.

The public syntax check parses the reconstructed file, not an indented fragment.
The optional single syntax-feedback retry still provides no hidden-test results.
Invalid span bounds fail before a provider call. Missing-final-newline markers
are generated locally and tested against the real `patch` executable.

Workspace preparation now:

1. Applies scope policy to paired, same-path source/destination headers.
2. Rejects rename, creation/deletion metadata, mode changes, binary patches,
   duplicate sections, and unsafe paths. Supported scope is existing regular
   text-file modification; this is not a general Git patch parser.
3. Verifies the diff digest and trusted source-tree digest.
4. Rejects source symlinks and special files; copies without following links
   and rechecks the copied snapshot's digest.
5. Applies the diff noninteractively with `--fuzz=0`, fixed argv, and stdin;
   no internal patch filename can overwrite a source file.
6. Removes the disposable snapshot on failure. Successful-workspace cleanup
   remains the caller's responsibility.

The independent verifier also checks the diff digest: disagreement is
`CONTROL_FAILURE`, not a passing repair. Unsupported source objects likewise
fail source integrity. Its fixed container entrypoint applies patches with
zero fuzz. These checks do not eliminate concurrent hostile-host races or
authenticate the filesystem owner.

### Failure found during integration

An old integration helper declared a placeholder diff digest. The strengthened
workspace correctly rejected it, which skipped that helper's optional re-scan.
The test-gaming candidate then unexpectedly verified because several hidden
payloads decoded to the same blocked string or referenced nonexistent files.
The helper now declares the actual digest; the owned fixture additionally tests
two distinct, valid paths to its sentinel. This strengthens our synthetic range,
not an external benchmark. Earlier results remain historical; new passes do
not establish arbitrary adversarial-patch resistance.

## Optional durable receipts

Use the same operator-owned `SQLiteEvidenceStore` for the broker's `audit`,
`artifacts`, and `journal`, then opt into the coordinator receipt sink:

```python
broker = ActionBroker(registry=registry, audit=store, artifacts=store, journal=store)
coordinator = ActionTransactionCoordinator(broker, receipts=store)
```

SQLite schema version 3 adds append-once execution receipts, upgrading existing
version 1/2 stores without replacing records. Storage validates receipt hashes,
its terminal journal snapshot, and membership in the verified case audit chain.
A new receipt must bind the current audit head. Identical re-storage is
idempotent; replacement is refused. `receipt_for_transaction(id)` validates
these links again on read. Historical receipts may bind earlier verified heads.

If saving a receipt fails **after** a terminal action, the coordinator raises
`ReceiptPersistenceError`. The action may already be committed. Inspect the
journal/audit; do not retry execution or assume the effect was rolled back.
External mutation and local receipt persistence are not one atomic transaction.

## Inspect without resuming uncertain effects

```bash
uv run aegis journal inspect /operator/selected/evidence.sqlite3 --case AGE-0001
uv run aegis audit verify /operator/export/audit.jsonl
uv run aegis receipt verify /operator/export/receipt.json --audit /operator/export/audit.jsonl
```

Journal inspection opens an existing version 2/3 database in SQLite read-only
mode with query-only enabled: no migrations, SQL writes, missing-database
creation, capabilities, approvals, target calls, replay, or quarantine clearance.
SQLite may still need WAL shared-memory sidecars; this is SQL read-only, not a
claim of zero filesystem activity. Its review flags conservatively identify
executed transactions without recorded commit/rollback, without an action
catalog or external target reconciliation. Output omits request parameters and
raw artifacts. Errors do not echo supplied database contents.

Hashes detect tested corruption relative to retained records; they do not
authenticate writers or detect an attacker replacing an entire database and
its chain. Secure independent anchoring, durable authority, coordinated
multi-process execution, and safe post-crash clearance remain unfinished.

## Next model-enabled round

- Use the same repaired transport for predefined, held-out tasks.
- Run matched raw/basic-harness and Aegis comparisons with the same model,
  inputs, resources, tests, and budgets; retain failures and all denominators.
- Keep capability, safety, efficiency, and intervention metrics separate.
- Re-run the bounded external repair pilot before attempting a larger suite.
- Do not convert our narrowed SWE pilot or this simulation into a full SWE
  score, a general coding uplift, or a learned-monitor claim.

This round adds no secrets, dependencies, model endpoints, target permissions,
or network allow rules. Existing owned Docker integrations exercise actual
repair/containment/deployment behavior; model-specific tests remain opt-in.
