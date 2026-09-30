"""Opt-in SWE-bench pilot: required official tests, rootless offline execution.

Run with the separate .bench venv containing pinned SWE-bench v4.1.0 and pyarrow.
No image download/build occurs here. The operator must extract the pinned image
to .bench/<instance>/rootfs without starting a rootful Docker container.
Model input contains the public issue and a localized source class only; never
the developer patch or evaluator tests. This is NOT the full official harness.
"""

from __future__ import annotations

import argparse
import ast
import base64
import json
import shlex
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.benchmarks.gvisor import EvaluationPlan, GVisorEvaluationAdapter  # noqa: E402
from aegis.broker.broker import ActionBroker  # noqa: E402
from aegis.broker.registry import AdapterRegistry  # noqa: E402
from aegis.domain import (  # noqa: E402
    ActionsPolicy,
    Authorization,
    Budgets,
    Case,
    FilesystemPolicy,
    NetworkPolicy,
    RepositoryTarget,
    ScopePolicy,
    Targets,
    ToolsPolicy,
)
from aegis.domain.action import ActionRequest  # noqa: E402
from aegis.domain.base import ActorRole  # noqa: E402
from aegis.evidence.audit import InMemoryAuditSink, verify_audit_chain  # noqa: E402
from aegis.evidence.store import InMemoryArtifactStore, sha256_digest  # noqa: E402
from aegis.providers.hosted import HostedProviderConfig  # noqa: E402
from aegis.repair.candidate import validate_diff_policy  # noqa: E402
from aegis.repair.hashing import hash_source_tree  # noqa: E402
from aegis.repair.provider import HostedPatchProvider, PatchGenerationRequest  # noqa: E402
from aegis.repair.source import SourceSpan  # noqa: E402

SELECTED = ("psf__requests-1142", "psf__requests-1327", "psf__requests-1339")
CONTEXT = {
    "psf__requests-1142": ("requests/models.py", "PreparedRequest"),
    "psf__requests-1327": ("requests/sessions.py", "Session"),
    "psf__requests-1339": ("requests/structures.py", "CaseInsensitiveDict"),
}
IMAGES = {
    "psf__requests-1142": "sha256:b2733e57feb4cfaeac24ab5ec496d4cb89a37db53bd0ca72eaededdb2ce19d1c",
    "psf__requests-1339": "sha256:e47079ea07cc6b2c1781ff0c9192845a6e2eee0b04271364ddef5930653dabed",
}


def source_class_span(path: Path, name: str) -> SourceSpan:
    """Source-only localization; no test/gold information determines this span."""
    source = path.read_text()
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == name)
    if node.end_lineno is None:
        raise ValueError("source class has no bounded line range")
    return SourceSpan(start_line=node.lineno, end_line=node.end_lineno)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", choices=tuple(IMAGES), default=SELECTED[0])
    parser.add_argument("--variant", choices=("unpatched", "oracle", "model"), required=True)
    parser.add_argument("--candidate-file", type=Path, help="Operator-supplied candidate replay.")
    args = parser.parse_args()
    # Optional benchmark dependencies never become runtime dependencies.
    import pyarrow.parquet as parquet  # type: ignore[import-not-found]
    from swebench.harness.grading import get_eval_report  # type: ignore[import-not-found]
    from swebench.harness.test_spec.test_spec import (  # type: ignore[import-not-found]
        make_test_spec,
    )

    rows = parquet.read_table(ROOT / ".bench/swe-test.parquet").to_pylist()
    selected = tuple(sorted(r["instance_id"] for r in rows if r["repo"] == "psf/requests")[:3])
    if selected != SELECTED:
        raise ValueError("dataset does not match the predeclared selection")
    row = next(r for r in rows if r["instance_id"] == args.instance)
    spec = make_test_spec(row, namespace="swebench")
    rootfs = ROOT / ".bench" / args.instance / "rootfs"
    if not (rootfs / "testbed/.git").exists():
        raise ValueError("operator-prepared image filesystem is missing")
    source_file, class_name = CONTEXT[args.instance]
    source_digest = hash_source_tree(rootfs / "testbed/requests")
    run_id = f"swe-offline-{args.instance}-{args.variant}-{uuid4().hex[:12]}"
    out = ROOT / "artifacts/benchmark_runs" / run_id
    out.mkdir(parents=True)
    case_id = "AGE-SWE-" + args.instance.rsplit("-", 1)[1]
    request_count = 0
    usage = None
    # Produce the candidate BEFORE constructing the private test script.
    if args.candidate_file is not None:
        if args.variant != "model":
            raise ValueError("candidate replay requires the model variant")
        patch = args.candidate_file.read_text()
        validate_diff_policy(patch, allowed_files=frozenset({source_file}))
    elif args.variant == "oracle":
        patch = row["patch"]
    elif args.variant == "model":
        provider = HostedPatchProvider(
            HostedProviderConfig(
                base_url="http://127.0.0.1:11434/v1", model="qwen2.5:7b", timeout_seconds=180
            ),
            api_key="local-ollama-no-secret",
            structured_output=True,
            public_syntax_retry=True,
        )
        generated = provider.generate_with_metadata(
            PatchGenerationRequest(
                case_id=case_id,
                base_repository=row["repo"],
                base_source_digest=source_digest,
                source_file=source_file,
                source=(rootfs / "testbed" / source_file).read_text(),
                source_span=source_class_span(rootfs / "testbed" / source_file, class_name),
                vulnerability_summary=row["problem_statement"][:800]
                + "\nContext is the complete localized class, not the entire file. "
                "Return this class only, preserving indentation and other methods.",
                allowed_files=frozenset({source_file}),
            )
        )
        patch = generated.candidate.diff
        request_count = generated.provider_requests
        usage = generated.usage.model_dump(mode="json") if generated.usage else None
    else:
        patch = ""
    now = datetime.now(UTC)
    (out / "candidate.diff").write_text(patch)
    (out / "generation.json").write_text(
        json.dumps(
            {
                "instance_id": args.instance,
                "variant": args.variant,
                "model": "qwen2.5:7b" if args.variant == "model" else None,
                "requests": request_count,
                "candidate_replay": args.candidate_file is not None,
                "usage": usage,
                "candidate_digest": sha256_digest(patch.encode()).digest,
            },
            indent=2,
        )
        + "\n"
    )
    # Required test IDs are unchanged. Unrelated network-dependent tests are
    # omitted; this execution deviation is explicit in every report.
    required = list(dict.fromkeys(spec.FAIL_TO_PASS + spec.PASS_TO_PASS))
    original_command = "pytest -rA test_requests.py"
    if spec.eval_script.count(original_command) != 1:
        raise ValueError("unrecognized official evaluation script; refuse substitution")
    official = spec.eval_script.replace(
        original_command, "pytest -rA " + " ".join(shlex.quote(t) for t in required)
    )
    encoded = base64.b64encode(patch.encode()).decode()
    prefix = (
        "#!/bin/bash\nset -euo pipefail\n"
        "exec 3>&1\nexec > /tmp/aegis-combined.log 2>&1\n"
        "trap 'status=$?; cat /tmp/aegis-combined.log >&3; exit \"$status\"' EXIT\n"
        "ulimit -f 8192\n"
        "test ! -e /var/run/docker.sock\n"
        "test ! -e /media/shoaib/LinuxStore\n"
        "test ! -e /home/shoaib\n"
        'test -z "${LLM_API_KEY:-}"\n'
        "echo AEGIS_BOUNDARY_CHECKS_PASSED\n"
        "rm -f /aegis-eval/unpatched.sh /aegis-eval/oracle.sh /aegis-eval/model.sh\n"
        "cd /testbed\n"
        "git config --global --add safe.directory /testbed\n"
        f"git diff --quiet {shlex.quote(row['base_commit'])} -- requests\n"
        f"printf %s {shlex.quote(encoded)} | base64 -d > /tmp/candidate.diff\n"
    )
    if patch:
        prefix += "git apply --check /tmp/candidate.diff\ngit apply /tmp/candidate.diff\n"
    # Execute the upstream script verbatim apart from required-test selection.
    script = prefix + "set +e\n" + official
    script_dir = rootfs / "aegis-eval"
    script_dir.mkdir(exist_ok=True)
    script_path = script_dir / f"{args.variant}.sh"
    script_path.write_text(script)
    target = f"workspace://{case_id}/candidate"
    plan = EvaluationPlan(
        rootfs=rootfs,
        script_name=args.variant,
        script_digest=sha256_digest(script.encode()).digest,
        target_ref=target,
    )
    adapter = GVisorEvaluationAdapter(
        runsc=ROOT / ".bench/gvisor/runsc",
        state_root=ROOT / ".bench/runsc-state",
        plans={args.variant: plan},
    )
    registry = AdapterRegistry()
    registry.register(adapter)
    audit = InMemoryAuditSink()
    broker = ActionBroker(registry=registry, audit=audit, artifacts=InMemoryArtifactStore())
    scope = ScopePolicy(
        case_id=case_id,
        version=1,
        authorization=Authorization(expires_at=now + timedelta(hours=1)),
        targets=Targets(repositories=(RepositoryTarget(id="requests", commit=row["base_commit"]),)),
        network=NetworkPolicy(),
        filesystem=FilesystemPolicy(write=(target,)),
        tools=ToolsPolicy(allow=(adapter.descriptor.id,)),
        actions=ActionsPolicy(auto=("test.run",)),
        budgets=Budgets(tool_calls=1, model_tokens=32768, wall_time_seconds=600, spend_usd=1),
    )
    case = Case(
        id=case_id,
        title=f"Authorized offline SWE-bench pilot {args.instance}",
        created_at=now,
        created_by="operator:benchmark",
        scope_ref=f"scope://{case_id}/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    outcome = broker.submit(
        ActionRequest(
            id="req-" + uuid4().hex,
            case_id=case_id,
            actor_id="verifier:benchmark",
            role=ActorRole.REASONING_RUNTIME,
            action_type="test.run",
            target_ref=target,
            adapter=adapter.descriptor.id,
            parameters={"plan_id": args.variant},
            reason="Evaluate the fixed authorized benchmark plan, without host or network access.",
            requested_at=now,
        ),
        case=case,
        scope=scope,
        now=now,
        decision_id="dec-" + uuid4().hex,
        policy_version="swe-offline-pilot-v1",
    )
    result = outcome.result
    base_unchanged = hash_source_tree(rootfs / "testbed/requests") == source_digest
    log = str(result.output.get("log", "")) if result else ""
    log_path = out / "test_output.txt"
    log_path.write_text(log)
    prediction = {
        "instance_id": args.instance,
        "model_name_or_path": "qwen2.5:7b" if args.variant == "model" else args.variant,
        "model_patch": patch,
    }
    report = get_eval_report(spec, prediction, str(log_path), include_tests_status=True)
    events = audit.events_for_case(case_id)
    (out / "audit.jsonl").write_text("".join(e.model_dump_json() + "\n" for e in events))
    (out / "candidate.diff").write_text(patch)
    record = {
        "benchmark": "SWE-bench original: localized offline required-test pilot",
        "official_full_harness_run": False,
        "selection": list(SELECTED),
        "instance_id": args.instance,
        "variant": args.variant,
        "dataset_revision": "e48e2bd1e9fecd5bbd641e9414ac59da9f2e69f6",
        "harness_revision": "726c5461e2ef52d83cf1ea2107870a8bb3328d57",
        "image_digest": IMAGES[args.instance],
        "source_digest": source_digest.model_dump(mode="json"),
        "localization_assistance": {"file": source_file, "class": class_name},
        "model_requests": request_count,
        "candidate_replay": args.candidate_file is not None,
        "candidate_origin": (
            "operator_supplied_replay" if args.candidate_file is not None else args.variant
        ),
        "usage": usage,
        "gold_and_hidden_tests_sent_to_model": False,
        "network": "none",
        "isolation": "rootless gVisor release-20260921.0; memory overlay; user systemd cgroups",
        "required_tests": required,
        "script_digest": plan.script_digest,
        "log_digest": sha256_digest(log.encode()).digest,
        "policy_outcome": outcome.decision.outcome.value,
        "policy_reasons": list(outcome.decision.reasons),
        "execution_status": result.exit_status if result else "control_failure",
        "trusted_base_unchanged": base_unchanged,
        "duration_seconds": result.duration_seconds if result else None,
        "official_grader_report": report,
        "audit_valid": verify_audit_chain(events),
        "audit_head": events[-1].integrity.digest if events else None,
        "caveats": [
            "Only official FAIL_TO_PASS/PASS_TO_PASS IDs executed, not full repository suite.",
            "Model received a localized source class and public issue, not autonomous search.",
            "Unpatched/oracle runs validate infrastructure; neither is a basic-agent baseline.",
            "No full SWE-bench score or harness capability uplift can be inferred.",
        ],
    }
    (out / "report.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"output": str(out), "report": record}, indent=2))
    return 0 if result and result.exit_status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
