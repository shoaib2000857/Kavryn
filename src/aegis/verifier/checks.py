"""Individual clean-room verifier checks.

See docs/EVIDENCE_AND_ASSURANCE.md's "Example assurance profile" table.
Container-dependent checks accept an injected runner (default: the real
``run_container``) so their orchestration logic — mount construction,
sentinel handling, JUnit-to-CheckResult translation — is unit-testable
without Docker; genuine end-to-end runs against the real pinned
verifier image and the real fixture are exercised in
``tests/integration``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from aegis.repair.candidate import DiffPolicyError, PatchCandidate, validate_diff_policy
from aegis.repair.hashing import hash_source_tree
from aegis.tools.findings import NormalizedFinding
from aegis.verifier.junit import JUnitParseError, TestOutcome, parse_junit_xml
from aegis.verifier.models import CheckResult, CheckStatus
from aegis.workers.container import ContainerRunResult, ContainerRunSpec
from aegis.workers.container import run_container as _default_run_container

__all__ = [
    "check_clean_room_tests",
    "check_diff_policy",
    "check_security_rescan",
    "check_source_integrity",
]

# The entrypoint script's own sentinel exit code for "could not even
# reach the test-running stage" (patch failed to apply, or the patched
# source failed to import) -- see docker/verifier/entrypoint.sh.
_BUILD_FAILURE_EXIT_CODE = 2


def check_source_integrity(candidate: PatchCandidate, *, trusted_source_dir: str) -> CheckResult:
    """Recompute the base source digest independently and compare.

    A mismatch means either the candidate misrepresented what it
    patched against, or the pinned base source itself was tampered
    with — either way this is an integrity failure, not an ordinary
    rejection (docs/EVIDENCE_AND_ASSURANCE.md: "evidence digest/
    signature mismatch").
    """
    try:
        actual = hash_source_tree(trusted_source_dir)
    except (OSError, ValueError):
        return CheckResult(
            check_id="source_integrity",
            status=CheckStatus.FAIL,
            hard_failure=True,
            detail="trusted source snapshot contains unreadable or unsupported filesystem objects",
        )
    if actual != candidate.base_source_digest:
        return CheckResult(
            check_id="source_integrity",
            status=CheckStatus.FAIL,
            hard_failure=True,
            detail=(
                f"candidate base_source_digest={candidate.base_source_digest.digest} does not "
                f"match the verifier's own recomputed digest={actual.digest}"
            ),
        )
    return CheckResult(
        check_id="source_integrity",
        status=CheckStatus.PASS,
        hard_failure=True,
        detail="candidate's claimed base source digest matches the verifier's own copy",
    )


def check_diff_policy(candidate: PatchCandidate, *, allowed_files: frozenset[str]) -> CheckResult:
    """Re-validate diff policy independently; never trust that the patch
    worker's own check actually ran (docs/DECISIONS.md ADR-009)."""
    if hashlib.sha256(candidate.diff.encode()).hexdigest() != candidate.diff_digest.digest:
        return CheckResult(
            check_id="diff_integrity",
            status=CheckStatus.FAIL,
            hard_failure=True,
            detail="candidate diff content differs from its declared digest",
        )
    try:
        validate_diff_policy(candidate.diff, allowed_files=allowed_files)
    except DiffPolicyError as exc:
        return CheckResult(
            check_id="diff_policy", status=CheckStatus.FAIL, hard_failure=True, detail=str(exc)
        )
    return CheckResult(
        check_id="diff_policy", status=CheckStatus.PASS, hard_failure=True, detail="within policy"
    )


def _group_outcomes(outcomes: tuple[TestOutcome, ...]) -> dict[str, list[TestOutcome]]:
    groups: dict[str, list[TestOutcome]] = {"public": [], "exploit_replay": [], "regression": []}
    for outcome in outcomes:
        if "test_exploit_replay" in outcome.classname:
            groups["exploit_replay"].append(outcome)
        elif "test_regression" in outcome.classname:
            groups["regression"].append(outcome)
        else:
            groups["public"].append(outcome)
    return groups


def check_clean_room_tests(
    *,
    image_ref: str,
    trusted_source_dir: str,
    diff_file: str,
    public_tests_dir: str,
    hidden_tests_dir: str,
    timeout_seconds: int = 120,
    runner: Callable[[ContainerRunSpec], ContainerRunResult] = _default_run_container,
) -> tuple[CheckResult, ...]:
    """Run the verifier container and translate its result into checks.

    Always mounts the base source and hidden tests read-only and
    reconstructs the candidate inside the container itself
    (docker/verifier/entrypoint.sh) — the caller's already-patched tree,
    if any, is never trusted or even referenced here.
    """
    spec = ContainerRunSpec(
        image=image_ref,
        command=("/entrypoint.sh",),
        read_only_mounts=(
            (trusted_source_dir, "/base"),
            (diff_file, "/candidate/patch.diff"),
            (public_tests_dir, "/tests/public"),
            (hidden_tests_dir, "/tests/hidden"),
        ),
        network="none",
        timeout_seconds=timeout_seconds,
        memory_mb=512,
        cpus=1.0,
    )
    result = runner(spec)

    if result.timed_out:
        return (
            CheckResult(
                check_id="clean_room_tests",
                status=CheckStatus.ERROR,
                hard_failure=True,
                detail="verifier container timed out",
            ),
        )

    if result.exit_code == _BUILD_FAILURE_EXIT_CODE:
        return (
            CheckResult(
                check_id="clean_build",
                status=CheckStatus.FAIL,
                hard_failure=True,
                detail=(result.stdout + result.stderr)[-2000:],
            ),
        )

    try:
        outcomes = parse_junit_xml(result.stdout)
    except JUnitParseError as exc:
        return (
            CheckResult(
                check_id="clean_room_tests",
                status=CheckStatus.ERROR,
                hard_failure=True,
                detail=f"could not parse verifier output: {exc}",
            ),
        )

    checks = []
    for check_id, group in _group_outcomes(outcomes).items():
        if not group:
            checks.append(
                CheckResult(
                    check_id=check_id,
                    status=CheckStatus.ERROR,
                    hard_failure=True,
                    detail="no tests were collected for this group",
                )
            )
            continue
        failed = [o for o in group if not o.passed]
        if failed:
            detail = "; ".join(f"{o.classname}::{o.name}: {o.message}" for o in failed)[:2000]
            checks.append(
                CheckResult(
                    check_id=check_id, status=CheckStatus.FAIL, hard_failure=True, detail=detail
                )
            )
        else:
            checks.append(
                CheckResult(
                    check_id=check_id,
                    status=CheckStatus.PASS,
                    hard_failure=True,
                    detail=f"{len(group)} test(s) passed",
                )
            )
    return tuple(checks)


def check_security_rescan(
    findings_before: tuple[NormalizedFinding, ...], findings_after: tuple[NormalizedFinding, ...]
) -> CheckResult:
    """Compare a pre-patch and post-patch static-analysis scan.

    The original finding surviving the patch is a hard failure. A brand
    new finding is flagged for review but is not itself non-compensating
    (docs/EVIDENCE_AND_ASSURANCE.md lists "unexplained removal/weakening
    of security tests" as the hard-failure case, not "any new finding").
    """
    before_ids = {finding.rule_id for finding in findings_before}
    still_present = sorted({f.rule_id for f in findings_after if f.rule_id in before_ids})
    new_findings = sorted({f.rule_id for f in findings_after if f.rule_id not in before_ids})

    if still_present:
        return CheckResult(
            check_id="security_rescan",
            status=CheckStatus.FAIL,
            hard_failure=True,
            detail=f"original finding(s) still present after patching: {still_present}",
        )
    if new_findings:
        return CheckResult(
            check_id="security_rescan",
            status=CheckStatus.FAIL,
            hard_failure=False,
            detail=f"new finding(s) introduced, review required: {new_findings}",
        )
    return CheckResult(
        check_id="security_rescan",
        status=CheckStatus.PASS,
        hard_failure=False,
        detail="no original finding remains and no new finding was introduced",
    )
