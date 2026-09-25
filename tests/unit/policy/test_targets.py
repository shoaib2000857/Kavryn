from __future__ import annotations

from aegis.domain.scope import ScopePolicy
from aegis.policy.targets import resolve_target


def test_workspace_target_resolves_when_prefix_matches(scope_policy: ScopePolicy) -> None:
    result = resolve_target("workspace://AGE-0001/candidate/patch.diff", scope_policy)
    assert result.resolved


def test_workspace_target_rejects_out_of_scope_path(scope_policy: ScopePolicy) -> None:
    """The acceptance-constraint case: an out-of-scope filesystem path is denied."""
    result = resolve_target("workspace://AGE-0001/../other-case/candidate", scope_policy)
    assert not result.resolved


def test_workspace_target_rejects_unrelated_case_workspace(scope_policy: ScopePolicy) -> None:
    result = resolve_target("workspace://AGE-9999/candidate", scope_policy)
    assert not result.resolved


def test_workspace_target_rejects_traversal_through_allowed_prefix(
    scope_policy: ScopePolicy,
) -> None:
    """A traversal path can share a string prefix with an allowed path
    while resolving somewhere else entirely; it must still be denied."""
    result = resolve_target("workspace://AGE-0001/candidate/../../etc/passwd", scope_policy)
    assert not result.resolved


def test_workspace_target_rejects_sibling_directory_sharing_string_prefix(
    scope_policy: ScopePolicy,
) -> None:
    """workspace://AGE-0001/candidate-evil is not beneath the allowed
    workspace://AGE-0001/candidate prefix, even though it starts with
    the same characters."""
    result = resolve_target("workspace://AGE-0001/candidate-evil/secret", scope_policy)
    assert not result.resolved


def test_workspace_target_resolves_exact_prefix_with_no_trailing_slash(
    scope_policy: ScopePolicy,
) -> None:
    result = resolve_target("workspace://AGE-0001/candidate", scope_policy)
    assert result.resolved


def test_artifact_target_resolves_when_prefix_matches(scope_policy: ScopePolicy) -> None:
    result = resolve_target("artifact://AGE-0001/source/app.py", scope_policy)
    assert result.resolved


def test_artifact_target_rejects_unlisted_prefix(scope_policy: ScopePolicy) -> None:
    result = resolve_target("artifact://AGE-0001/other/app.py", scope_policy)
    assert not result.resolved


def test_asset_target_resolves_to_declared_repository(scope_policy: ScopePolicy) -> None:
    result = resolve_target("asset://demo-api", scope_policy)
    assert result.resolved


def test_asset_target_rejects_unknown_repository(scope_policy: ScopePolicy) -> None:
    result = resolve_target("asset://unknown-repo", scope_policy)
    assert not result.resolved


def test_service_target_resolves_to_declared_service(scope_policy: ScopePolicy) -> None:
    result = resolve_target("service://demo-api-range", scope_policy)
    assert result.resolved


def test_service_target_rejects_unknown_service(scope_policy: ScopePolicy) -> None:
    result = resolve_target("service://unknown-service", scope_policy)
    assert not result.resolved


def test_unrecognized_scheme_is_never_resolved(scope_policy: ScopePolicy) -> None:
    result = resolve_target("ftp://demo-api-range/x", scope_policy)
    assert not result.resolved
