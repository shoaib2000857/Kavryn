"""Target resolution: mapping an ``ActionRequest.target_ref`` to scope.

FR-SCP-003 requires that a target which cannot be resolved to an
explicit scope object is rejected. ``docs/CONTROL_PLANE.md`` specifies
the shape of a scope policy but not an executable resolution algorithm
("The final schema will be versioned and validated; this example is not
executable yet."); the scheme-based resolution below is this project's
implementation of that algorithm (docs/DECISIONS.md ADR-016), not a
resolution of any item in docs/OPEN_QUESTIONS.md.

Resolution rules, by URI scheme of ``target_ref``:

- ``workspace://`` — resolved if it starts with one of
  ``scope.filesystem.write``. This is the case's disposable work area.
- ``artifact://`` — resolved if it starts with one of
  ``scope.filesystem.read``.
- ``asset://`` or ``repo://`` — resolved if the host segment matches a
  declared ``RepositoryTarget.id``.
- ``service://`` — resolved if the host segment matches a declared
  ``ServiceTarget.id``.
- any other scheme, or no match — unresolved.
"""

from __future__ import annotations

from aegis.domain.base import AegisModel
from aegis.domain.scope import ScopePolicy

__all__ = ["TargetResolution", "resolve_target"]


class TargetResolution(AegisModel):
    resolved: bool
    reason: str


def _host(target_ref: str) -> str:
    return target_ref.split("://", 1)[1].split("/", 1)[0]


def _has_path_traversal(target_ref: str) -> bool:
    """True if any path segment after the URI scheme is ``.`` or ``..``.

    Plain prefix matching on a URI string is unsound on its own:
    ``workspace://AGE-0001/candidate/../../etc/passwd`` starts with the
    allowed prefix ``workspace://AGE-0001/candidate`` as a *string*, but
    resolves outside it once ``..`` segments are followed. This check
    runs before any prefix match so such a request is denied rather
    than accidentally permitted (docs/THREAT_MODEL.md T14).
    """
    rest = target_ref.split("://", 1)[1]
    return any(segment in (".", "..") for segment in rest.split("/"))


def _matches_scope_prefix(target_ref: str, prefix: str) -> bool:
    """True if ``target_ref`` is ``prefix`` or a path strictly beneath it.

    A bare ``str.startswith`` check is unsound at path-segment
    boundaries: prefix ``workspace://AGE-0001/candidate`` would also
    match ``workspace://AGE-0001/candidate-evil/secret``, which is a
    different, undeclared path that merely shares a string prefix. This
    requires the match to land exactly on a ``/`` boundary (or be an
    exact match) instead.
    """
    prefix = prefix.rstrip("/")
    return target_ref == prefix or target_ref.startswith(prefix + "/")


def resolve_target(target_ref: str, scope: ScopePolicy) -> TargetResolution:
    scheme = target_ref.split("://", 1)[0]

    if scheme in ("workspace", "artifact") and _has_path_traversal(target_ref):
        return TargetResolution(resolved=False, reason="target path contains a traversal segment")

    if scheme == "workspace":
        if any(_matches_scope_prefix(target_ref, prefix) for prefix in scope.filesystem.write):
            return TargetResolution(resolved=True, reason="matched filesystem.write prefix")
        return TargetResolution(
            resolved=False, reason="no matching filesystem.write prefix in scope"
        )

    if scheme == "artifact":
        if any(_matches_scope_prefix(target_ref, prefix) for prefix in scope.filesystem.read):
            return TargetResolution(resolved=True, reason="matched filesystem.read prefix")
        return TargetResolution(
            resolved=False, reason="no matching filesystem.read prefix in scope"
        )

    if scheme in ("asset", "repo"):
        host = _host(target_ref)
        if any(repo.id == host for repo in scope.targets.repositories):
            return TargetResolution(resolved=True, reason="matched a declared repository target")
        return TargetResolution(
            resolved=False, reason=f"'{host}' is not a declared repository target"
        )

    if scheme == "service":
        host = _host(target_ref)
        if any(service.id == host for service in scope.targets.services):
            return TargetResolution(resolved=True, reason="matched a declared service target")
        return TargetResolution(resolved=False, reason=f"'{host}' is not a declared service target")

    return TargetResolution(resolved=False, reason=f"unrecognized target scheme '{scheme}'")
