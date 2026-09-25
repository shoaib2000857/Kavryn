"""Risk-tier classification for action types.

See docs/CONTROL_PLANE.md "Risk tiers". Risk is a property of the
action type and context, assigned here by the policy engine — never
supplied by the reasoning plane on an ``ActionRequest``
(docs/ARCHITECTURE.md: "Risk is determined by the action and context,
not by the model's label.").

The mapping is keyed by the action-type namespace (the segment before
the first dot, e.g. ``"test"`` for ``"test.run"``), matching the
examples in docs/CONTROL_PLANE.md's risk-tier table and action-broker
contract. It is deliberately small and will grow only as new action
namespaces are introduced with a documented rationale (see ADR-017 in
docs/DECISIONS.md); an unrecognized namespace is intentionally left
unclassified so callers fail closed rather than guess a tier.
"""

from __future__ import annotations

from aegis.domain.policy import RiskTier

__all__ = ["classify_risk"]

_NAMESPACE_RISK_TIER: dict[str, RiskTier] = {
    "evidence": RiskTier.R0_OBSERVE,
    "scan": RiskTier.R1_ANALYZE,
    "dependency": RiskTier.R1_ANALYZE,
    "secret": RiskTier.R1_ANALYZE,
    "patch": RiskTier.R1_ANALYZE,
    "test": RiskTier.R2_VALIDATE,
    "http": RiskTier.R2_VALIDATE,
    "contain": RiskTier.R3_REVERSIBLE_RESPONSE,
    "deployment": RiskTier.R4_CHANGE,
    "build": RiskTier.R4_CHANGE,
    "host": RiskTier.R5_HIGH_IMPACT,
    "iam": RiskTier.R5_HIGH_IMPACT,
    "audit": RiskTier.R5_HIGH_IMPACT,
}


def classify_risk(action_type: str) -> RiskTier | None:
    """Return the risk tier for ``action_type``, or ``None`` if unrecognized.

    ``action_type`` is already validated as a dotted ``namespace.verb``
    identifier by ``aegis.domain.base.ActionId``; only the namespace
    segment is used for classification.
    """
    namespace = action_type.split(".", 1)[0]
    return _NAMESPACE_RISK_TIER.get(namespace)
