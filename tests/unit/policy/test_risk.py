from __future__ import annotations

import pytest

from aegis.domain.policy import RiskTier
from aegis.policy.risk import classify_risk


@pytest.mark.parametrize(
    ("action_type", "expected"),
    [
        ("evidence.read", RiskTier.R0_OBSERVE),
        ("telemetry.read", RiskTier.R0_OBSERVE),
        ("scan.run", RiskTier.R1_ANALYZE),
        ("patch.propose", RiskTier.R1_ANALYZE),
        ("test.run", RiskTier.R2_VALIDATE),
        ("http.replay", RiskTier.R2_VALIDATE),
        ("contain.rate_limit", RiskTier.R3_REVERSIBLE_RESPONSE),
        ("deployment.rollout", RiskTier.R4_CHANGE),
        ("host.shell", RiskTier.R5_HIGH_IMPACT),
        ("iam.admin", RiskTier.R5_HIGH_IMPACT),
        ("audit.modify", RiskTier.R5_HIGH_IMPACT),
    ],
)
def test_classify_risk_matches_control_plane_examples(action_type: str, expected: RiskTier) -> None:
    assert classify_risk(action_type) is expected


def test_classify_risk_returns_none_for_unknown_namespace() -> None:
    assert classify_risk("unknown_namespace.do_thing") is None
