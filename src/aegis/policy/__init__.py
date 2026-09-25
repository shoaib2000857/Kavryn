"""The deterministic policy engine (docs/IMPLEMENTATION_HANDOFF.md Change 2).

Contains the pure ``evaluate_action_request`` decision function and its
supporting, independently testable pieces: risk-tier classification,
target resolution, and budget accounting. No network, model, or Docker
dependency.
"""

from aegis.policy.approval import Approval, ApprovalDecision, resolve_approval
from aegis.policy.budget import BudgetUsage, exhausted_dimensions
from aegis.policy.decision import evaluate_action_request
from aegis.policy.risk import classify_risk
from aegis.policy.targets import TargetResolution, resolve_target

__all__ = [
    "Approval",
    "ApprovalDecision",
    "BudgetUsage",
    "TargetResolution",
    "classify_risk",
    "evaluate_action_request",
    "exhausted_dimensions",
    "resolve_approval",
    "resolve_target",
]
