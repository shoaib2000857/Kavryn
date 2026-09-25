"""The explicit case workflow state machine (docs/IMPLEMENTATION_HANDOFF.md Change 2).

See docs/WORKFLOWS.md for the state diagram this module implements.
"""

from aegis.workflow.states import TERMINAL_STATES, CaseState, Trigger
from aegis.workflow.transitions import InvalidTransitionError, allowed_triggers, apply_transition

__all__ = [
    "TERMINAL_STATES",
    "CaseState",
    "InvalidTransitionError",
    "Trigger",
    "allowed_triggers",
    "apply_transition",
]
