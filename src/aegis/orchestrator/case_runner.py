"""The Change 8 case orchestrator: incident states wired to repair/recovery.

Drives the real Change 2 workflow state machine (``apply_transition``)
using real outcomes from the real subsystems built in Changes 3, 5, 6,
and 7 — never inventing a transition the accepted state diagram
(docs/WORKFLOWS.md) does not define. Every Docker-backed or
provider-backed step is injected via ``CaseDependencies`` so the
orchestration logic itself is fully unit-testable with the Change 3
stub/replay providers and fake callables; a genuine end-to-end run
wires the real Change 5/6/7 infrastructure as those same callables.

Two deliberate, documented simplifications, both directly grounded in
accepted docs rather than invented:

- Containment and deployment always route through their approval gates
  (``RISK_REQUIRES_APPROVAL``, never ``POLICY_PERMITS``), matching
  docs/WORKFLOWS.md's "Human checkpoints in early releases": "executing
  any containment, even reversible, until policy evaluation is
  validated" and "deploying any patch to the range service."
- Where a real outcome does not correspond to any edge the accepted
  diagram defines from the current state (e.g. the provider declines to
  propose an action at all), the case halts at its current state with
  an explanatory note rather than forcing a transition that was never
  accepted — "a safe stop, refusal, or escalation is a successful
  outcome when evidence is insufficient" (README.md).

A retry (containment or repair) re-runs its *entire* propose/approve/
apply/verify sub-sequence, never just re-checks a stale result — an
ineffective containment rule does not become effective by asking twice
without changing anything.

Every transition goes through ``CaseTrace.advance``, which records the
new state as part of applying it — there is no code path that can
change ``state`` without that change landing in the trace (the first
draft of this function had exactly that bug in four places, caught by
``tests/unit/orchestrator/test_case_runner.py``'s exact-state-sequence
assertion, not by inspection).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field

from aegis.providers.base import ReasoningProvider
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ProposalKind,
    ReasoningTask,
    StructuredProposal,
    TaskRole,
    ToolDescriptor,
)
from aegis.repair.candidate import PatchCandidate
from aegis.verifier.models import AssuranceOutcome
from aegis.workflow.states import CaseState, Trigger
from aegis.workflow.transitions import apply_transition

__all__ = ["CaseDependencies", "CaseTrace", "run_case"]


@dataclass(frozen=True)
class CaseDependencies:
    """Every real-world step the orchestrator does not decide for itself.

    Boolean-returning callables report a fact the orchestrator then
    maps onto a workflow trigger; the orchestrator never inspects *how*
    that fact was determined (a real Docker-backed check, or a canned
    test value).
    """

    provider: ReasoningProvider
    exploit_reachable: Callable[[], bool]
    approve_containment: Callable[[], bool]
    apply_containment: Callable[[], None]
    rollback_containment: Callable[[], None]
    attack_blocked: Callable[[], bool]
    benign_available: Callable[[], bool]
    generate_candidate: Callable[[], PatchCandidate]
    verify_candidate: Callable[[PatchCandidate], AssuranceOutcome]
    approve_deployment: Callable[[], bool]
    recovery_attack_blocked: Callable[[], bool]
    recovery_benign_available: Callable[[], bool]
    recurrence_detected: Callable[[], bool] = lambda: False
    containment_tools: tuple[ToolDescriptor, ...] = ()
    max_containment_attempts: int = 2
    max_repair_attempts: int = 2


@dataclass
class CaseTrace:
    """A human-and-machine-readable record of every state the case visited.

    ``advance`` is the only sanctioned way to change ``state`` while
    building a trace: it applies the transition and records the
    resulting state in the same step, so the two can never drift apart.
    """

    case_id: str
    states: list[CaseState] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    halted: bool = False
    halt_reason: str = ""

    def note(self, text: str) -> None:
        """Attach a note to the current state without transitioning."""
        self.states.append(self.final_state)
        self.notes.append(text)

    def advance(self, trigger: Trigger, note: str) -> CaseState:
        new_state = apply_transition(self.final_state, trigger)
        self.states.append(new_state)
        self.notes.append(note)
        return new_state

    def halt(self, reason: str) -> CaseTrace:
        self.halted = True
        self.halt_reason = reason
        self.notes[-1] = f"{self.notes[-1]} — HALTED: {reason}"
        return self

    @property
    def final_state(self) -> CaseState:
        return self.states[-1]


async def _propose(
    provider: ReasoningProvider,
    *,
    case_id: str,
    role: TaskRole,
    instructions: str,
    summary: str,
    tools: tuple[ToolDescriptor, ...] = (),
) -> StructuredProposal:
    task = ReasoningTask(role=role, case_id=case_id, instructions=instructions)
    context = EvidenceContext(case_id=case_id, summary=summary)
    limits = InferenceLimits(max_output_tokens=1000, max_tool_calls=5, timeout_seconds=30)
    return await provider.propose(task, context, tools, limits)


def _propose_or_none(
    provider: ReasoningProvider,
    *,
    case_id: str,
    role: TaskRole,
    instructions: str,
    summary: str,
    tools: tuple[ToolDescriptor, ...] = (),
) -> tuple[StructuredProposal | None, str | None]:
    """Call the provider and return ``(proposal, None)``, or ``(None, reason)``
    if the provider raised anything at all.

    docs/MODEL_STRATEGY.md: "provider response treated as untrusted."
    That includes the provider failing outright -- a bad/unreachable
    hosted endpoint, or (as found live, against a real local model) a
    real response that never becomes schema-valid even after its own
    bounded-repair budget is exhausted. docs/WORKFLOWS.md's failure
    semantics table calls this "Model unavailable... pause safely," not
    a reason to crash the whole case. Deliberately broad: any provider
    implementation can fail in an implementation-specific way, and the
    orchestrator's job here is only to never trust that failure mode to
    be well-behaved.
    """
    try:
        proposal = asyncio.run(
            _propose(
                provider,
                case_id=case_id,
                role=role,
                instructions=instructions,
                summary=summary,
                tools=tools,
            )
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return proposal, None


def run_case(case_id: str, deps: CaseDependencies) -> CaseTrace:
    trace = CaseTrace(case_id=case_id, states=[CaseState.INTAKE], notes=["case intake"])

    trace.advance(Trigger.ADVANCE, "scope accepted")
    trace.advance(Trigger.ADVANCE, "telemetry observed")
    trace.advance(Trigger.ADVANCE, f"triaged: exploit_reachable={deps.exploit_reachable()}")
    trace.advance(Trigger.ADVANCE, "investigated: candidate hypothesis formed")
    trace.advance(Trigger.ADVANCE, "ready to propose containment")

    contained = False
    for attempt in range(1, deps.max_containment_attempts + 1):
        proposal, failure = _propose_or_none(
            deps.provider,
            case_id=case_id,
            role=TaskRole.CONTAINMENT_PLANNING,
            instructions=(
                "Propose a reversible containment action for the observed suspicious traffic. "
                "The adapter field must be exactly the id of one of the tools listed below."
            ),
            summary="Suspicious path-traversal-shaped requests observed against the range.",
            tools=deps.containment_tools,
        )
        if failure is not None:
            trace.note(f"provider failed to produce a containment proposal: {failure}")
            return trace.halt("containment proposal failed (provider error)")
        assert proposal is not None
        if proposal.kind is not ProposalKind.PROPOSE_ACTION:
            trace.note(f"provider declined to propose containment (kind={proposal.kind.value})")
            return trace.halt("no containment action was proposed")
        trace.note(f"containment proposed (attempt {attempt}): {proposal.rationale}")

        trace.advance(Trigger.RISK_REQUIRES_APPROVAL, "awaiting containment approval")
        if not deps.approve_containment():
            trace.advance(Trigger.DENIED_OR_EXPIRED, "containment approval denied or expired")
            return trace.halt("containment approval denied or expired")
        trace.advance(Trigger.APPROVED, "containment approved")

        deps.apply_containment()
        trace.advance(Trigger.ADVANCE, "containment applied; verifying")

        blocked, available = deps.attack_blocked(), deps.benign_available()
        if blocked and available:
            trace.advance(Trigger.EFFECTIVE, f"containment effective on attempt {attempt}")
            contained = True
            break

        if blocked and not available:
            deps.rollback_containment()
            trace.note(f"containment broke availability on attempt {attempt}; rolled back")
        else:
            trace.note(f"containment ineffective on attempt {attempt}")

        if attempt == deps.max_containment_attempts:
            return trace.halt("containment budget exhausted without an effective result")
        trace.advance(Trigger.INEFFECTIVE_BUDGET_REMAINS, "re-investigating before another attempt")
        trace.advance(Trigger.ADVANCE, "ready to retry containment")

    assert contained  # the only way out of the loop other than an early return

    trace.advance(Trigger.ADVANCE, "vulnerable component localized")

    for attempt in range(1, deps.max_repair_attempts + 1):
        candidate = deps.generate_candidate()
        trace.note(f"candidate {candidate.id} generated (attempt {attempt})")
        trace.advance(Trigger.ADVANCE, f"verifying candidate {candidate.id}")
        outcome = deps.verify_candidate(candidate)
        trace.note(f"candidate {candidate.id} outcome: {outcome.value}")

        if outcome is AssuranceOutcome.VERIFIED:
            trace.advance(Trigger.VERIFIED, "candidate verified; awaiting deployment approval")
            break
        if outcome is AssuranceOutcome.REJECTED and attempt < deps.max_repair_attempts:
            trace.advance(Trigger.REJECTED_BUDGET_REMAINS, "retrying repair")
            continue
        # REJECTED with no budget remaining, CONTROL_FAILURE, or REVIEW_REQUIRED
        # all fail closed to the one accepted edge: escalate, never deploy.
        trace.advance(Trigger.INSUFFICIENT_EVIDENCE, "escalating: repair did not reach VERIFIED")
        return trace.halt(f"repair did not reach VERIFIED (last outcome: {outcome.value})")

    if not deps.approve_deployment():
        trace.advance(Trigger.DENIED_OR_EXPIRED, "deployment approval denied or expired")
        return trace.halt("deployment approval denied or expired")
    trace.advance(Trigger.APPROVED, "deployment approved")

    trace.advance(Trigger.ADVANCE, "verified candidate deployed; verifying recovery")

    if deps.recovery_attack_blocked() and deps.recovery_benign_available():
        trace.advance(
            Trigger.SUCCESSFUL, "recovery verified: exploit blocked, benign traffic intact"
        )
    else:
        trace.advance(Trigger.FAILED, "recovery verification failed")
        trace.advance(Trigger.ADVANCE, "recovery rolled back")
        return trace.halt("recovery failed and was rolled back")

    if deps.recurrence_detected():
        trace.advance(Trigger.RECURRENCE, "recurrence detected during the monitoring window")
        return trace.halt("recurrence detected during the monitoring window")

    trace.advance(Trigger.OBSERVATION_WINDOW_PASSES, "observation window passed with no recurrence")
    return trace
