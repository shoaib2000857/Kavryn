from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.providers.schemas import ProposalKind, ProposedAction, StructuredProposal


def _action() -> ProposedAction:
    return ProposedAction(
        action_type="scan.run",
        target_ref="workspace://AGE-0001/candidate",
        adapter="semgrep.scan",
        reason="Look for the reported vulnerability class",
    )


def test_propose_action_requires_an_action() -> None:
    with pytest.raises(ValidationError, match="must include an action"):
        StructuredProposal(kind=ProposalKind.PROPOSE_ACTION, rationale="no action attached")


def test_propose_action_with_action_is_valid() -> None:
    proposal = StructuredProposal(
        kind=ProposalKind.PROPOSE_ACTION, action=_action(), rationale="scan for the finding"
    )
    assert proposal.action is not None


@pytest.mark.parametrize("kind", [ProposalKind.REFUSE, ProposalKind.ESCALATE])
def test_refuse_and_escalate_must_not_include_an_action(kind: ProposalKind) -> None:
    with pytest.raises(ValidationError, match="must not include an action"):
        StructuredProposal(kind=kind, action=_action(), rationale="insufficient evidence")


def test_refuse_without_action_is_valid() -> None:
    proposal = StructuredProposal(kind=ProposalKind.REFUSE, rationale="insufficient evidence")
    assert proposal.action is None


def test_structured_proposal_round_trips_through_json() -> None:
    proposal = StructuredProposal(
        kind=ProposalKind.PROPOSE_ACTION, action=_action(), rationale="scan for the finding"
    )
    restored = StructuredProposal.model_validate_json(proposal.model_dump_json())
    assert restored == proposal
