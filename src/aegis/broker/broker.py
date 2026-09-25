"""The action broker: the only effectful path from a request to a tool.

See docs/PRODUCT_REQUIREMENTS.md SR-AUT-004 ("The action broker is the
only effectful path from reasoning to tools or targets") and
docs/ARCHITECTURE.md's data-flow steps 6-9: resolve policy, dispatch to
a worker, audit request/decision/result.

``ActionBroker.submit`` is the integration point for Changes 1-4: it
evaluates the pure policy decision (Change 2) against a request (Change
1), dispatches to a registered typed adapter (Change 4) only if
permitted, and records every request, decision, and result to the
append-only audit sink and content-addressed artifact store (Change 2).
It never lets an unregistered adapter or unresolved capability through
silently.
"""

from __future__ import annotations

import json
from datetime import datetime
from itertools import count

from aegis.broker.adapter import AdapterResult
from aegis.broker.registry import AdapterRegistry, UnknownAdapterError
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, AegisModel, CaseId, Digest
from aegis.domain.case import Case
from aegis.domain.policy import PolicyDecision, PolicyOutcome
from aegis.domain.scope import ScopePolicy
from aegis.evidence.audit import AuditSink
from aegis.evidence.store import ArtifactStore, sha256_digest
from aegis.policy.budget import BudgetUsage
from aegis.policy.decision import evaluate_action_request

__all__ = ["ActionBroker", "BrokerError", "BrokerOutcome"]


class BrokerError(RuntimeError):
    """Raised on a broker-level integrity failure (not an ordinary policy denial).

    E.g. a scope policy allow-lists an adapter id that was never
    registered: the request must not silently proceed or silently
    degrade to "denied" as if the operator had intended that — it is a
    configuration/control fault that must be surfaced loudly.
    """


class BrokerOutcome(AegisModel):
    decision: PolicyDecision
    result: AdapterResult | None = None


def _event_content_digest(
    *,
    event_id: str,
    case_id: str,
    created_at: datetime,
    event_type: AuditEventType,
    actor_id: str,
    role: ActorRole,
    subject_ref: str,
    summary: str,
) -> Digest:
    payload = json.dumps(
        {
            "id": event_id,
            "case_id": case_id,
            "created_at": created_at.isoformat(),
            "event_type": event_type.value,
            "actor_id": actor_id,
            "role": role.value,
            "subject_ref": subject_ref,
            "summary": summary,
        },
        sort_keys=True,
    ).encode()
    return sha256_digest(payload)


class ActionBroker:
    def __init__(
        self, *, registry: AdapterRegistry, audit: AuditSink, artifacts: ArtifactStore
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._artifacts = artifacts
        self._usage: dict[str, BudgetUsage] = {}
        self._audit_seq = count(1)

    def usage_for(self, case_id: CaseId) -> BudgetUsage:
        return self._usage.get(case_id, BudgetUsage())

    def submit(
        self,
        request: ActionRequest,
        *,
        case: Case,
        scope: ScopePolicy,
        now: datetime,
        decision_id: str,
        policy_version: str,
    ) -> BrokerOutcome:
        usage = self.usage_for(case.id)
        candidate_capability_ref = f"capability://{case.id}/{decision_id}"

        decision = evaluate_action_request(
            request,
            case=case,
            scope=scope,
            usage=usage,
            now=now,
            decision_id=decision_id,
            policy_version=policy_version,
            capability_ref=candidate_capability_ref,
        )

        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.ACTION_REQUESTED,
            actor_id=request.actor_id,
            role=request.role,
            subject_ref=f"action-request://{case.id}/{request.id}",
            summary=f"action_type={request.action_type} adapter={request.adapter}",
        )
        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.POLICY_DECISION_RECORDED,
            actor_id="control-plane:policy-engine",
            role=ActorRole.CONTROL_PLANE,
            subject_ref=f"policy-decision://{case.id}/{decision.id}",
            summary=f"outcome={decision.outcome.value} risk_tier={decision.risk_tier.value}",
        )

        if decision.outcome is not PolicyOutcome.PERMITTED:
            return BrokerOutcome(decision=decision, result=None)

        assert decision.capability_ref is not None  # guaranteed by PolicyDecision's own invariant

        try:
            adapter = self._registry.get(request.adapter)
        except UnknownAdapterError as exc:
            raise BrokerError(
                f"scope permitted adapter '{request.adapter}' but it is not registered"
            ) from exc

        result = adapter.run(request, capability_ref=decision.capability_ref)

        result_digest = self._artifacts.put(result.model_dump_json().encode())
        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.TOOL_RUN_RECORDED,
            actor_id=f"worker:{request.adapter}",
            role=ActorRole.WORKER,
            subject_ref=f"tool-run://{case.id}/{request.id}",
            summary=(
                f"adapter={request.adapter} exit_status={result.exit_status} "
                f"result_digest=sha256:{result_digest.digest}"
            ),
        )

        self._usage[case.id] = usage.model_copy(update={"tool_calls": usage.tool_calls + 1})

        return BrokerOutcome(decision=decision, result=result)

    def _append_audit(
        self,
        *,
        case_id: str,
        now: datetime,
        event_type: AuditEventType,
        actor_id: str,
        role: ActorRole,
        subject_ref: str,
        summary: str,
    ) -> None:
        event_id = f"audit-{case_id}-{next(self._audit_seq)}"
        prior = self._audit.last_event(case_id)
        integrity = _event_content_digest(
            event_id=event_id,
            case_id=case_id,
            created_at=now,
            event_type=event_type,
            actor_id=actor_id,
            role=role,
            subject_ref=subject_ref,
            summary=summary,
        )
        event = AuditEvent(
            id=event_id,
            case_id=case_id,
            created_at=now,
            event_type=event_type,
            actor_id=actor_id,
            role=role,
            subject_ref=subject_ref,
            summary=summary,
            integrity=integrity,
            prev_event_digest=prior.integrity if prior else None,
        )
        self._audit.append(event)
