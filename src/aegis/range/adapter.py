"""Typed broker adapter for reversible local-range proxy containment."""

from __future__ import annotations

import re
from threading import RLock

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    AdapterResult,
    ParameterValidationError,
    ToolAdapter,
)
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.domain.action import ActionRequest
from aegis.domain.policy import RiskTier
from aegis.range.containment import ContainmentRule, read_rules, write_rules

__all__ = ["ProxyRuleAdapter"]


class ProxyRuleAdapter(ToolAdapter):
    """Apply/reset the first cyber range's proxy rule through the action broker.

    The agent can choose only the enumerated ``apply`` or ``rollback`` operation;
    it cannot provide a regex, filesystem path, command, or network destination.
    Prior rules are held in process memory for this local reference range. This is
    not a durable transaction log or a production containment adapter.
    """

    descriptor = AdapterDescriptor(
        id="range.proxy",
        version=1,
        category="local-range-containment",
        permissions=AdapterPermissions(filesystem="read-write-workspace"),
        risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
        limits=AdapterLimits(timeout_seconds=10, cpu=1.0, memory_mb=128),
        parser="aegis-range-rule-v1",
    )
    action_definitions = (
        ActionDefinition(
            action_type="contain.rate_limit",
            version=1,
            adapter_id="range.proxy",
            description="Apply the fixed traversal-deny rule to the owned local range.",
            inputs=(
                ActionParameter(
                    name="operation",
                    value_type=ActionValueType.STRING,
                    description="Must select the allowlisted apply operation.",
                ),
            ),
            outputs=(
                ActionParameter(
                    name="operation",
                    value_type=ActionValueType.STRING,
                    required=False,
                    description="Adapter operation executed.",
                ),
                ActionParameter(
                    name="rule_set",
                    value_type=ActionValueType.STRING,
                    required=False,
                    description="Fixed rule set identifier applied.",
                ),
            ),
            risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
            side_effects=(ActionSideEffect.WRITE,),
            filesystem="read-write-workspace",
            reversible=True,
            rollback_action_type="contain.rollback",
            resources=ActionResources(timeout_seconds=10, cpu=1, memory_mb=128),
            verification=VerificationContract(required=True, verifier_id="verifier:range-probes"),
        ),
        ActionDefinition(
            action_type="contain.rollback",
            version=1,
            adapter_id="range.proxy",
            description="Restore the prior fixed local-range proxy rule.",
            inputs=(
                ActionParameter(
                    name="operation",
                    value_type=ActionValueType.STRING,
                    description="Must select the allowlisted rollback operation.",
                ),
                ActionParameter(
                    name="rollback_of",
                    value_type=ActionValueType.STRING,
                    description="Identifier of the containment request being rolled back.",
                ),
            ),
            outputs=(
                ActionParameter(
                    name="operation",
                    value_type=ActionValueType.STRING,
                    required=False,
                    description="Adapter operation executed.",
                ),
                ActionParameter(
                    name="restored",
                    value_type=ActionValueType.BOOLEAN,
                    required=False,
                    description="Whether the prior rules were restored.",
                ),
            ),
            risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
            side_effects=(ActionSideEffect.WRITE,),
            filesystem="read-write-workspace",
            resources=ActionResources(timeout_seconds=10, cpu=1, memory_mb=128),
            verification=VerificationContract(required=True, verifier_id="verifier:range-probes"),
        ),
    )
    allowed_parameter_keys = frozenset({"operation", "rollback_of"})

    def __init__(
        self,
        rules_file: str,
        *,
        deny_query_patterns: tuple[str, ...] = (r"\.\.",),
        deny_authorization_patterns: tuple[str, ...] = (),
        rule_set_id: str = "path-traversal-deny",
    ) -> None:
        """Bind the adapter to owner-configured, fixed local-range rules.

        Patterns are trusted deployment configuration, never action parameters
        or model output. Bounds keep a malformed local policy from creating an
        unbounded rule set or pathological expressions.
        """
        patterns = (*deny_query_patterns, *deny_authorization_patterns)
        if not patterns or len(patterns) > 16:
            raise ValueError("containment requires between 1 and 16 fixed patterns")
        if any(not pattern or len(pattern) > 256 for pattern in patterns):
            raise ValueError("containment patterns must contain 1..256 characters")
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError("containment pattern is not a valid regular expression") from exc
        if not rule_set_id or len(rule_set_id) > 80:
            raise ValueError("rule_set_id must contain 1..80 characters")
        self._rules_file = rules_file
        self._deny_query_patterns = deny_query_patterns
        self._deny_authorization_patterns = deny_authorization_patterns
        self._rule_set_id = rule_set_id
        self._prior_rules: dict[str, ContainmentRule] = {}
        self._lock = RLock()

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        del capability_ref  # The broker validates it; the adapter never interprets authority.
        operation = request.parameters.get("operation")
        if operation == "apply" and request.action_type == "contain.rate_limit":
            with self._lock:
                self._prior_rules[request.id] = read_rules(self._rules_file)
                write_rules(
                    self._rules_file,
                    ContainmentRule(
                        deny_query_patterns=self._deny_query_patterns,
                        deny_authorization_patterns=self._deny_authorization_patterns,
                    ),
                )
            return AdapterResult(
                exit_status="success",
                output={"operation": "apply", "rule_set": self._rule_set_id},
                duration_seconds=0.0,
            )

        rollback_of = request.parameters.get("rollback_of")
        if (
            operation == "rollback"
            and request.action_type == "contain.rollback"
            and isinstance(rollback_of, str)
        ):
            with self._lock:
                previous = self._prior_rules.pop(rollback_of, None)
                if previous is None:
                    raise ParameterValidationError("rollback_of does not identify a prior apply")
                write_rules(self._rules_file, previous)
            return AdapterResult(
                exit_status="success",
                output={"operation": "rollback", "restored": True},
                duration_seconds=0.0,
            )

        raise ParameterValidationError("operation/action_type pair is not supported")
