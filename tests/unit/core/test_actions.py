from __future__ import annotations

import pytest

from aegis.core.actions import (
    ActionCatalog,
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
    action_definition_digest,
)
from aegis.domain.policy import RiskTier


def _definition(**overrides: object) -> ActionDefinition:
    values: dict[str, object] = {
        "action_type": "contain.rate_limit",
        "version": 1,
        "adapter_id": "range.proxy",
        "description": "Apply the fixed local range containment rule.",
        "inputs": (
            ActionParameter(
                name="operation",
                value_type=ActionValueType.STRING,
                description="The allowlisted operation name.",
            ),
            ActionParameter(
                name="rollback_of",
                value_type=ActionValueType.STRING,
                required=False,
                description="Prior operation reference for rollback.",
            ),
        ),
        "outputs": (
            ActionParameter(
                name="applied",
                value_type=ActionValueType.BOOLEAN,
                description="Whether the fixed rule was applied.",
            ),
        ),
        "risk_tier": RiskTier.R3_REVERSIBLE_RESPONSE,
        "side_effects": (ActionSideEffect.WRITE,),
        "filesystem": "read-write-workspace",
        "reversible": True,
        "rollback_action_type": "contain.rollback",
        "resources": ActionResources(timeout_seconds=10, cpu=1, memory_mb=128),
        "verification": VerificationContract(required=True, verifier_id="range.verify"),
    }
    values.update(overrides)
    return ActionDefinition(**values)


def test_catalog_validates_binding_required_fields_and_primitive_types() -> None:
    catalog = ActionCatalog((_definition(),))
    assert (
        catalog.validate_parameters(
            "contain.rate_limit", "range.proxy", {"operation": "apply"}
        ).rollback_action_type
        == "contain.rollback"
    )

    with pytest.raises(ValueError, match="adapter"):
        catalog.validate_parameters("contain.rate_limit", "other.adapter", {"operation": "apply"})
    with pytest.raises(ValueError, match="missing"):
        catalog.validate_parameters("contain.rate_limit", "range.proxy", {})
    with pytest.raises(ValueError, match="unknown"):
        catalog.validate_parameters(
            "contain.rate_limit", "range.proxy", {"operation": "apply", "raw_command": "x"}
        )
    with pytest.raises(ValueError, match="must be string"):
        catalog.validate_parameters("contain.rate_limit", "range.proxy", {"operation": 1})


def test_catalog_validates_typed_outputs_and_rejects_unknown_actions() -> None:
    catalog = ActionCatalog((_definition(),))
    definition = catalog.get("contain.rate_limit")
    catalog.validate_output(definition, {"applied": True})
    with pytest.raises(ValueError, match="must be boolean"):
        catalog.validate_output(definition, {"applied": "yes"})
    with pytest.raises(ValueError, match="unknown"):
        catalog.validate_output(definition, {"applied": True, "message": "ok"})
    with pytest.raises(KeyError, match="unregistered"):
        catalog.get("host.shell")


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"reversible": True, "rollback_action_type": None}, "must name a rollback"),
        ({"reversible": False, "rollback_action_type": "contain.rollback"}, "must name a rollback"),
        ({"idempotent": False, "max_retries": 1}, "require an idempotent"),
        ({"side_effects": ()}, "must be declared"),
        (
            {
                "inputs": (
                    ActionParameter(name="same", value_type="string", description="First."),
                    ActionParameter(name="same", value_type="string", description="Second."),
                )
            },
            "must be unique",
        ),
        (
            {"inputs": ({"name": "cmd", "value_type": "string", "description": "Forbidden."},)},
            "raw command fields",
        ),
    ],
)
def test_invalid_action_definition_is_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _definition(**overrides)


def test_required_verification_requires_a_named_independent_verifier() -> None:
    with pytest.raises(ValueError, match="exactly one verifier"):
        VerificationContract(required=True)
    with pytest.raises(ValueError, match="exactly one verifier"):
        VerificationContract(required=False, verifier_id="range.verify")


def test_action_definition_digest_binds_the_complete_contract() -> None:
    original = _definition()
    assert action_definition_digest(original) == action_definition_digest(_definition())
    assert action_definition_digest(original) != action_definition_digest(
        _definition(side_effects=(ActionSideEffect.READ,))
    )
