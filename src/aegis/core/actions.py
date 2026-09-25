"""Versioned, typed contracts for actions exposed through the runtime."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from aegis.domain.base import ActionId, ActorId, AegisModel, ToolId
from aegis.domain.policy import RiskTier

__all__ = [
    "ACTION_DEFINITION_SCHEMA_VERSION",
    "ActionCatalog",
    "ActionDefinition",
    "ActionParameter",
    "ActionResources",
    "ActionSideEffect",
    "ActionValueType",
    "VerificationContract",
]

ACTION_DEFINITION_SCHEMA_VERSION: Final[Literal["aegis.action_definition/v1"]] = (
    "aegis.action_definition/v1"
)


class ActionValueType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"


class ActionSideEffect(StrEnum):
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    DEPLOYMENT = "deployment"


class ActionParameter(AegisModel):
    """A small, runtime-enforced JSON value contract for one named field."""

    name: Annotated[
        str, StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    ]
    value_type: ActionValueType
    required: bool = True
    description: Annotated[str, StringConstraints(min_length=1, max_length=300)]

    @field_validator("name")
    @classmethod
    def _no_command_shaped_fields(cls, value: str) -> str:
        if value in {"command", "cmd", "shell", "argv", "exec", "script", "raw_command"}:
            raise ValueError("action parameters cannot declare raw command fields")
        return value


class ActionResources(AegisModel):
    """Declared resource envelope; the concrete adapter/backend must enforce it."""

    timeout_seconds: int = Field(gt=0)
    cpu: float = Field(gt=0)
    memory_mb: int = Field(gt=0)


class VerificationContract(AegisModel):
    required: bool
    verifier_id: ActorId | None = None

    @model_validator(mode="after")
    def _required_has_verifier(self) -> VerificationContract:
        if self.required != (self.verifier_id is not None):
            raise ValueError("required verification must name exactly one verifier")
        return self


class ActionDefinition(AegisModel):
    """Immutable, versioned contract binding intent to a registered adapter."""

    schema_version: Literal["aegis.action_definition/v1"] = ACTION_DEFINITION_SCHEMA_VERSION
    action_type: ActionId
    version: int = Field(ge=1)
    adapter_id: ToolId
    description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    inputs: tuple[ActionParameter, ...] = ()
    outputs: tuple[ActionParameter, ...] = ()
    risk_tier: RiskTier
    side_effects: tuple[ActionSideEffect, ...]
    filesystem: Literal["none", "read-target", "read-write-workspace"]
    network: Literal["none"] = "none"
    secrets: Literal["none"] = "none"
    reversible: bool = False
    rollback_action_type: ActionId | None = None
    resources: ActionResources
    verification: VerificationContract
    idempotent: bool = False
    max_retries: int = Field(default=0, ge=0, le=5)

    @model_validator(mode="after")
    def _definition_invariants(self) -> ActionDefinition:
        for label, parameters in (("input", self.inputs), ("output", self.outputs)):
            names = [parameter.name for parameter in parameters]
            if len(names) != len(set(names)):
                raise ValueError(f"{label} parameter names must be unique")
        if self.reversible != (self.rollback_action_type is not None):
            raise ValueError("reversible actions must name a rollback action, and only those may")
        if self.rollback_action_type == self.action_type:
            raise ValueError("an action cannot roll itself back")
        if self.max_retries and not self.idempotent:
            raise ValueError("automatic retries require an idempotent action")
        if not self.side_effects:
            raise ValueError("action side effects must be declared")
        if len(self.side_effects) != len(set(self.side_effects)):
            raise ValueError("action side effects must be unique")
        if ActionSideEffect.NETWORK in self.side_effects and self.network == "none":
            raise ValueError("network side effect cannot be declared when network access is none")
        return self


class ActionCatalog:
    """Fail-closed lookup and validation for registered action definitions."""

    def __init__(self, definitions: tuple[ActionDefinition, ...] = ()) -> None:
        self._definitions: dict[str, ActionDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ActionDefinition) -> None:
        if definition.action_type in self._definitions:
            raise ValueError(f"action '{definition.action_type}' is already registered")
        self._definitions[definition.action_type] = definition

    def unregister(self, action_type: str) -> None:
        """Undo a partially completed adapter registration."""
        self._definitions.pop(action_type, None)

    def get(self, action_type: str) -> ActionDefinition:
        try:
            return self._definitions[action_type]
        except KeyError:
            raise KeyError(f"unregistered action type: {action_type}") from None

    def validate_parameters(
        self, action_type: str, adapter_id: str, parameters: dict[str, object]
    ) -> ActionDefinition:
        definition = self.get(action_type)
        if definition.adapter_id != adapter_id:
            raise ValueError("action type is not bound to the requested adapter")
        fields = {parameter.name: parameter for parameter in definition.inputs}
        unknown = set(parameters) - fields.keys()
        missing = {name for name, field in fields.items() if field.required} - parameters.keys()
        if unknown or missing:
            raise ValueError(
                f"action parameters mismatch (unknown={sorted(unknown)}, missing={sorted(missing)})"
            )
        for name, value in parameters.items():
            if not _matches_type(fields[name].value_type, value):
                raise ValueError(
                    f"action parameter '{name}' must be {fields[name].value_type.value}"
                )
        return definition

    def validate_registration(self, definition: ActionDefinition, descriptor: object) -> None:
        """Ensure catalog claims do not exceed the registered adapter envelope."""
        adapter_id = getattr(descriptor, "id", None)
        permissions = getattr(descriptor, "permissions", None)
        risk_tier = getattr(descriptor, "risk_tier", None)
        limits = getattr(descriptor, "limits", None)
        if adapter_id != definition.adapter_id:
            raise ValueError("action definition adapter does not match registration")
        # Authorization computes contextual risk from the action and case;
        # adapter risk metadata is retained independently as defense in depth.
        del risk_tier
        if permissions is None or limits is None:
            raise ValueError("adapter descriptor is missing permission or resource metadata")
        if permissions.filesystem != definition.filesystem:
            raise ValueError("action filesystem declaration differs from adapter permissions")
        if permissions.network != definition.network or permissions.secrets != definition.secrets:
            raise ValueError("action network/secret declaration differs from adapter permissions")
        if (
            definition.resources.timeout_seconds != limits.timeout_seconds
            or definition.resources.cpu != limits.cpu
            or definition.resources.memory_mb != limits.memory_mb
        ):
            raise ValueError("action resource contract must equal the adapter's declared limits")

    def validate_output(self, definition: ActionDefinition, output: dict[str, object]) -> None:
        fields = {parameter.name: parameter for parameter in definition.outputs}
        unknown = set(output) - fields.keys()
        missing = {name for name, field in fields.items() if field.required} - output.keys()
        if unknown or missing:
            raise ValueError(
                f"action output mismatch (unknown={sorted(unknown)}, missing={sorted(missing)})"
            )
        for name, value in output.items():
            if not _matches_type(fields[name].value_type, value):
                raise ValueError(f"action output '{name}' must be {fields[name].value_type.value}")


def _matches_type(expected: ActionValueType, value: object) -> bool:
    if expected is ActionValueType.STRING:
        return isinstance(value, str)
    if expected is ActionValueType.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is ActionValueType.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected is ActionValueType.BOOLEAN:
        return isinstance(value, bool)
    if expected is ActionValueType.OBJECT:
        return isinstance(value, dict)
    if expected is ActionValueType.ARRAY:
        return isinstance(value, list)
    return False
