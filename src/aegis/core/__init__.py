"""Reusable execution-runtime primitives.

This package is intentionally independent of the cyber-defense range and
orchestrator. Cyber-specific applications may build on these primitives.
"""

from aegis.core.actions import (
    ActionCatalog,
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.core.capability import Capability, CapabilityAuthority, CapabilityDeniedError
from aegis.core.receipt import (
    ExecutionDisposition,
    ExecutionReceipt,
    create_execution_receipt,
    verify_execution_receipt,
)
from aegis.core.sandbox import SandboxBackend, SandboxExecutionRequest, SandboxExecutionResult
from aegis.core.transaction import (
    ActionTransaction,
    IllegalTransactionTransitionError,
    TransactionState,
    TransactionTransition,
)

__all__ = [
    "ActionCatalog",
    "ActionDefinition",
    "ActionParameter",
    "ActionResources",
    "ActionSideEffect",
    "ActionTransaction",
    "ActionValueType",
    "Capability",
    "CapabilityAuthority",
    "CapabilityDeniedError",
    "ExecutionDisposition",
    "ExecutionReceipt",
    "IllegalTransactionTransitionError",
    "SandboxBackend",
    "SandboxExecutionRequest",
    "SandboxExecutionResult",
    "TransactionState",
    "TransactionTransition",
    "VerificationContract",
    "create_execution_receipt",
    "verify_execution_receipt",
]
