"""Public Kavryn SDK facade; existing evidence/schema identifiers remain stable.

This exposes explicit broker/coordinator contracts, not a generic shell or an
agent loop. Authority is process-local and this alpha is not production hardened.
"""

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    AdapterResult,
    ToolAdapter,
)
from aegis.broker.broker import ActionBroker
from aegis.broker.registry import AdapterRegistry
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    ReceiptPersistenceError,
    VerificationCheck,
    VerificationOutcome,
    Verifier,
)
from aegis.core.receipt import ExecutionReceipt, verify_execution_receipt
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.demo import run_transaction_demo
from aegis.domain.action import ActionRequest
from aegis.domain.case import Case
from aegis.domain.scope import ScopePolicy
from aegis.evidence.sqlite_store import SQLiteEvidenceStore
from aegis.policy.approval import Approval

__version__ = "0.1.0"

__all__ = [
    "ActionBroker",
    "ActionDefinition",
    "ActionParameter",
    "ActionRequest",
    "ActionResources",
    "ActionSideEffect",
    "ActionTransaction",
    "ActionTransactionCoordinator",
    "ActionValueType",
    "AdapterDescriptor",
    "AdapterLimits",
    "AdapterPermissions",
    "AdapterRegistry",
    "AdapterResult",
    "Approval",
    "Case",
    "ExecutionReceipt",
    "ReceiptPersistenceError",
    "SQLiteEvidenceStore",
    "ScopePolicy",
    "ToolAdapter",
    "TransactionState",
    "VerificationCheck",
    "VerificationContract",
    "VerificationOutcome",
    "Verifier",
    "run_transaction_demo",
    "verify_execution_receipt",
]
