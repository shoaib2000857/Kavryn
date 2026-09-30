from __future__ import annotations

import pytest
from scripts.check_release import validate_members

import kavryn
from aegis.broker.broker import ActionBroker
from aegis.core.receipt import ExecutionDisposition


def test_public_sdk_preserves_existing_type_identity_and_schema_ids() -> None:
    assert kavryn.ActionBroker is ActionBroker
    assert kavryn.__version__ == "0.1.0"
    receipt = kavryn.run_transaction_demo()
    assert receipt.schema_version == "aegis.execution_receipt/v1"
    assert receipt.disposition is ExecutionDisposition.COMMITTED
    assert kavryn.verify_execution_receipt(receipt)


@pytest.mark.parametrize(
    "unsafe",
    [
        ".env.local",
        "../outside",
        "artifacts/benchmark_runs/private.json",
        "kavryn/secret.key",
        "kavryn/__pycache__/x.pyc",
    ],
)
def test_release_member_checks_reject_sensitive_payloads(unsafe: str) -> None:
    with pytest.raises(ValueError):
        validate_members([unsafe], wheel=True)


def test_release_requires_attribution_and_typed_sdk() -> None:
    with pytest.raises(ValueError, match="NOTICE"):
        validate_members(["kavryn/LICENSE"], wheel=True)
    validate_members(
        [
            "kavryn/__init__.py",
            "kavryn/py.typed",
            "aegis/py.typed",
            "kavryn-0.1.0.dist-info/licenses/LICENSE",
            "kavryn-0.1.0.dist-info/licenses/NOTICE",
        ],
        wheel=True,
    )
