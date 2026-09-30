"""Run the public SDK without credentials, Docker, network, or live inference."""

from kavryn import run_transaction_demo, verify_execution_receipt

for fail_verification in (False, True):
    receipt = run_transaction_demo(fail_verification=fail_verification)
    assert verify_execution_receipt(receipt)
    print(receipt.disposition.value, receipt.transaction_id)
