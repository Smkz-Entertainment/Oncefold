from __future__ import annotations

import copy
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from oncefold.identity import ReuseClass
from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    InMemoryReceiptStore,
    ReceiptVerifier,
    ReuseReceipt,
)

VECTOR_PATH = Path("conformance/vectors.json")


def test_language_neutral_stdlib_checker_passes_without_package_import() -> None:
    source = Path("conformance/stdlib_check.py").read_text(encoding="utf-8")
    assert "from oncefold" not in source
    result = subprocess.run(
        [sys.executable, "conformance/stdlib_check.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def _receipt_payload(
    base: dict[str, Any], patch: dict[str, Any], recompute: bool
) -> dict[str, Any]:
    payload = copy.deepcopy(base)
    if not recompute:
        payload.update(patch)
        return payload
    receipt = ReuseReceipt.from_dict(payload)
    changes: dict[str, Any] = {}
    for key, value in patch.items():
        changes[key] = ReuseClass(value) if key == "reuse_class" else value
    return replace(receipt, **changes).as_dict()


def test_all_conformance_vectors_fail_closed_or_match_expected_state() -> None:
    document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    base_action = document["base"]["action"]
    base_receipt = document["base"]["receipt"]
    for case in document["cases"]:
        action_payload = {**base_action, **case.get("action_patch", {})}
        receipt_payload = _receipt_payload(
            base_receipt,
            case.get("receipt_patch", {}),
            bool(case.get("recompute_receipt_digest", False)),
        )
        store = InMemoryReceiptStore()
        try:
            action = ActionIdentity.from_dict(action_payload)
            receipt = ReuseReceipt.from_dict(receipt_payload)
            store.put(receipt)
            if case.get("revoked"):
                store.revoke(receipt.digest, "vector revocation")
            decision = ReceiptVerifier(store).evaluate(
                action,
                receipt,
                validator=(lambda _, result=case["validator_result"]: bool(result))
                if "validator_result" in case
                else None,
                available_result_digest=case.get("available_result_digest"),
            )
        except (TypeError, ValueError, KeyError):
            decision = type("MalformedDecision", (), {"state": DecisionState.UNKNOWN})()
        assert decision.state.value == case["expected_state"], case["id"]


def test_cli_producer_receipt_is_consumable_by_python_verifier(tmp_path: Path) -> None:
    receipt_path = tmp_path / "cli-receipt.json"
    produced = subprocess.run(
        [sys.executable, "examples/interop_cli_producer.py", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert produced.returncode == 0, produced.stderr
    receipt = ReuseReceipt.from_dict(json.loads(receipt_path.read_text(encoding="utf-8")))
    store = InMemoryReceiptStore()
    store.put(receipt)
    decision = ReceiptVerifier(store).evaluate(receipt.action, receipt)
    assert decision.state is DecisionState.REUSABLE_EXACT
    consumed = subprocess.run(
        [sys.executable, "examples/interop_consumer.py", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert consumed.returncode == 0, consumed.stderr
    assert "REUSABLE_EXACT" in consumed.stdout
