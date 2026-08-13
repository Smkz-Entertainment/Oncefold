from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from oncefold.identity import ReuseClass, canonical_timestamp
from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    InMemoryReceiptStore,
    ReceiptTrustPolicy,
    ReceiptVerifier,
    ReuseReceipt,
)
from oncefold.wire import parse_json_object

VECTOR_PATH = Path("conformance/vectors.json")
SOURCE_ENV = {**os.environ, "PYTHONPATH": str(Path("src").resolve())}


def trust_policy(document: dict[str, Any]) -> ReceiptTrustPolicy:
    value = document["trust_policy"]
    return ReceiptTrustPolicy(
        allowed_producers=frozenset(value["allowed_producers"]),
        allowed_cache_scopes=frozenset(value["allowed_cache_scopes"]),
        required_provenance=value["required_provenance"],
    )


def test_language_neutral_stdlib_checker_passes_without_package_import() -> None:
    source = Path("conformance/stdlib_check.py").read_text(encoding="utf-8")
    assert "from oncefold" not in source
    result = subprocess.run(
        [sys.executable, "conformance/stdlib_check.py"],
        check=False,
        capture_output=True,
        text=True,
        env=SOURCE_ENV,
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
            validator: Callable[[ReuseReceipt], object] | None = None
            if "validator_result" in case:
                result = case["validator_result"]

                def fixed_validator(_: ReuseReceipt, expected: object = result) -> object:
                    return bool(expected)

                validator = fixed_validator
            decision = ReceiptVerifier(store, trust_policy(document)).evaluate(
                action,
                receipt,
                validator=validator,
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
        env=SOURCE_ENV,
    )
    assert produced.returncode == 0, produced.stderr
    receipt = ReuseReceipt.from_dict(parse_json_object(receipt_path.read_bytes()))
    store = InMemoryReceiptStore()
    store.put(receipt)
    decision = ReceiptVerifier(
        store,
        ReceiptTrustPolicy.for_producer("generic-cli-producer", "private"),
    ).evaluate(receipt.action, receipt)
    assert decision.state is DecisionState.REUSABLE_EXACT
    consumed = subprocess.run(
        [sys.executable, "examples/interop_consumer.py", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
        env=SOURCE_ENV,
    )
    assert consumed.returncode == 0, consumed.stderr
    assert "REUSABLE_EXACT" in consumed.stdout
    inspected = subprocess.run(
        [sys.executable, "-m", "oncefold", "inspect", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
        env=SOURCE_ENV,
    )
    assert inspected.returncode == 0
    assert '"state": "UNKNOWN"' in inspected.stdout
    action_path = tmp_path / "current-action.json"
    action_path.write_text(json.dumps(receipt.action.as_dict(), sort_keys=True), encoding="utf-8")
    unchecked = subprocess.run(
        [sys.executable, "-m", "oncefold", "check", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
        env=SOURCE_ENV,
    )
    assert unchecked.returncode == 2
    checked = subprocess.run(
        [
            sys.executable,
            "-m",
            "oncefold",
            "verify",
            str(receipt_path),
            "--action",
            str(action_path),
            "--trusted-producer",
            "generic-cli-producer",
            "--trusted-cache-scope",
            "private",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=SOURCE_ENV,
    )
    assert checked.returncode == 0, checked.stderr
    assert "REUSABLE_EXACT" in checked.stdout


def test_raw_json_guards_and_timestamp_vectors() -> None:
    document = parse_json_object(VECTOR_PATH.read_bytes())
    for item in document["raw_json_cases"]:
        try:
            parse_json_object(item["json"])
            accepted = True
        except (TypeError, ValueError):
            accepted = False
        assert accepted is item["accepted"], item["id"]
    for item in document["timestamp_cases"]:
        try:
            actual = canonical_timestamp(item["value"])
            assert item["accepted"] is True
            assert actual == item.get("canonical", actual)
        except (TypeError, ValueError):
            assert item["accepted"] is False, item["value"]
