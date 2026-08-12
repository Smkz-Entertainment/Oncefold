from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from oncefold import (
    ActionIdentity,
    DependencyDescriptor,
    InMemoryReceiptStore,
    ReceiptVerifier,
    ReuseClass,
    ReuseReceipt,
    SideEffectClass,
    SQLiteReceiptStore,
    canonical_json,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def action(**changes: object) -> ActionIdentity:
    values: dict[str, object] = {
        "operation_identity": "example.read",
        "operation_version": "1",
        "input_digest": digest("input"),
        "dependencies": (DependencyDescriptor("file", "config", digest("v1")),),
        "side_effect_class": SideEffectClass.READ_ONLY,
    }
    values.update(changes)
    return ActionIdentity(**values)  # type: ignore[arg-type]


def receipt(current: ActionIdentity) -> ReuseReceipt:
    return ReuseReceipt(
        action=current,
        result_digest=digest("result"),
        media_type="application/json",
        producer_identity="test-producer",
        reuse_class=ReuseClass.EXACT,
        dependency_snapshot=current.dependencies,
        trust_scope=current.trust_scope,
    )


def test_canonicalization_rejects_ambiguous_or_unbounded_values() -> None:
    with pytest.raises(TypeError):
        canonical_json({1: "non-string key"})
    with pytest.raises(ValueError):
        canonical_json({"value": "x" * 4097})
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})


def test_receipt_tampering_and_scope_changes_fail_closed() -> None:
    current = action()
    stored = receipt(current)
    verifier = ReceiptVerifier(InMemoryReceiptStore())
    assert verifier.evaluate(current, stored).state.value == "REUSABLE_EXACT"
    assert (
        verifier.evaluate(replace(current, trust_scope="other-scope"), stored).state.value
        == "SCOPE_MISMATCH"
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        ReuseReceipt.from_dict({**stored.as_dict(), "result_digest": digest("tampered")})


def test_external_mutation_and_incomplete_dependencies_are_not_reusable() -> None:
    current = action(side_effect_class=SideEffectClass.LOCAL_WRITE)
    stored = receipt(current)
    assert ReceiptVerifier(InMemoryReceiptStore()).evaluate(current, stored).state.value == "UNSAFE"
    incomplete = action(dependency_completeness=False)
    incomplete_receipt = receipt(incomplete)
    assert (
        ReceiptVerifier(InMemoryReceiptStore()).evaluate(incomplete, incomplete_receipt).state.value
        == "UNKNOWN"
    )


def test_sqlite_revocation_is_not_lost_and_can_precede_publication(tmp_path) -> None:
    current = action()
    stored = receipt(current)
    store = SQLiteReceiptStore(tmp_path / "receipts.sqlite3")
    store.revoke(stored.digest, "before publication")
    store.put(stored)
    assert store.is_revoked(stored.digest)
    assert store.get(stored.digest) is None
    unknown_digest = digest("future-receipt")
    store.revoke(unknown_digest, "future incident")
    decision = ReceiptVerifier(store).evaluate_digest(current, unknown_digest)
    assert decision.state.value == "REVOKED"
