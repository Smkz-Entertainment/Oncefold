from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oncefold.identity import DependencyDescriptor, ReuseClass, SideEffectClass
from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    InMemoryReceiptStore,
    ReceiptVerifier,
    ReuseReceipt,
    SQLiteReceiptStore,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def make_action(**changes: object) -> ActionIdentity:
    values: dict[str, object] = {
        "operation_identity": "catalog.lookup",
        "operation_version": "2026-08",
        "input_digest": digest("input"),
        "trust_scope": "tenant:one",
        "environment": {"tool": "catalog-2"},
        "dependencies": (DependencyDescriptor("db", "catalog", digest("catalog-v1")),),
        "side_effect_class": SideEffectClass.READ_ONLY,
        "authorization_scope_digest": digest("read:catalog"),
        "freshness": {"time_bucket": "2026-08-11T12"},
        "validator_identity": "validator/1",
    }
    values.update(changes)
    return ActionIdentity(**values)  # type: ignore[arg-type]


def make_receipt(action: ActionIdentity, **changes: object) -> ReuseReceipt:
    values: dict[str, object] = {
        "action": action,
        "result_digest": digest("result"),
        "media_type": "application/json",
        "producer_identity": "producer-a",
        "reuse_class": ReuseClass.EXACT,
        "created_at": datetime(2026, 8, 11, 12, tzinfo=UTC),
        "dependency_snapshot": action.dependencies,
        "provenance": {"path": "cli"},
        "trust_scope": action.trust_scope,
        "cache_scope": "tenant-private",
        "validator_identity": action.validator_identity,
    }
    values.update(changes)
    return ReuseReceipt(**values)  # type: ignore[arg-type]


def test_receipt_is_portable_and_strictly_self_verifying() -> None:
    receipt = make_receipt(make_action())
    encoded = receipt.as_dict()
    assert ReuseReceipt.from_dict(encoded).digest == receipt.digest
    assert encoded["action_digest"] == receipt.action.digest
    with pytest.raises(ValueError, match="unknown fields"):
        ReuseReceipt.from_dict({**encoded, "producer_private_reasoning": "never"})
    with pytest.raises(ValueError, match="digest mismatch"):
        ReuseReceipt.from_dict({**encoded, "result_digest": digest("tampered")})


def test_duplicate_dependencies_and_non_read_only_actions_fail_closed() -> None:
    dependency = DependencyDescriptor("db", "catalog", digest("catalog-v1"))
    with pytest.raises(ValueError, match="duplicate dependency"):
        make_action(dependencies=(dependency, dependency))
    action = make_action(side_effect_class=SideEffectClass.LOCAL_WRITE)
    receipt = make_receipt(action)
    assert (
        ReceiptVerifier(InMemoryReceiptStore()).evaluate(action, receipt).state
        is DecisionState.UNSAFE
    )


def test_verifier_fails_closed_for_dependency_scope_and_result_changes() -> None:
    store = InMemoryReceiptStore()
    action = make_action()
    receipt = make_receipt(action)
    store.put(receipt)
    verifier = ReceiptVerifier(store)
    assert verifier.evaluate(action, receipt).state is DecisionState.REUSABLE_EXACT
    changed_dependency = replace(
        action,
        dependencies=(DependencyDescriptor("db", "catalog", digest("catalog-v2")),),
    )
    assert verifier.evaluate(changed_dependency, receipt).state is DecisionState.STALE
    assert (
        verifier.evaluate(replace(action, trust_scope="tenant:two"), receipt).state
        is DecisionState.SCOPE_MISMATCH
    )
    assert (
        verifier.evaluate(
            replace(action, authorization_scope_digest=digest("write:catalog")), receipt
        ).state
        is DecisionState.SCOPE_MISMATCH
    )
    assert (
        verifier.evaluate(action, receipt, available_result_digest=digest("other")).state
        is DecisionState.UNKNOWN
    )
    assert (
        verifier.evaluate(action, receipt, available_result_digest="bad").state
        is DecisionState.UNKNOWN
    )
    assert (
        verifier.evaluate(replace(action, dependency_completeness=False), receipt).state
        is DecisionState.UNKNOWN
    )


def test_verifier_distinguishes_advisory_verified_and_revoked() -> None:
    action = make_action()
    advisory = make_receipt(action, reuse_class=ReuseClass.ADVISORY)
    verified = make_receipt(action, reuse_class=ReuseClass.VERIFIED)
    store = InMemoryReceiptStore()
    store.put(advisory)
    store.put(verified)
    verifier = ReceiptVerifier(store)
    assert verifier.evaluate(action, advisory).state is DecisionState.ADVISORY_ONLY
    assert verifier.evaluate(action, verified).state is DecisionState.REQUIRES_VALIDATION
    missing_validator = make_receipt(
        action,
        reuse_class=ReuseClass.VERIFIED,
        validator_identity=None,
    )
    assert (
        verifier.evaluate(action, missing_validator, validator=lambda _: True).state
        is DecisionState.REQUIRES_VALIDATION
    )
    assert (
        verifier.evaluate(action, verified, validator=lambda _: True).state
        is DecisionState.REUSABLE_EXACT
    )
    assert (
        verifier.evaluate(action, verified, validator=lambda _: False).state is DecisionState.STALE
    )
    store.revoke(advisory.digest, "incident")
    assert verifier.evaluate_digest(action, advisory.digest).state is DecisionState.REVOKED
    external = replace(action, side_effect_class=SideEffectClass.EXTERNAL_MUTATION)
    assert verifier.evaluate(external, verified).state is DecisionState.UNSAFE


def test_same_verifier_contract_works_with_memory_and_sqlite(tmp_path: Path) -> None:
    action = make_action()
    receipt = make_receipt(action)
    memory = InMemoryReceiptStore()
    sqlite = SQLiteReceiptStore(tmp_path / "receipts.sqlite3")
    for store in (memory, sqlite):
        store.put(receipt)
        assert (
            ReceiptVerifier(store).evaluate_digest(action, receipt.digest).state
            is DecisionState.REUSABLE_EXACT
        )
