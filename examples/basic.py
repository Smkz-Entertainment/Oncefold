"""Create and evaluate one in-memory, read-only receipt."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from oncefold import (
    ActionIdentity,
    InMemoryReceiptStore,
    ReceiptTrustPolicy,
    ReceiptVerifier,
    ReuseClass,
    ReuseReceipt,
    SideEffectClass,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


TRUSTED_PRODUCER = "example-producer"
TRUSTED_CACHE_SCOPE = "private"


action = ActionIdentity(
    operation_identity="example.lookup",
    operation_version="1",
    input_digest=digest("lookup:oncefold"),
    trust_scope="example:public",
    side_effect_class=SideEffectClass.READ_ONLY,
    dependency_completeness=True,
)
receipt = ReuseReceipt(
    action=action,
    result_digest=digest("result:oncefold"),
    media_type="text/plain",
    producer_identity=TRUSTED_PRODUCER,
    reuse_class=ReuseClass.EXACT,
    created_at=datetime(2026, 1, 1, tzinfo=UTC),
    dependency_snapshot=(),
    trust_scope=action.trust_scope,
)
store = InMemoryReceiptStore()
store.put(receipt)
policy = ReceiptTrustPolicy.for_producer(TRUSTED_PRODUCER, TRUSTED_CACHE_SCOPE)
decision = ReceiptVerifier(store, policy).evaluate(action, receipt)
print(json.dumps({"state": decision.state.value, "reason": decision.reason}, sort_keys=True))
