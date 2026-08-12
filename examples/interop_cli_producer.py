"""Write one portable receipt that another tool can consume."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from oncefold import ActionIdentity, ReuseClass, ReuseReceipt, SideEffectClass


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--value", default="cli-producer-result")
    args = parser.parse_args()
    action = ActionIdentity(
        operation_identity="example.cli.lookup",
        operation_version="1",
        input_digest=digest("example-cli-input"),
        trust_scope="example:public",
        side_effect_class=SideEffectClass.READ_ONLY,
        dependency_completeness=True,
    )
    receipt = ReuseReceipt(
        action=action,
        result_digest=digest(args.value),
        media_type="text/plain",
        producer_identity="generic-cli-producer",
        reuse_class=ReuseClass.EXACT,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        dependency_snapshot=(),
        provenance={"example": "producer"},
        trust_scope=action.trust_scope,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt.as_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
