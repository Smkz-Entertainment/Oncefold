"""Small command-line surface for inspecting a receipt decision."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    InMemoryReceiptStore,
    ReceiptVerifier,
    ReuseReceipt,
)


def _read_json(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("JSON document must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oncefold", description="Evaluate a Oncefold reuse receipt"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="evaluate a receipt against current action facts")
    verify.add_argument("receipt", type=Path)
    verify.add_argument(
        "--action",
        type=Path,
        help="JSON file containing the current Action Identity; defaults to the receipt action",
    )
    verify.add_argument("--result-digest", help="digest of the currently available result")
    args = parser.parse_args(argv)

    try:
        receipt = ReuseReceipt.from_dict(_read_json(args.receipt))
        action = (
            ActionIdentity.from_dict(_read_json(args.action)) if args.action else receipt.action
        )
        store = InMemoryReceiptStore()
        store.put(receipt)
        decision = ReceiptVerifier(store).evaluate(
            action, receipt, available_result_digest=args.result_digest
        )
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"state": DecisionState.UNKNOWN.value, "reason": str(exc)}))
        return 2

    print(
        json.dumps(
            {
                "state": decision.state.value,
                "reason": decision.reason,
                "receipt_digest": decision.receipt_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
