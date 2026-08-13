"""Small, bounded command-line surface for receipt decisions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    InMemoryReceiptStore,
    ReceiptTrustPolicy,
    ReceiptVerifier,
    ReuseReceipt,
)
from oncefold.wire import load_json_object


def _add_evaluation_arguments(parser: argparse.ArgumentParser, *, action_required: bool) -> None:
    parser.add_argument("receipt", type=Path)
    parser.add_argument(
        "--action",
        type=Path,
        required=action_required,
        help=(
            "JSON file containing the independently observed current Action Identity"
            if action_required
            else "JSON file containing current Action Identity; defaults to the receipt action"
        ),
    )
    parser.add_argument("--result-digest", help="digest of the currently available result")
    parser.add_argument(
        "--trusted-producer",
        action="append",
        default=[],
        help="producer identity admitted for automatic reuse; repeatable",
    )
    parser.add_argument(
        "--trusted-cache-scope",
        action="append",
        default=[],
        help="cache scope admitted for automatic reuse; repeatable",
    )
    parser.add_argument(
        "--require-provenance",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="exact provenance entry required for automatic reuse; repeatable",
    )


def _trust_policy(args: argparse.Namespace) -> ReceiptTrustPolicy:
    required_provenance: dict[str, str] = {}
    for item in args.require_provenance:
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise ValueError("--require-provenance must be KEY=VALUE")
        if key in required_provenance:
            raise ValueError(f"duplicate provenance policy key: {key}")
        required_provenance[key] = value
    return ReceiptTrustPolicy(
        allowed_producers=frozenset(args.trusted_producer),
        allowed_cache_scopes=frozenset(args.trusted_cache_scope),
        required_provenance=required_provenance,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="oncefold", description="Evaluate a bounded Oncefold reuse receipt"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser(
        "inspect", help="report a decision without using its exit status as a gate"
    )
    _add_evaluation_arguments(inspect, action_required=False)
    for name in ("check", "verify"):
        gate = subparsers.add_parser(
            name,
            help="report a decision and exit 0 only for trusted REUSABLE_EXACT evidence",
        )
        _add_evaluation_arguments(gate, action_required=True)
    args = parser.parse_args(argv)

    try:
        receipt = ReuseReceipt.from_dict(load_json_object(args.receipt))
        action = (
            ActionIdentity.from_dict(load_json_object(args.action))
            if args.action
            else receipt.action
        )
        store = InMemoryReceiptStore()
        store.put(receipt)
        decision = ReceiptVerifier(store, _trust_policy(args)).evaluate(
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
    if args.command == "inspect":
        return 0
    return 0 if decision.state is DecisionState.REUSABLE_EXACT else 1


if __name__ == "__main__":
    sys.exit(main())
