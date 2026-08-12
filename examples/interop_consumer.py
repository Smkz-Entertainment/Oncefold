"""Read and verify a receipt produced by another process."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oncefold import InMemoryReceiptStore, ReceiptTrustPolicy, ReceiptVerifier, ReuseReceipt
from oncefold.wire import load_json_object


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    receipt = ReuseReceipt.from_dict(load_json_object(args.receipt))
    store = InMemoryReceiptStore()
    store.put(receipt)
    decision = ReceiptVerifier(
        store, ReceiptTrustPolicy.for_producer(receipt.producer_identity, receipt.cache_scope)
    ).evaluate(receipt.action, receipt)
    print(json.dumps({"state": decision.state.value, "reason": decision.reason}, sort_keys=True))


if __name__ == "__main__":
    main()
