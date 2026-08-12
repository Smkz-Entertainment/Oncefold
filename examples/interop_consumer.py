"""Read and verify a receipt produced by another process."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oncefold import InMemoryReceiptStore, ReceiptVerifier, ReuseReceipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    receipt = ReuseReceipt.from_dict(json.loads(args.receipt.read_text(encoding="utf-8")))
    store = InMemoryReceiptStore()
    store.put(receipt)
    decision = ReceiptVerifier(store).evaluate(receipt.action, receipt)
    print(json.dumps({"state": decision.state.value, "reason": decision.reason}, sort_keys=True))


if __name__ == "__main__":
    main()
