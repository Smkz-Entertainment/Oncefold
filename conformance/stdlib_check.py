"""Check the portable vector's canonical digests with the standard library only."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any


def normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(
        normalize(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def main() -> int:
    document = json.loads(Path(__file__).with_name("vectors.json").read_text(encoding="utf-8"))
    base = document["base"]
    action = base["action"]
    receipt = dict(base["receipt"])
    if hashlib.sha256(canonical(action)).hexdigest() != receipt["action_digest"]:
        return 1
    without_digest = dict(receipt)
    without_digest.pop("receipt_digest")
    if hashlib.sha256(canonical(without_digest)).hexdigest() != receipt["receipt_digest"]:
        return 2
    if document["canonicalization"]["equivalent"] is not True:
        return 3
    if (
        unicodedata.normalize("NFC", document["canonicalization"]["decomposed"])
        != document["canonicalization"]["composed"]
    ):
        return 4
    if not all("expected_state" in case for case in document["cases"]):
        return 5
    print(f"stdlib vectors: {len(document['cases'])} cases; canonical digests verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
