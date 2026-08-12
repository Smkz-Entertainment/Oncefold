"""Check protocol digests and ingress guards with the standard library only."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_COLLECTION = 256
TIMESTAMP = re.compile(
    r"^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$"
)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_JSON_COLLECTION:
        raise ValueError("JSON object exceeds bound")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def _reject_number(value: str) -> None:
    raise ValueError(f"JSON numbers are not accepted: {value}")


def _depth(data: bytes) -> None:
    level = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            level += 1
            if level > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds bound")
        elif byte in (ord("}"), ord("]")):
            level -= 1
            if level < 0:
                raise ValueError("malformed JSON nesting")


def parse_object(data: bytes | str) -> dict[str, Any]:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds bound")
    _depth(raw)
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique,
        parse_constant=_reject_constant,
        parse_int=_reject_number,
        parse_float=_reject_number,
    )
    if not isinstance(value, dict):
        raise TypeError("JSON document must be an object")
    check_unicode(value)
    return value


def check_unicode(value: Any) -> None:
    if isinstance(value, str):
        value.encode("utf-8")
        if any(char in "\u2028\u2029" for char in value):
            raise ValueError("prohibited line-separator code point")
    elif isinstance(value, dict):
        if len(value) > MAX_JSON_COLLECTION:
            raise ValueError("JSON object exceeds bound")
        for key, item in value.items():
            check_unicode(key)
            check_unicode(item)
    elif isinstance(value, list):
        if len(value) > MAX_JSON_COLLECTION:
            raise ValueError("JSON array exceeds bound")
        for item in value:
            check_unicode(item)


def normalize(value: Any) -> Any:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("invalid Unicode scalar") from exc
        if any(char in "\u2028\u2029" for char in value):
            raise ValueError("prohibited line-separator code point")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int | float):
        raise TypeError("numbers are not canonicalizable")
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if any(char in "\u2028\u2029" for char in normalized_key):
                raise ValueError("prohibited line-separator code point")
            normalized[normalized_key] = normalize(item)
        if len(normalized) != len(value):
            raise ValueError("canonical key collision")
        return dict(sorted(normalized.items(), key=lambda item: item[0].encode("utf-8")))
    if isinstance(value, list):
        return [normalize(item) for item in value]
    raise TypeError(f"unsupported value: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    return json.dumps(
        normalize(value), ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode("utf-8")


def canonical_timestamp(value: str) -> str:
    if not TIMESTAMP.fullmatch(value):
        raise ValueError("non-canonical timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("timestamp is not UTC")
    if parsed.microsecond:
        return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def main() -> int:
    document = parse_object(Path(__file__).with_name("vectors.json").read_bytes())
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
    if (
        hashlib.sha256(canonical(document["canonicalization"]["utf8_key_order"])).hexdigest()
        != document["canonicalization"]["utf8_key_order_digest"]
    ):
        return 5
    if not all("expected_state" in case for case in document["cases"]):
        return 6
    for item in document["timestamp_cases"]:
        try:
            actual = canonical_timestamp(item["value"])
            if not item["accepted"] or actual != item.get("canonical", actual):
                return 7
        except (TypeError, ValueError):
            if item["accepted"]:
                return 8
    for item in document["raw_json_cases"]:
        try:
            parse_object(item["json"])
            accepted = True
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            accepted = False
        if accepted is not item["accepted"]:
            return 9
    print(f"stdlib vectors: {len(document['cases'])} cases; digests and ingress guards verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
