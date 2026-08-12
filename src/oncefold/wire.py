"""Bounded JSON ingress for protocol documents."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_COLLECTION = 256


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_JSON_COLLECTION:
        raise ValueError("JSON object exceeds the input bound")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def _reject_number(value: str) -> None:
    raise ValueError(f"JSON numbers are not accepted: {value}")


def _check_depth(data: bytes) -> None:
    depth = 0
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
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds the input bound")
        elif byte in (ord("}"), ord("]")):
            depth -= 1
            if depth < 0:
                raise ValueError("JSON nesting is malformed")


def _check_unicode(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("JSON contains an invalid Unicode scalar") from exc
        if any(char in "\u2028\u2029" for char in value):
            raise ValueError("JSON contains a prohibited line-separator code point")
    elif isinstance(value, Mapping):
        if len(value) > MAX_JSON_COLLECTION:
            raise ValueError("JSON object exceeds the input bound")
        for key, item in value.items():
            _check_unicode(key)
            _check_unicode(item)
    elif isinstance(value, list):
        if len(value) > MAX_JSON_COLLECTION:
            raise ValueError("JSON array exceeds the input bound")
        for item in value:
            _check_unicode(item)


def parse_json_object(data: bytes | str) -> dict[str, Any]:
    """Parse one bounded JSON object, rejecting duplicate keys and surrogates."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    _check_depth(raw)
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_int=_reject_number,
            parse_float=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON input") from exc
    if not isinstance(value, dict):
        raise TypeError("JSON document must be an object")
    _check_unicode(value)
    return value


def load_json_object(path: Path) -> dict[str, Any]:
    """Read and parse a bounded JSON object without an unbounded read."""

    with path.open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    return parse_json_object(raw)
