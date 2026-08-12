"""Canonical JSON and shared enums for the Oncefold protocol."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_STRING_LENGTH = 4096
MAX_COLLECTION_LENGTH = 256
MAX_CANONICAL_DEPTH = 16
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ReuseClass(StrEnum):
    """The maximum authority a producer says a receipt may receive."""

    EXACT = "EXACT"
    VERIFIED = "VERIFIED"
    ADVISORY = "ADVISORY"
    UNSAFE = "UNSAFE"


class SideEffectClass(StrEnum):
    """The side-effect boundary of the described operation."""

    READ_ONLY = "READ_ONLY"
    LOCAL_WRITE = "LOCAL_WRITE"
    EXTERNAL_MUTATION = "EXTERNAL_MUTATION"
    UNKNOWN = "UNKNOWN"


def _bounded_string(value: object, field_name: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if required and not value:
        raise ValueError(f"{field_name} is required")
    if len(value) > MAX_STRING_LENGTH or any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field_name} is invalid or exceeds the canonical bound")
    return value


def _normalize(value: Any, *, depth: int = 0) -> Any:
    """Normalize bounded JSON-compatible values for deterministic hashing."""

    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError("canonical value is too deeply nested")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        _bounded_string(value, "canonical string", required=False)
        return unicodedata.normalize("NFC", value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not canonicalizable")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_LENGTH:
            raise ValueError("mapping exceeds the canonical bound")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            _bounded_string(normalized_key, "canonical object key")
            if normalized_key in normalized:
                raise ValueError("mapping keys collide after normalization")
            normalized[normalized_key] = _normalize(item, depth=depth + 1)
        return dict(sorted(normalized.items()))
    if isinstance(value, list | tuple):
        if len(value) > MAX_COLLECTION_LENGTH:
            raise ValueError("sequence exceeds the canonical bound")
        return [_normalize(item, depth=depth + 1) for item in value]
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON for a bounded protocol value."""

    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(value).hexdigest()


def _check_digest(value: object, field_name: str) -> str:
    candidate = _bounded_string(value, field_name)
    if not _DIGEST_RE.fullmatch(candidate):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return candidate


@dataclass(frozen=True, slots=True)
class DependencyDescriptor:
    """A producer-supplied dependency identity and digest."""

    kind: str
    identity: str
    digest: str
    required: bool = True

    def __post_init__(self) -> None:
        _bounded_string(self.kind, "dependency kind")
        _bounded_string(self.identity, "dependency identity")
        _check_digest(self.digest, "dependency digest")
        if not isinstance(self.required, bool):
            raise TypeError("dependency required flag must be boolean")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identity": self.identity,
            "digest": self.digest,
            "required": self.required,
        }
