"""Storage-independent Action Identity, Reuse Receipt, and decision semantics."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

from oncefold.identity import (
    MAX_COLLECTION_LENGTH,
    MAX_STRING_LENGTH,
    DependencyDescriptor,
    ReuseClass,
    SideEffectClass,
    canonical_json,
    canonical_timestamp,
    sha256_digest,
)

_ACTION_SCHEMA = "oncefold.action/1"
_RECEIPT_SCHEMA = "oncefold.receipt/1"
_MAX_STRING = MAX_STRING_LENGTH
_MAX_COLLECTION = MAX_COLLECTION_LENGTH
_MISSING = object()


def _bounded_text(value: object, field_name: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    text = value
    if required and not text:
        raise ValueError(f"{field_name} is required")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} contains an invalid Unicode scalar") from exc
    if len(text) > _MAX_STRING or any(ord(char) < 0x20 for char in text):
        raise ValueError(f"{field_name} is invalid or exceeds the canonical bound")
    return text


def _optional_text(value: object | None, field_name: str) -> str | None:
    return None if value is None else _bounded_text(value, field_name, required=False)


def _boolean(value: object, field_name: str, *, default: bool) -> bool:
    if value is _MISSING:
        return default
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be boolean")
    return value


def _strict_keys(
    value: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    object_name: str,
) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValueError(f"{object_name} is missing required fields: {sorted(missing)}")
    if unknown:
        raise ValueError(f"{object_name} contains unknown fields: {sorted(unknown)}")


def _string_mapping(value: Mapping[str, Any], field_name: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be an object")
    if len(value) > _MAX_COLLECTION:
        raise ValueError(f"{field_name} exceeds the collection bound")
    return dict(
        sorted(
            (
                _bounded_text(key, f"{field_name} key"),
                _bounded_text(item, f"{field_name} value"),
            )
            for key, item in value.items()
        )
    )


def _dependency(value: Mapping[str, Any]) -> DependencyDescriptor:
    if not isinstance(value, Mapping):
        raise TypeError("dependency must be an object")
    _strict_keys(value, {"kind", "identity", "digest"}, {"required"}, "dependency")
    return DependencyDescriptor(
        kind=_bounded_text(value["kind"], "dependency kind"),
        identity=_bounded_text(value["identity"], "dependency identity"),
        digest=_bounded_text(value["digest"], "dependency digest"),
        required=_boolean(value.get("required", _MISSING), "dependency.required", default=True),
    )


def _dependencies(value: object, field_name: str) -> tuple[DependencyDescriptor, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field_name} must be an array")
    if len(value) > _MAX_COLLECTION:
        raise ValueError(f"{field_name} exceeds the collection bound")
    parsed = tuple(_dependency(item) for item in value)
    return tuple(
        sorted(
            parsed,
            key=lambda item: tuple(
                field.encode("utf-8") for field in (item.kind, item.identity, item.digest)
            ),
        )
    )


def _check_digest_field(value: str, field_name: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ActionIdentity:
    """Canonical facts that identify an operation at the reuse boundary."""

    operation_identity: str
    operation_version: str
    input_digest: str
    trust_scope: str = "local"
    environment: Mapping[str, str] = field(default_factory=dict)
    dependencies: tuple[DependencyDescriptor, ...] = ()
    side_effect_class: SideEffectClass = SideEffectClass.UNKNOWN
    authorization_scope_digest: str | None = None
    freshness: Mapping[str, str] = field(default_factory=dict)
    dependency_completeness: bool = True
    validator_identity: str | None = None
    schema_version: str = _ACTION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _ACTION_SCHEMA:
            raise ValueError(f"unsupported action schema: {self.schema_version}")
        _bounded_text(self.operation_identity, "operation_identity")
        _bounded_text(self.operation_version, "operation_version")
        _check_digest_field(self.input_digest, "input_digest")
        _bounded_text(self.trust_scope, "trust_scope")
        object.__setattr__(self, "side_effect_class", SideEffectClass(self.side_effect_class))
        object.__setattr__(self, "environment", _string_mapping(self.environment, "environment"))
        object.__setattr__(self, "freshness", _string_mapping(self.freshness, "freshness"))
        if len(self.dependencies) > _MAX_COLLECTION:
            raise ValueError("dependencies exceeds the collection bound")
        if not all(isinstance(item, DependencyDescriptor) for item in self.dependencies):
            raise TypeError("dependencies must contain DependencyDescriptor values")
        if not isinstance(self.dependency_completeness, bool):
            raise TypeError("dependency_completeness must be boolean")
        object.__setattr__(
            self,
            "dependencies",
            tuple(
                sorted(
                    self.dependencies,
                    key=lambda item: tuple(
                        field.encode("utf-8") for field in (item.kind, item.identity, item.digest)
                    ),
                )
            ),
        )
        dependency_ids = {(item.kind, item.identity) for item in self.dependencies}
        if len(dependency_ids) != len(self.dependencies):
            raise ValueError("duplicate dependency identity")
        if self.authorization_scope_digest is not None:
            _check_digest_field(self.authorization_scope_digest, "authorization_scope_digest")
        object.__setattr__(
            self,
            "validator_identity",
            _optional_text(self.validator_identity, "validator_identity"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "operation_identity": self.operation_identity,
            "operation_version": self.operation_version,
            "input_digest": self.input_digest,
            "trust_scope": self.trust_scope,
            "environment": dict(self.environment),
            "dependencies": [item.as_dict() for item in self.dependencies],
            "side_effect_class": self.side_effect_class.value,
            "authorization_scope_digest": self.authorization_scope_digest,
            "freshness": dict(self.freshness),
            "dependency_completeness": self.dependency_completeness,
            "validator_identity": self.validator_identity,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_dict())

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ActionIdentity:
        if not isinstance(value, Mapping):
            raise TypeError("action identity must be an object")
        _strict_keys(
            value,
            {"schema_version", "operation_identity", "operation_version", "input_digest"},
            {
                "trust_scope",
                "environment",
                "dependencies",
                "side_effect_class",
                "authorization_scope_digest",
                "freshness",
                "dependency_completeness",
                "validator_identity",
            },
            "action identity",
        )
        return cls(
            schema_version=_bounded_text(value["schema_version"], "schema_version"),
            operation_identity=_bounded_text(value["operation_identity"], "operation_identity"),
            operation_version=_bounded_text(value["operation_version"], "operation_version"),
            input_digest=_bounded_text(value["input_digest"], "input_digest"),
            trust_scope=_bounded_text(value.get("trust_scope", "local"), "trust_scope"),
            environment=_string_mapping(
                cast(Mapping[str, Any], value.get("environment", {})), "environment"
            ),
            dependencies=_dependencies(value.get("dependencies", []), "dependencies"),
            side_effect_class=SideEffectClass(
                value.get("side_effect_class", SideEffectClass.UNKNOWN)
            ),
            authorization_scope_digest=_optional_text(
                value.get("authorization_scope_digest"), "authorization_scope_digest"
            ),
            freshness=_string_mapping(
                cast(Mapping[str, Any], value.get("freshness", {})), "freshness"
            ),
            dependency_completeness=_boolean(
                value.get("dependency_completeness", _MISSING),
                "dependency_completeness",
                default=True,
            ),
            validator_identity=_optional_text(
                value.get("validator_identity"), "validator_identity"
            ),
        )


@dataclass(frozen=True, slots=True)
class ReuseReceipt:
    """Bounded post-execution evidence that a consumer can verify independently."""

    action: ActionIdentity
    result_digest: str
    media_type: str
    producer_identity: str
    reuse_class: ReuseClass
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    dependency_snapshot: tuple[DependencyDescriptor, ...] = ()
    result_reference: str | None = None
    provenance: Mapping[str, str] = field(default_factory=dict)
    trust_scope: str = "local"
    cache_scope: str = "private"
    revocation_ref: str | None = None
    validator_identity: str | None = None
    execution_metadata: Mapping[str, str] = field(default_factory=dict)
    economics: Mapping[str, str] = field(default_factory=dict)
    schema_version: str = _RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != _RECEIPT_SCHEMA:
            raise ValueError(f"unsupported receipt schema: {self.schema_version}")
        _check_digest_field(self.result_digest, "result_digest")
        _bounded_text(self.media_type, "media_type")
        _bounded_text(self.producer_identity, "producer_identity")
        object.__setattr__(self, "reuse_class", ReuseClass(self.reuse_class))
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        object.__setattr__(self, "created_at", self.created_at.astimezone(UTC))
        if len(self.dependency_snapshot) > _MAX_COLLECTION:
            raise ValueError("dependency_snapshot exceeds the collection bound")
        if not all(isinstance(item, DependencyDescriptor) for item in self.dependency_snapshot):
            raise TypeError("dependency_snapshot must contain DependencyDescriptor values")
        object.__setattr__(
            self,
            "dependency_snapshot",
            tuple(
                sorted(
                    self.dependency_snapshot,
                    key=lambda item: tuple(
                        field.encode("utf-8") for field in (item.kind, item.identity, item.digest)
                    ),
                )
            ),
        )
        dependency_ids = {(item.kind, item.identity) for item in self.dependency_snapshot}
        if len(dependency_ids) != len(self.dependency_snapshot):
            raise ValueError("duplicate dependency identity in receipt snapshot")
        object.__setattr__(self, "provenance", _string_mapping(self.provenance, "provenance"))
        object.__setattr__(
            self,
            "execution_metadata",
            _string_mapping(self.execution_metadata, "execution_metadata"),
        )
        object.__setattr__(self, "economics", _string_mapping(self.economics, "economics"))
        _bounded_text(self.trust_scope, "trust_scope")
        _bounded_text(self.cache_scope, "cache_scope")
        object.__setattr__(
            self, "result_reference", _optional_text(self.result_reference, "result_reference")
        )
        object.__setattr__(
            self, "revocation_ref", _optional_text(self.revocation_ref, "revocation_ref")
        )
        object.__setattr__(
            self,
            "validator_identity",
            _optional_text(self.validator_identity, "validator_identity"),
        )

    def as_dict(self, *, include_receipt_digest: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "action": self.action.as_dict(),
            "action_digest": self.action.digest,
            "result_digest": self.result_digest,
            "result_reference": self.result_reference,
            "media_type": self.media_type,
            "producer_identity": self.producer_identity,
            "reuse_class": self.reuse_class.value,
            "created_at": canonical_timestamp(
                self.created_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
            ),
            "dependency_snapshot": [item.as_dict() for item in self.dependency_snapshot],
            "provenance": dict(self.provenance),
            "trust_scope": self.trust_scope,
            "cache_scope": self.cache_scope,
            "revocation_ref": self.revocation_ref,
            "validator_identity": self.validator_identity,
            "execution_metadata": dict(self.execution_metadata),
            "economics": dict(self.economics),
        }
        if include_receipt_digest:
            value["receipt_digest"] = self.digest
        return value

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_dict(include_receipt_digest=False))

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReuseReceipt:
        if not isinstance(value, Mapping):
            raise TypeError("reuse receipt must be an object")
        _strict_keys(
            value,
            {
                "schema_version",
                "action",
                "action_digest",
                "result_digest",
                "media_type",
                "producer_identity",
                "reuse_class",
                "created_at",
                "dependency_snapshot",
                "trust_scope",
                "cache_scope",
                "receipt_digest",
            },
            {
                "result_reference",
                "provenance",
                "revocation_ref",
                "validator_identity",
                "execution_metadata",
                "economics",
            },
            "reuse receipt",
        )
        action = ActionIdentity.from_dict(cast(Mapping[str, Any], value["action"]))
        if value["action_digest"] != action.digest:
            raise ValueError("receipt action digest mismatch")
        receipt = cls(
            schema_version=_bounded_text(value["schema_version"], "schema_version"),
            action=action,
            result_digest=_bounded_text(value["result_digest"], "result_digest"),
            result_reference=_optional_text(value.get("result_reference"), "result_reference"),
            media_type=_bounded_text(value["media_type"], "media_type"),
            producer_identity=_bounded_text(value["producer_identity"], "producer_identity"),
            reuse_class=ReuseClass(value["reuse_class"]),
            created_at=datetime.fromisoformat(
                canonical_timestamp(value["created_at"], "created_at").replace("Z", "+00:00")
            ),
            dependency_snapshot=_dependencies(value["dependency_snapshot"], "dependency_snapshot"),
            provenance=_string_mapping(
                cast(Mapping[str, Any], value.get("provenance", {})), "provenance"
            ),
            trust_scope=_bounded_text(value["trust_scope"], "trust_scope"),
            cache_scope=_bounded_text(value["cache_scope"], "cache_scope"),
            revocation_ref=_optional_text(value.get("revocation_ref"), "revocation_ref"),
            validator_identity=_optional_text(
                value.get("validator_identity"), "validator_identity"
            ),
            execution_metadata=_string_mapping(
                cast(Mapping[str, Any], value.get("execution_metadata", {})), "execution_metadata"
            ),
            economics=_string_mapping(
                cast(Mapping[str, Any], value.get("economics", {})), "economics"
            ),
        )
        if value["receipt_digest"] != receipt.digest:
            raise ValueError("receipt digest mismatch")
        return receipt


class DecisionState(StrEnum):
    REUSABLE_EXACT = "REUSABLE_EXACT"
    REQUIRES_VALIDATION = "REQUIRES_VALIDATION"
    ADVISORY_ONLY = "ADVISORY_ONLY"
    REVOKED = "REVOKED"
    STALE = "STALE"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    UNSAFE = "UNSAFE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ReuseDecision:
    state: DecisionState
    reason: str
    receipt_digest: str | None = None


class ReceiptStore(Protocol):
    """Minimal store contract consumed by the verifier."""

    def put(self, receipt: ReuseReceipt) -> None: ...

    def get(self, receipt_digest: str) -> ReuseReceipt | None: ...

    def is_revoked(self, receipt_digest: str) -> bool: ...

    def revoke(self, receipt_digest: str, reason: str = "") -> None: ...


class InMemoryReceiptStore:
    """Small alternate backend used for portability and conformance tests."""

    def __init__(self) -> None:
        self._receipts: dict[str, ReuseReceipt] = {}
        self._revoked: set[str] = set()

    def put(self, receipt: ReuseReceipt) -> None:
        self._receipts[receipt.digest] = receipt

    def get(self, receipt_digest: str) -> ReuseReceipt | None:
        return self._receipts.get(receipt_digest)

    def is_revoked(self, receipt_digest: str) -> bool:
        return receipt_digest in self._revoked

    def revoke(self, receipt_digest: str, reason: str = "") -> None:
        _check_digest_field(receipt_digest, "receipt_digest")
        del reason
        self._revoked.add(receipt_digest)


class SQLiteReceiptStore:
    """Reference receipt backend; the public verifier does not depend on SQLite."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        parent = Path(self.path).parent
        if str(parent) not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path)
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS oncefold_receipts "
                "(digest TEXT PRIMARY KEY, payload TEXT NOT NULL, "
                "revoked INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS oncefold_revocations "
                "(digest TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '')"
            )
            db.commit()
        finally:
            db.close()

    def put(self, receipt: ReuseReceipt) -> None:
        payload = json.dumps(
            receipt.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        db = sqlite3.connect(self.path)
        try:
            db.execute(
                "INSERT INTO oncefold_receipts (digest, payload, revoked) VALUES (?, ?, 0) "
                "ON CONFLICT(digest) DO UPDATE SET payload = excluded.payload",
                (receipt.digest, payload),
            )
            db.commit()
        finally:
            db.close()

    def get(self, receipt_digest: str) -> ReuseReceipt | None:
        db = sqlite3.connect(self.path)
        try:
            row = db.execute(
                "SELECT payload, revoked FROM oncefold_receipts WHERE digest = ?",
                (receipt_digest,),
            ).fetchone()
        finally:
            db.close()
        if row is None or bool(row[1]) or self.is_revoked(receipt_digest):
            return None
        try:
            receipt = ReuseReceipt.from_dict(json.loads(str(row[0])))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return None
        return receipt if receipt.digest == receipt_digest else None

    def is_revoked(self, receipt_digest: str) -> bool:
        db = sqlite3.connect(self.path)
        try:
            row = db.execute(
                "SELECT revoked FROM oncefold_receipts WHERE digest = ?", (receipt_digest,)
            ).fetchone()
            marker = db.execute(
                "SELECT 1 FROM oncefold_revocations WHERE digest = ?", (receipt_digest,)
            ).fetchone()
        finally:
            db.close()
        return (row is not None and bool(row[0])) or marker is not None

    def revoke(self, receipt_digest: str, reason: str = "") -> None:
        _check_digest_field(receipt_digest, "receipt_digest")
        if len(reason) > _MAX_STRING:
            raise ValueError("revocation reason exceeds the canonical bound")
        db = sqlite3.connect(self.path)
        try:
            db.execute(
                "INSERT INTO oncefold_revocations (digest, reason) VALUES (?, ?) "
                "ON CONFLICT(digest) DO UPDATE SET reason = excluded.reason",
                (receipt_digest, reason),
            )
            db.execute(
                "UPDATE oncefold_receipts SET revoked = 1 WHERE digest = ?", (receipt_digest,)
            )
            db.commit()
        finally:
            db.close()


Validator = Callable[[ReuseReceipt], object]


@dataclass(frozen=True, slots=True)
class ReceiptTrustPolicy:
    """Consumer policy that admits receipt provenance for automatic reuse."""

    allowed_producers: frozenset[str] = frozenset()
    allowed_cache_scopes: frozenset[str] = frozenset()
    required_provenance: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for producer in self.allowed_producers:
            _bounded_text(producer, "allowed producer")
        for scope in self.allowed_cache_scopes:
            _bounded_text(scope, "allowed cache scope")
        object.__setattr__(
            self,
            "required_provenance",
            _string_mapping(self.required_provenance, "required_provenance"),
        )

    @classmethod
    def for_producer(
        cls,
        producer_identity: str,
        cache_scope: str,
        *,
        required_provenance: Mapping[str, str] | None = None,
    ) -> ReceiptTrustPolicy:
        return cls(
            allowed_producers=frozenset({_bounded_text(producer_identity, "producer_identity")}),
            allowed_cache_scopes=frozenset({_bounded_text(cache_scope, "cache_scope")}),
            required_provenance=required_provenance or {},
        )

    def admits(self, receipt: ReuseReceipt) -> bool:
        if receipt.producer_identity not in self.allowed_producers:
            return False
        if receipt.cache_scope not in self.allowed_cache_scopes:
            return False
        return all(
            receipt.provenance.get(key) == value for key, value in self.required_provenance.items()
        )


class ReceiptVerifier:
    """Deterministic, fail-closed consumer evaluation."""

    def __init__(self, store: ReceiptStore, trust_policy: ReceiptTrustPolicy | None = None) -> None:
        self.store = store
        self.trust_policy = trust_policy or ReceiptTrustPolicy()

    @staticmethod
    def validate_receipt(receipt: ReuseReceipt) -> None:
        parsed = ReuseReceipt.from_dict(receipt.as_dict())
        if parsed.digest != receipt.digest:
            raise ValueError("receipt canonical digest changed")

    def evaluate_digest(
        self,
        action: ActionIdentity,
        receipt_digest: str,
        *,
        validator: Validator | None = None,
        available_result_digest: str | None = None,
    ) -> ReuseDecision:
        receipt = self.store.get(receipt_digest)
        if receipt is None:
            if self.store.is_revoked(receipt_digest):
                return ReuseDecision(DecisionState.REVOKED, "receipt revoked", receipt_digest)
            return ReuseDecision(DecisionState.UNKNOWN, "receipt not found", receipt_digest)
        return self.evaluate(
            action,
            receipt,
            validator=validator,
            available_result_digest=available_result_digest,
        )

    def evaluate(
        self,
        action: ActionIdentity,
        receipt: ReuseReceipt | None,
        *,
        validator: Validator | None = None,
        available_result_digest: str | None = None,
    ) -> ReuseDecision:
        if receipt is None:
            return ReuseDecision(DecisionState.UNKNOWN, "no receipt")
        receipt_digest = receipt.digest
        try:
            self.validate_receipt(receipt)
        except (TypeError, ValueError):
            return ReuseDecision(
                DecisionState.UNKNOWN, "receipt integrity or schema failure", receipt_digest
            )
        if self.store.is_revoked(receipt_digest) or receipt.revocation_ref is not None:
            return ReuseDecision(DecisionState.REVOKED, "receipt revoked", receipt_digest)
        if (
            action.trust_scope != receipt.trust_scope
            or action.trust_scope != receipt.action.trust_scope
        ):
            return ReuseDecision(
                DecisionState.SCOPE_MISMATCH, "trust scope mismatch", receipt_digest
            )
        if action.authorization_scope_digest != receipt.action.authorization_scope_digest:
            return ReuseDecision(
                DecisionState.SCOPE_MISMATCH, "authorization scope mismatch", receipt_digest
            )
        if action.side_effect_class is not SideEffectClass.READ_ONLY:
            return ReuseDecision(
                DecisionState.UNSAFE, "non-read-only action is not reusable", receipt_digest
            )
        if receipt.action.side_effect_class is not SideEffectClass.READ_ONLY:
            return ReuseDecision(
                DecisionState.UNSAFE, "receipt describes non-read-only work", receipt_digest
            )
        if receipt.reuse_class is ReuseClass.UNSAFE:
            return ReuseDecision(DecisionState.UNSAFE, "receipt is marked unsafe", receipt_digest)
        if not action.dependency_completeness or not receipt.action.dependency_completeness:
            return ReuseDecision(
                DecisionState.UNKNOWN,
                "dependency declaration is incomplete; exact reuse is unsafe",
                receipt_digest,
            )
        if action.digest != receipt.action.digest:
            return ReuseDecision(DecisionState.STALE, "action identity mismatch", receipt_digest)
        if tuple(action.dependencies) != tuple(receipt.dependency_snapshot):
            return ReuseDecision(
                DecisionState.STALE, "dependency snapshot mismatch", receipt_digest
            )
        if available_result_digest is not None:
            try:
                _check_digest_field(available_result_digest, "available_result_digest")
            except ValueError:
                return ReuseDecision(
                    DecisionState.UNKNOWN,
                    "available result digest is malformed",
                    receipt_digest,
                )
            if available_result_digest != receipt.result_digest:
                return ReuseDecision(
                    DecisionState.UNKNOWN, "result digest mismatch", receipt_digest
                )
        if receipt.reuse_class is ReuseClass.EXACT:
            if not self.trust_policy.admits(receipt):
                return ReuseDecision(
                    DecisionState.UNKNOWN,
                    "receipt producer, cache scope, or provenance is not trusted",
                    receipt_digest,
                )
            return ReuseDecision(
                DecisionState.REUSABLE_EXACT, "identity and dependencies match", receipt_digest
            )
        if receipt.reuse_class is ReuseClass.VERIFIED:
            if not self.trust_policy.admits(receipt):
                return ReuseDecision(
                    DecisionState.UNKNOWN,
                    "receipt producer, cache scope, or provenance is not trusted",
                    receipt_digest,
                )
            if (
                not receipt.validator_identity
                or receipt.validator_identity != action.validator_identity
            ):
                return ReuseDecision(
                    DecisionState.REQUIRES_VALIDATION,
                    "matching validator identity required",
                    receipt_digest,
                )
            if validator is None:
                return ReuseDecision(
                    DecisionState.REQUIRES_VALIDATION, "current validator required", receipt_digest
                )
            try:
                validation_result = validator(receipt)
            except Exception:
                return ReuseDecision(
                    DecisionState.UNKNOWN, "current validator failed", receipt_digest
                )
            if type(validation_result) is not bool:
                return ReuseDecision(
                    DecisionState.UNKNOWN,
                    "current validator returned a non-boolean result",
                    receipt_digest,
                )
            if validation_result:
                return ReuseDecision(
                    DecisionState.REUSABLE_EXACT, "current validator passed", receipt_digest
                )
            return ReuseDecision(
                DecisionState.STALE, "current validator rejected receipt", receipt_digest
            )
        if receipt.reuse_class is ReuseClass.ADVISORY:
            return ReuseDecision(
                DecisionState.ADVISORY_ONLY, "context only; not authoritative", receipt_digest
            )
        return ReuseDecision(DecisionState.UNSAFE, "unknown reuse class", receipt_digest)
