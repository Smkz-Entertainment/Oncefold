"""MCP-shaped shadow adapter with no MCP SDK dependency or call suppression."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from oncefold.identity import (
    DependencyDescriptor,
    ReuseClass,
    SideEffectClass,
    canonical_json,
    sha256_digest,
)
from oncefold.protocol import (
    ActionIdentity,
    DecisionState,
    ReceiptStore,
    ReceiptVerifier,
    ReuseDecision,
    ReuseReceipt,
)

SHADOW_METADATA_KEY = "dev.oncefold/shadow-v1"
ToolCall = Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    decision: ReuseDecision
    shadow_metadata: Mapping[str, Any]
    receipt: ReuseReceipt | None = None
    actual_result_digest: str | None = None
    actual_result_matches_prior: bool | None = None
    calls_executed: int = 0


class MCPShadowProxy:
    """Observe equivalent tools/call requests while always forwarding the real call."""

    def __init__(self, store: ReceiptStore) -> None:
        self.store = store
        self.verifier = ReceiptVerifier(store)
        self._by_action: dict[str, str] = {}

    @staticmethod
    def _call_parts(request: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
        if request.get("method") != "tools/call":
            raise ValueError("shadow adapter only accepts tools/call")
        params = request.get("params")
        if not isinstance(params, Mapping):
            raise ValueError("tools/call params are required")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name or not isinstance(arguments, Mapping):
            raise ValueError("tools/call name and object arguments are required")
        return name, arguments

    def action_for_request(
        self,
        request: Mapping[str, Any],
        *,
        operation_version: str,
        trust_scope: str,
        side_effect_class: SideEffectClass,
        dependencies: Sequence[DependencyDescriptor] = (),
        environment: Mapping[str, str] = {},
        authorization_scope_digest: str | None = None,
        validator_identity: str | None = None,
        dependency_completeness: bool = True,
    ) -> ActionIdentity:
        name, arguments = self._call_parts(request)
        return ActionIdentity(
            operation_identity=f"mcp:tools/call:{name}",
            operation_version=operation_version,
            input_digest=sha256_digest(canonical_json(arguments)),
            trust_scope=trust_scope,
            environment=environment,
            dependencies=tuple(dependencies),
            side_effect_class=side_effect_class,
            authorization_scope_digest=authorization_scope_digest,
            dependency_completeness=dependency_completeness,
            validator_identity=validator_identity,
        )

    @staticmethod
    def _result_digest(result: Mapping[str, Any]) -> str:
        value = result.get("result", result)
        return sha256_digest(canonical_json(value))

    @staticmethod
    def _eligible(result: Mapping[str, Any], side_effect_class: SideEffectClass) -> bool:
        return side_effect_class is SideEffectClass.READ_ONLY and result.get("isError") is not True

    @staticmethod
    def _metadata(
        decision: ReuseDecision,
        *,
        receipt_digest: str | None,
        actual_result_digest: str | None = None,
        matches_prior: bool | None = None,
    ) -> dict[str, Any]:
        return {
            SHADOW_METADATA_KEY: {
                "decision": decision.state.value,
                "reason": decision.reason,
                "receipt_digest": receipt_digest,
                "actual_result_digest": actual_result_digest,
                "matches_prior": matches_prior,
                "would_reuse": decision.state is DecisionState.REUSABLE_EXACT,
            }
        }

    def observe_tools_call(
        self,
        request: Mapping[str, Any],
        result: Mapping[str, Any],
        *,
        operation_version: str,
        trust_scope: str,
        side_effect_class: SideEffectClass,
        dependencies: Sequence[DependencyDescriptor] = (),
        environment: Mapping[str, str] = {},
        authorization_scope_digest: str | None = None,
        producer_identity: str = "mcp-server",
        validator_identity: str | None = None,
        cache_scope: str = "private",
        dependency_completeness: bool = True,
        created_at: datetime | None = None,
    ) -> ShadowObservation:
        action = self.action_for_request(
            request,
            operation_version=operation_version,
            trust_scope=trust_scope,
            side_effect_class=side_effect_class,
            dependencies=dependencies,
            environment=environment,
            authorization_scope_digest=authorization_scope_digest,
            validator_identity=validator_identity,
            dependency_completeness=dependency_completeness,
        )
        if not self._eligible(result, side_effect_class):
            decision = ReuseDecision(DecisionState.UNSAFE, "ineligible MCP result")
            return ShadowObservation(decision, self._metadata(decision, receipt_digest=None))
        receipt = ReuseReceipt(
            action=action,
            result_digest=self._result_digest(result),
            media_type="application/json",
            producer_identity=producer_identity,
            reuse_class=ReuseClass.EXACT,
            dependency_snapshot=tuple(dependencies),
            provenance={"protocol": "mcp", "method": "tools/call"},
            trust_scope=trust_scope,
            cache_scope=cache_scope,
            validator_identity=validator_identity,
            created_at=created_at or datetime.now(UTC),
        )
        self.store.put(receipt)
        self._by_action[action.digest] = receipt.digest
        decision = ReuseDecision(
            DecisionState.UNKNOWN, "receipt recorded after forwarded call", receipt.digest
        )
        return ShadowObservation(
            decision, self._metadata(decision, receipt_digest=receipt.digest), receipt
        )

    def evaluate_tools_call(
        self,
        request: Mapping[str, Any],
        *,
        operation_version: str,
        trust_scope: str,
        side_effect_class: SideEffectClass,
        dependencies: Sequence[DependencyDescriptor] = (),
        environment: Mapping[str, str] = {},
        authorization_scope_digest: str | None = None,
        dependency_completeness: bool = True,
    ) -> ShadowObservation:
        action = self.action_for_request(
            request,
            operation_version=operation_version,
            trust_scope=trust_scope,
            side_effect_class=side_effect_class,
            dependencies=dependencies,
            environment=environment,
            authorization_scope_digest=authorization_scope_digest,
            dependency_completeness=dependency_completeness,
        )
        digest = self._by_action.get(action.digest)
        decision = (
            self.verifier.evaluate_digest(action, digest)
            if digest is not None
            else ReuseDecision(DecisionState.UNKNOWN, "no prior receipt")
        )
        return ShadowObservation(decision, self._metadata(decision, receipt_digest=digest))

    def forward(
        self,
        request: Mapping[str, Any],
        call: ToolCall,
        *,
        operation_version: str,
        trust_scope: str,
        side_effect_class: SideEffectClass,
        dependencies: Sequence[DependencyDescriptor] = (),
        environment: Mapping[str, str] = {},
        authorization_scope_digest: str | None = None,
        producer_identity: str = "mcp-server",
        validator_identity: str | None = None,
        cache_scope: str = "private",
        dependency_completeness: bool = True,
    ) -> ShadowObservation:
        prior = self.evaluate_tools_call(
            request,
            operation_version=operation_version,
            trust_scope=trust_scope,
            side_effect_class=side_effect_class,
            dependencies=dependencies,
            environment=environment,
            authorization_scope_digest=authorization_scope_digest,
            dependency_completeness=dependency_completeness,
        )
        actual_result = call(request)
        actual_digest = self._result_digest(actual_result)
        prior_digest = (
            prior.receipt.digest
            if prior.receipt is not None
            else prior.shadow_metadata[SHADOW_METADATA_KEY]["receipt_digest"]
        )
        matches = None
        if isinstance(prior_digest, str):
            prior_receipt = self.store.get(prior_digest)
            matches = prior_receipt is not None and prior_receipt.result_digest == actual_digest
        observed = self.observe_tools_call(
            request,
            actual_result,
            operation_version=operation_version,
            trust_scope=trust_scope,
            side_effect_class=side_effect_class,
            dependencies=dependencies,
            environment=environment,
            authorization_scope_digest=authorization_scope_digest,
            producer_identity=producer_identity,
            validator_identity=validator_identity,
            cache_scope=cache_scope,
            dependency_completeness=dependency_completeness,
        )
        metadata = self._metadata(
            prior.decision,
            receipt_digest=prior_digest
            if isinstance(prior_digest, str)
            else observed.receipt.digest
            if observed.receipt
            else None,
            actual_result_digest=actual_digest,
            matches_prior=matches,
        )
        return ShadowObservation(
            prior.decision,
            metadata,
            observed.receipt,
            actual_digest,
            matches,
            calls_executed=1,
        )
