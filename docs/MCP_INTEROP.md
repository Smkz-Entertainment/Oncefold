# MCP interoperability

MCP is an optional reference integration, not Oncefold's identity and not a
Oncefold dependency. Oncefold does not fork MCP or claim official MCP
standardization.

## Boundary

An MCP `tools/call` describes transport and tool invocation. It does not by
itself prove that a completed result remains reusable. A producer still needs
to supply an Action Identity, dependency/freshness facts, result digest, trust
scope, side-effect class, and validator contract where relevant.

The reference `oncefold.mcp_shadow` adapter shows the boundary:

1. derive an action input digest from bounded, number-free tool arguments;
2. forward the real call;
3. record a receipt only for an ordinary successful read-only result;
4. evaluate a later equivalent action against the stored receipt; and
5. report the decision and result comparison as local shadow metadata.

The adapter's verifier has no trusted producer by default. A caller that wants
an authoritative `REUSABLE_EXACT` observation must pass a
`ReceiptTrustPolicy` binding the expected MCP producer and cache scope. Numeric
tool arguments are rejected by the canonicalizer rather than hashed with
language-specific number rules.

Every `forward` call executes the supplied tool. The adapter never suppresses a
call, never turns a receipt into a cache hit, and never supplies idempotency for
an external mutation.

## Separation of concerns

| Mechanism | Responsibility | Oncefold relationship |
| --- | --- | --- |
| MCP transport | capability negotiation and message exchange | carries a receipt or metadata when an adapter chooses to do so |
| attestation | binds a caller/tool/arguments for audit or authorization | may be an input fact; Oncefold does not mint or replace it |
| idempotency | handles retry/deduplication of one request | distinct from evaluating completed prior evidence |
| Oncefold | evaluates reuse eligibility under current facts | consumes completed evidence and fails closed |

The example uses an experimental `dev.oncefold/shadow-v1` metadata key in local
output. It is not an official MCP extension. A production integration must
define its own authorization, transport, lifecycle, and result-storage policy.
