# Architecture

Oncefold has one intentionally narrow dependency direction:

```text
tool or agent runtime
        |
        v
completed result + producer facts
        |
        v
Action Identity -> Reuse Receipt -> trust admission + deterministic verifier -> Reuse Decision
        |                               |
        +--> optional store ------------+
        +--> optional MCP shadow adapter
```

## Public core

The Python package contains the protocol models, canonicalization, deterministic
verifier, and two small reference stores. The Action Identity and Reuse Receipt
are portable JSON values. The verifier does not import an agent SDK, MCP SDK,
cloud service, model provider, or orchestration framework.

The core has no execution authority. A producer performs work and supplies the
facts it can observe. Oncefold evaluates those facts; it does not discover
complete dependencies magically or decide whether an arbitrary model answer is
true.

A consumer must explicitly configure producer, cache-scope, and optional
provenance admission before an authoritative reuse result is possible.

## Reference-only components

`SQLiteReceiptStore` and `InMemoryReceiptStore` demonstrate the store contract.
`oncefold.mcp_shadow` demonstrates how a completed MCP-shaped `tools/call` can
produce and later evaluate receipts while still forwarding the underlying call.
The TypeScript, Go, and .NET directories are independent conformance consumers.

These components are replaceable examples, not a distributed cache or required
runtime architecture.

## Deliberate exclusions

The public tree does not include the research-era CAS, broker, tracing, replay,
economics, benchmark launchers, runtime-specific workload servers, or private
repository adapters. They were useful for falsifying the original thesis but
would obscure the surviving protocol boundary.
