# Oncefold

**Portable reuse evidence for agent tools.**

Oncefold is an open protocol and reference implementation for evaluating whether
previously produced tool work remains eligible for reuse under current
dependencies, scope, validator rules, revocation state, and result integrity.

Oncefold is not a general-purpose agent cache and does not make arbitrary
AI-generated output trustworthy.

> **Experimental 0.1 release.** The protocol and Python implementation are
> suitable for review, local integration, and conformance work. They are not a
> public trust service, signed attestation system, or production shared cache.

## Why a receipt?

A result digest alone proves only that some bytes match. A Oncefold receipt binds
that result to a deterministic Action Identity: the operation, version, inputs,
declared dependencies, environment, trust scope, validator contract, and
side-effect class. A consumer can then make a small deterministic decision
without trusting the producer's prose or importing the producer's storage.

```python
from hashlib import sha256

from oncefold import ActionIdentity, ReuseReceipt, ReuseClass, SideEffectClass

def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()

action = ActionIdentity(
    operation_identity="catalog.lookup",
    operation_version="2026-01",
    input_digest=digest("catalog.lookup:input"),
    trust_scope="tenant:one",
    side_effect_class=SideEffectClass.READ_ONLY,
)
receipt = ReuseReceipt(
    action=action,
    result_digest=digest("catalog.lookup:result"),
    media_type="application/json",
    producer_identity="catalog-worker",
    reuse_class=ReuseClass.EXACT,
    trust_scope=action.trust_scope,
)
```

The verifier returns states such as `REUSABLE_EXACT`, `REQUIRES_VALIDATION`,
`STALE`, `REVOKED`, `SCOPE_MISMATCH`, `UNSAFE`, and `UNKNOWN`. Unknown,
malformed, incomplete, or contradictory evidence fails closed.

## Install and verify

Requires Python 3.11 or newer. The runtime package has no third-party
dependencies.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

The examples show a producer and an independent consumer:

```powershell
python examples/interop_cli_producer.py receipt.json
python examples/interop_consumer.py receipt.json
```

A receipt can also be evaluated through the small CLI:

```powershell
oncefold verify receipt.json
```

## What Oncefold does and does not own

The core owns the reuse contract and deterministic verification semantics. It
does not own storage, execution, caching policy, orchestration, memory, model
behavior, or an agent runtime. `InMemoryReceiptStore` and
`SQLiteReceiptStore` are replaceable reference stores, not a required
architecture.

MCP is an optional integration boundary. The reference shadow adapter observes
completed `tools/call` work and always forwards the real call; it does not fork
MCP, add official MCP fields, or turn a receipt into request idempotency or
attestation. See [`docs/MCP_INTEROP.md`](docs/MCP_INTEROP.md).

## Implementations and conformance

- Python in `src/oncefold/` is the primary reference implementation.
- TypeScript in `implementations/typescript/` is an independent conformance
  consumer, not a full SDK.
- Go in `implementations/go/` is an independent conformance consumer, not a
  full SDK.
- The language-neutral 50-case corpus is in `conformance/vectors.json`.

Run the portable checks from the repository root:

```powershell
python conformance/stdlib_check.py
python -m pytest
node --experimental-strip-types implementations/typescript/run_conformance.ts conformance/vectors.json
go -C implementations/go run ./cmd/conformance ../../conformance/vectors.json
```

The protocol, schemas, and vectors are intended to be sufficient for a new
consumer implementation without reading the Python internals. See
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) and [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

## Maturity and research conclusion

This is a pre-1.0 protocol release. It has bounded cross-language conformance,
storage-independent verification, fail-closed negative controls, and a reference
MCP integration. It does not have authenticated public publishers, complete
dependency discovery, tenant isolation, or a live reuse canary.

Oncefold began as an investigation into general cross-agent caching. The final
authentic V5.1 experiment measured 70 primary observations, 5 safe natural
repeats, 7.1429% observation-weighted reuse, 12.8078% duration-weighted reuse,
and zero cross-runtime safe repeats. Both reuse measures were below the frozen
15% standalone threshold, so that broad cache thesis was killed. The
portable reuse-evidence interoperability layer survived and is what this
project publishes. The concise research record is in
[`docs/research/RESEARCH_HISTORY.md`](docs/research/RESEARCH_HISTORY.md).

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Do not add prompts, private
reasoning, credentials, secrets, private repository data, or external-mutation
replay paths to the project.

Oncefold is released under Apache-2.0.
