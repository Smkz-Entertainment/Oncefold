# Limitations

Oncefold is deliberately narrower than a cache or agent platform.

- It does not execute work or discover all relevant dependencies.
- It does not make arbitrary LLM output safe, true, or authoritative.
- It does not provide a public cache, remote CAS, compute marketplace, SaaS,
  orchestrator, memory system, or distributed coordination layer.
- It does not provide cryptographic publisher signatures or a public trust
  network.
- `producer_identity` is a label until a consumer-supplied trust policy admits
  it; a valid digest alone cannot authorize reuse.
- The canonicalizer rejects JSON numbers and requires callers to define a
  separate input-digest contract for numeric external inputs.
- The canonicalizer rejects U+2028 and U+2029 line-separator code points to
  preserve byte parity across the reference implementations.
- `dependency_completeness` must be explicitly supplied on the wire; omission
  is malformed and programmatic actions default to incomplete.
- Protocol JSON ingress is bounded and rejects duplicate keys, excessive
  nesting, non-standard constants, and invalid Unicode scalar sequences.
- It does not prove tenant isolation or protect a compromised host.
- It does not guarantee that a producer observed every external dependency.
- `EXACT` is appropriate only for sufficiently closed, deterministic,
  inspectable, read-only work; `VERIFIED` still requires a current validator.
- External mutations such as email, payments, deployment, package publication,
  destructive infrastructure changes, and authorization-sensitive merges are
  unsafe for automatic reuse.
- The pre-1.0 Python reference and TypeScript, Go, and .NET conformance
  implementations are not mature SDKs with a long-term compatibility guarantee.
- MCP interoperability is an optional shadow example and does not claim MCP
  endorsement or standardization.
- The research tested protocol/evidence behavior and bounded economics. It did
  not validate a production shared cache or realized external savings.
