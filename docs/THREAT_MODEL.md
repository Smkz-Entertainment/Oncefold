# Threat model

Oncefold treats producer claims and tool output as untrusted evidence.

## Assets

- correctness and freshness of a reused result;
- separation of trust and authorization scopes;
- integrity of receipt bytes and referenced results;
- privacy of prompts, credentials, repository contents, and outputs; and
- deterministic behavior under malformed or oversized input.

## Relevant threats

- a mistaken or malicious producer claims `EXACT` for unsafe work;
- a receipt or result is tampered with after publication;
- dependencies, environment, validator, or authorization state become stale;
- a receipt is replayed across tenants or scopes;
- incomplete dependency observation hides a relevant change;
- revocation is lost across storage writes;
- canonicalization differences create digest collisions or disagreement;
- malformed JSON attempts resource exhaustion or parser confusion; and
- an LLM conclusion is treated as authoritative proof.

## Controls

- bounded canonical JSON with NFC normalization and key-collision rejection;
- bounded duplicate-key-rejecting JSON ingress with invalid-Unicode rejection;
- strict UTC timestamp syntax and language-neutral UTF-8 key ordering;
- lowercase SHA-256 action, result, and receipt digests;
- strict schema versions and unknown-field rejection;
- exact dependency identity and snapshot comparison;
- explicit side-effect, trust-scope, authorization-scope, validator, and
  revocation checks;
- consumer-supplied producer/cache-scope/provenance admission policy before
  authoritative reuse;
- deterministic decision precedence that fails closed;
- no raw prompts, private reasoning, credentials, or secrets in protocol fields;
- storage-independent verification; and
- adversarial and malformed-vector tests shared across languages.

## Accepted gaps

The pre-1.0 candidate does not authenticate remote publishers, sign receipts,
prove complete dependency closure, isolate hostile tenants on a shared host,
verify semantic correctness of arbitrary outputs, or provide durable
distributed result transport after process failure. A trust policy binds a
consumer's local admission decision; it is not a cryptographic publisher
signature or a public trust network. The project is not suitable by itself for payments,
email, deployment, package publication, destructive infrastructure changes, or
authorization-sensitive merges.

No LLM belongs in the trust decision.
