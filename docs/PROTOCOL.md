# Oncefold protocol

This document is the normative implementation guide for schema versions
`oncefold.action/1` and `oncefold.receipt/1`. It is deliberately independent of
Python, MCP, storage, and agent providers. It is an experimental open protocol,
not an industry standard.

## 1. Data model

An **Action Identity** describes the work whose previous result may be
considered. A **Reuse Receipt** records bounded evidence about a completed
result. A consumer evaluates a receipt against current Action Identity facts and
returns a **Reuse Decision**.

Receipts MUST NOT require raw prompts, private chain-of-thought, credentials,
secrets, or provider-private session data. A result digest proves byte identity
of the represented result; it does not prove semantic correctness.

The JSON Schemas in [`../schemas/`](../schemas/) are normative for field types,
required fields, enum values, and unknown-field rejection. The rules below add
canonicalization and decision semantics that JSON Schema alone cannot express.

## 2. Canonical JSON and digests

All protocol digests are lowercase SHA-256 over canonical UTF-8 JSON.

Canonicalization MUST:

1. normalize every string and object key to Unicode NFC;
2. reject control characters below U+0020;
3. reject strings longer than 4,096 Unicode scalar values;
4. reject arrays or objects with more than 256 entries;
5. reject nesting deeper than 16 levels;
6. reject non-string object keys and normalized key collisions;
7. sort object keys after NFC normalization;
8. preserve array order;
9. reject non-finite numbers; and
10. emit compact JSON encoded as UTF-8, without insignificant whitespace.

The version 1 Action Identity and Reuse Receipt schemas contain no numeric
fields. Implementations MUST validate schema field types before hashing; they
MUST NOT silently coerce strings, booleans, digests, or arrays. If an
implementation exposes canonicalization for values outside the schemas, it
MUST document its exact JSON-number behavior and keep it compatible with the
language-neutral vectors.

An implementation MUST reject a canonical key collision such as two keys that
become equal after NFC normalization. It MUST NOT resolve the collision by
choosing one value.

## 3. Action Identity

The required fields are:

- `schema_version`: exactly `oncefold.action/1`;
- `operation_identity`: stable tool/action identity;
- `operation_version`: version of the operation contract; and
- `input_digest`: lowercase SHA-256 digest of canonicalized inputs.

Optional fields have these defaults when omitted:

- `trust_scope`: `local`;
- `environment`: `{}`;
- `dependencies`: `[]`;
- `side_effect_class`: `UNKNOWN`;
- `authorization_scope_digest`: `null`;
- `freshness`: `{}`;
- `dependency_completeness`: `true`; and
- `validator_identity`: `null`.

Unknown fields MUST be rejected. Explicit `null` is not a substitute for an
omitted map, array, or required string.

Dependencies are objects with `kind`, `identity`, `digest`, and optional
boolean `required` (default `true`). Dependency `digest` values MUST be
lowercase SHA-256 digests. Duplicate dependency identities, defined as equal
`(kind, identity)`, are malformed. Implementations MUST sort dependencies by
`kind`, `identity`, and `digest` before canonical serialization. A producer
MUST set `dependency_completeness` to `false` when relevant inputs are omitted
or cannot be observed completely; a consumer MUST fail closed for incomplete
declarations.

`side_effect_class` is one of `READ_ONLY`, `LOCAL_WRITE`,
`EXTERNAL_MUTATION`, or `UNKNOWN`. Only `READ_ONLY` can reach an automatic exact
reuse decision. Oncefold does not infer side-effect safety from a tool name.

The Action Identity digest is the SHA-256 digest of the canonical Action
Identity object with all defaults materialized and with no extra digest field.

## 4. Reuse Receipt

The required fields are:

- `schema_version`: exactly `oncefold.receipt/1`;
- `action`: a complete Action Identity;
- `action_digest`: the digest of `action`;
- `result_digest`: lowercase SHA-256 digest of the represented result;
- `media_type`;
- `producer_identity`;
- `reuse_class`;
- `created_at`: a timezone-aware timestamp;
- `dependency_snapshot`: the producer's dependency snapshot;
- `trust_scope`;
- `cache_scope`; and
- `receipt_digest`.

Optional string fields default to `null`: `result_reference`, `revocation_ref`,
and `validator_identity`. Optional string maps default to `{}`:
`provenance`, `execution_metadata`, and `economics`. Unknown fields MUST be
rejected.

The receipt's `action_digest` MUST equal the digest of its embedded action. The
dependency snapshot MUST contain no duplicate dependency identity and is sorted
using the same rule as Action Identity dependencies. A producer SHOULD use the
same dependency descriptors in the action and snapshot; the verifier compares
them exactly before granting reuse.

The receipt digest is the SHA-256 digest of the canonical receipt object with
`receipt_digest` omitted and all defaults materialized. The serialized receipt
then includes that digest. A parser MUST reject a missing or mismatched digest.

`reuse_class` is a producer claim with four values:

- `EXACT`: sufficiently closed, deterministic, inspectable work;
- `VERIFIED`: a candidate requiring a current validator;
- `ADVISORY`: context only, never authoritative by existence alone; and
- `UNSAFE`: never automatically reusable.

The class does not override consumer checks. A producer claim is evidence, not
permission.

## 5. Scope, freshness, and revocation

Trust scope and authorization scope are exact opaque values. No parent/child,
prefix, wildcard, or implied inheritance relationship exists. A changed scope
is `SCOPE_MISMATCH`, not a stale or reusable result.

Freshness and environment facts participate in the Action Identity digest. A
consumer that changes them is evaluating a different action and cannot silently
reuse the old receipt.

An explicitly revoked receipt MUST return `REVOKED` before any reuse class or
dependency result is considered. A non-null `revocation_ref` is itself a
revocation signal. A store MUST preserve revocation when a receipt is written
again and SHOULD support revoking a digest before its receipt is available.

## 6. Decision algorithm

Given current `action`, a receipt, a receipt store, and optional current result
digest or validator, the consumer MUST apply this precedence:

1. malformed, unknown-version, unknown-field, or integrity-failing receipt ->
   `UNKNOWN`;
2. store revocation or non-null `revocation_ref` -> `REVOKED`;
3. trust scope or authorization scope mismatch -> `SCOPE_MISMATCH`;
4. current or receipt side-effect class other than `READ_ONLY` -> `UNSAFE`;
5. receipt reuse class `UNSAFE` -> `UNSAFE`;
6. incomplete action dependency declaration -> `UNKNOWN`;
7. action digest mismatch -> `STALE`;
8. dependency snapshot mismatch -> `STALE`;
9. malformed or unequal available result digest -> `UNKNOWN`;
10. reuse class `EXACT` -> `REUSABLE_EXACT`;
11. reuse class `VERIFIED`:
    - missing or non-matching validator identity -> `REQUIRES_VALIDATION`;
    - no current validator -> `REQUIRES_VALIDATION`;
    - validator pass -> `REUSABLE_EXACT`;
    - validator failure -> `STALE`; and
12. reuse class `ADVISORY` -> `ADVISORY_ONLY`.

The only decision states are:

`REUSABLE_EXACT`, `REQUIRES_VALIDATION`, `ADVISORY_ONLY`, `REVOKED`, `STALE`,
`SCOPE_MISMATCH`, `UNSAFE`, and `UNKNOWN`.

Implementations MUST fail closed for every state not listed above and MUST NOT
let an LLM choose or elevate a trust decision.

## 7. Storage and interoperability

The verifier consumes a small store interface: put, get, is-revoked, and revoke.
The protocol does not require SQLite, a filesystem, a CAS, a broker, a network,
or a particular serialization transport. A receipt MAY be transported through
MCP, a file, a database, or another provider-neutral channel as long as its
bytes and semantics remain unchanged.

Compatibility is pre-1.0. A future incompatible schema MUST use a new schema
version. Implementations MUST reject unsupported schema versions rather than
guessing. Additive optional fields require a new compatibility review because
version 1 consumers reject unknown fields by design.
