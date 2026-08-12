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
3. reject U+2028 and U+2029 line-separator code points;
4. reject strings longer than 4,096 Unicode scalar values;
5. reject arrays or objects with more than 256 entries;
6. reject nesting deeper than 16 levels;
7. reject non-string object keys and normalized key collisions;
8. sort object keys after NFC normalization by their UTF-8 byte sequences;
9. preserve array order;
10. reject all JSON numbers; producers MUST supply an opaque precomputed input
   digest when an external input contains numbers; and
11. emit compact JSON encoded as UTF-8, without insignificant whitespace.

The version 1 Action Identity and Reuse Receipt schemas contain no numeric
fields. Implementations MUST validate schema field types before hashing; they
MUST NOT silently coerce strings, booleans, digests, or arrays. Oncefold's
general canonicalizer intentionally rejects numbers rather than relying on
language-specific JSON-number behavior. The optional MCP shadow adapter
therefore fails closed for numeric tool arguments unless the caller supplies
an input digest under another explicitly specified contract.

An implementation MUST reject a canonical key collision such as two keys that
become equal after NFC normalization. It MUST NOT resolve the collision by
choosing one value.

Protocol JSON ingress MUST be bounded to 1 MiB, 32 nesting levels, and 256
members per object or array. It MUST reject duplicate object keys, non-standard
JSON constants, all JSON numbers, invalid Unicode scalar sequences, and U+2028 /
U+2029 line-separator code points. These checks apply before schema parsing; a
parser MUST NOT silently accept a later duplicate key.

## 3. Action Identity

The required fields are:

- `schema_version`: exactly `oncefold.action/1`;
- `operation_identity`: stable tool/action identity;
- `operation_version`: version of the operation contract; and
- `input_digest`: lowercase SHA-256 digest of canonicalized inputs;
- `dependency_completeness`: an explicit boolean completeness assertion.

Optional fields have these defaults when omitted:

- `trust_scope`: `local`;
- `environment`: `{}`;
- `dependencies`: `[]`;
- `side_effect_class`: `UNKNOWN`;
- `authorization_scope_digest`: `null`;
- `freshness`: `{}`;
- `validator_identity`: `null`.

Unknown fields MUST be rejected. Explicit `null` is not a substitute for an
omitted map, array, or required string.

`dependency_completeness` has no omission default. A producer MUST explicitly
set it to `true` only when all relevant dependencies were observed, or to
`false` when relevant inputs were omitted or cannot be observed completely.
Consumers MUST fail closed for `false`; an omitted wire field is malformed.

Dependencies are objects with `kind`, `identity`, `digest`, and optional
boolean `required` (default `true`). Dependency `digest` values MUST be
lowercase SHA-256 digests. Duplicate dependency identities, defined as equal
`(kind, identity)`, are malformed. Implementations MUST sort dependencies by
`kind`, `identity`, and `digest` before canonical serialization, comparing each
field by its UTF-8 byte sequence. `kind` is limited to 128 Unicode scalar
values; `identity` and `digest` use the general string and digest bounds. A producer
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
- `created_at`: a strict UTC RFC 3339 timestamp using `Z`, with optional
  exactly six-digit fractional seconds;
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

`2026-08-11T12:00:00Z` is canonical for an exact second. A non-zero fraction
is serialized with six digits, for example
`2026-08-11T12:00:00.123456Z`; an all-zero six-digit fraction normalizes to the
exact-second form. Offset spellings such as `+00:00` and `+02:00` are rejected,
not treated as equivalent input. Invalid dates, leap seconds, and other
timezone spellings are rejected.

`reuse_class` is a producer claim with four values:

- `EXACT`: sufficiently closed, deterministic, inspectable work;
- `VERIFIED`: a candidate requiring a current validator;
- `ADVISORY`: context only, never authoritative by existence alone; and
- `UNSAFE`: never automatically reusable.

The class does not override consumer checks. A producer claim is evidence, not
permission.

### Trust and admission

Receipt and result digests provide integrity, not authenticity. A
`producer_identity` is only a label unless the consumer supplies an independent
trust policy. A receipt from an unauthenticated producer MUST NOT by itself
authorize reuse, regardless of digest validity.

Before an `EXACT` or validator-passed `VERIFIED` receipt can produce
`REUSABLE_EXACT`, the consumer MUST admit the receipt through an external
policy that binds at least the producer identity and `cache_scope`. A policy
MAY additionally require exact provenance entries. An empty or absent policy
admits no authoritative producer. `cache_scope` is therefore a normative
consumer-policy input, not an informational field. `ADVISORY` evidence may be
reported as context but never authorizes reuse.

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
10. authoritative reuse class with a producer/cache/provenance policy failure
    -> `UNKNOWN`;
11. reuse class `EXACT` -> `REUSABLE_EXACT`;
12. reuse class `VERIFIED`:
    - missing or non-matching validator identity -> `REQUIRES_VALIDATION`;
    - no current validator -> `REQUIRES_VALIDATION`;
    - validator pass -> `REUSABLE_EXACT`;
    - validator failure -> `STALE`; and
13. reuse class `ADVISORY` -> `ADVISORY_ONLY`.

A current validator exception or non-boolean return is `UNKNOWN`; it is never a
successful validation.

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
