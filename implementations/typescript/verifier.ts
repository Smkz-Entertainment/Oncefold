/*
 * Independent Oncefold consumer implementation.
 * It is intentionally self-contained: the only inputs are the public protocol,
 * schemas, and JSON conformance vectors. It does not import Oncefold's Python code.
 */
import { createHash } from "node:crypto";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type DecisionState =
  | "REUSABLE_EXACT"
  | "REQUIRES_VALIDATION"
  | "ADVISORY_ONLY"
  | "REVOKED"
  | "STALE"
  | "SCOPE_MISMATCH"
  | "UNSAFE"
  | "UNKNOWN";

const ACTION_SCHEMA = "oncefold.action/1";
const RECEIPT_SCHEMA = "oncefold.receipt/1";
const DIGEST = /^[0-9a-f]{64}$/;
const SIDE_EFFECTS = new Set(["READ_ONLY", "LOCAL_WRITE", "EXTERNAL_MUTATION", "UNKNOWN"]);
const REUSE_CLASSES = new Set(["EXACT", "VERIFIED", "ADVISORY", "UNSAFE"]);

export type Action = {
  raw: Record<string, JsonValue>;
  digest: string;
  operationIdentity: string;
  operationVersion: string;
  inputDigest: string;
  trustScope: string;
  authorizationScopeDigest: string | null;
  sideEffectClass: string;
  dependencies: Record<string, JsonValue>[];
  dependencyCompleteness: boolean;
  validatorIdentity: string | null;
};

export type Receipt = {
  raw: Record<string, JsonValue>;
  digest: string;
  action: Action;
  resultDigest: string;
  reuseClass: string;
  trustScope: string;
  revocationRef: string | null;
  validatorIdentity: string | null;
  dependencySnapshot: Record<string, JsonValue>[];
};

export type Decision = { state: DecisionState; reason: string; receiptDigest?: string };

function fail(message: string): never {
  throw new Error(message);
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, name: string, optional = false): string | null {
  if (value === null && optional) return null;
  if (typeof value !== "string" || (!optional && value.length === 0)) fail(`${name} must be a string`);
  if ([...value].length > 4096 || [...value].some((char) => char.codePointAt(0)! < 0x20)) {
    fail(`${name} exceeds canonical bounds`);
  }
  return value;
}

function digest(value: unknown, name: string): string {
  const candidate = text(value, name);
  if (candidate === null || !DIGEST.test(candidate)) fail(`${name} must be a lowercase SHA-256 digest`);
  return candidate;
}

function allowed(value: Record<string, unknown>, required: string[], optional: string[], name: string): void {
  const known = new Set([...required, ...optional]);
  for (const key of required) if (!(key in value)) fail(`${name} is missing ${key}`);
  for (const key of Object.keys(value)) if (!known.has(key)) fail(`${name} contains unknown field ${key}`);
}

function normalize(value: unknown, depth = 0): JsonValue {
  if (depth > 16) fail("canonical value is too deeply nested");
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string") text(value, "canonical string");
    return typeof value === "string" ? value.normalize("NFC") : value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("non-finite number");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 256) fail("canonical array exceeds bound");
    return value.map((item) => normalize(item, depth + 1));
  }
  const source = object(value, "canonical object");
  if (Object.keys(source).length > 256) fail("canonical object exceeds bound");
  const entries = Object.entries(source).map(([key, item]) => {
    const normalizedKey = key.normalize("NFC");
    text(normalizedKey, "canonical object key");
    return [normalizedKey, normalize(item, depth + 1)] as const;
  });
  entries.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const result: Record<string, JsonValue> = {};
  for (let index = 0; index < entries.length; index += 1) {
    if (index > 0 && entries[index - 1][0] === entries[index][0]) fail("canonical key collision");
    result[entries[index][0]] = entries[index][1];
  }
  return result;
}

export function canonicalJson(value: unknown): string {
  const encoded = JSON.stringify(normalize(value));
  if (encoded === undefined) fail("value is not JSON-compatible");
  return encoded;
}

export function sha256(value: string): string {
  return createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
}

function stringMap(value: unknown, name: string): Record<string, JsonValue> {
  const source = object(value === undefined ? {} : value, name);
  if (Object.keys(source).length > 256) fail(`${name} exceeds the collection bound`);
  const result: Record<string, JsonValue> = {};
  for (const [key, item] of Object.entries(source)) {
    text(key, `${name} key`);
    result[key] = text(item, `${name}.${key}`)!;
  }
  return result;
}

function dependency(value: unknown): Record<string, JsonValue> {
  const source = object(value, "dependency");
  allowed(source, ["kind", "identity", "digest"], ["required"], "dependency");
  const parsed: Record<string, JsonValue> = {
    kind: text(source.kind, "dependency.kind")!,
    identity: text(source.identity, "dependency.identity")!,
    digest: digest(source.digest, "dependency.digest"),
    required: source.required === undefined ? true : source.required as boolean,
  };
  if (typeof parsed.required !== "boolean") fail("dependency.required must be boolean");
  return parsed;
}

function dependencies(value: unknown, name: string): Record<string, JsonValue>[] {
  if (!Array.isArray(value) || value.length > 256) fail(`${name} must be a bounded array`);
  const parsed = value.map(dependency);
  const ids = new Set<string>();
  for (const item of parsed) {
    const id = `${item.kind as string}\u0000${item.identity as string}`;
    if (ids.has(id)) fail(`${name} contains duplicate dependency identity`);
    ids.add(id);
  }
  parsed.sort((left, right) => `${left.kind}:${left.identity}:${left.digest}`.localeCompare(`${right.kind}:${right.identity}:${right.digest}`));
  return parsed;
}

export function parseAction(value: unknown): Action {
  const source = object(value, "action identity");
  allowed(source, ["schema_version", "operation_identity", "operation_version", "input_digest"], ["trust_scope", "environment", "dependencies", "side_effect_class", "authorization_scope_digest", "freshness", "dependency_completeness", "validator_identity"], "action identity");
  const schema = text(source.schema_version, "schema_version");
  if (schema !== ACTION_SCHEMA) fail(`unsupported action schema ${schema}`);
  const operationIdentity = text(source.operation_identity, "operation_identity")!;
  const operationVersion = text(source.operation_version, "operation_version")!;
  const inputDigest = digest(source.input_digest, "input_digest");
  const trustScope = text(source.trust_scope ?? "local", "trust_scope")!;
  const environment = stringMap(source.environment, "environment");
  const parsedDependencies = dependencies(source.dependencies === undefined ? [] : source.dependencies, "dependencies");
  const sideEffectClass = text(source.side_effect_class ?? "UNKNOWN", "side_effect_class")!;
  if (!SIDE_EFFECTS.has(sideEffectClass)) fail("unknown side effect class");
  const authorizationScopeDigest = source.authorization_scope_digest === undefined ? null : source.authorization_scope_digest === null ? null : digest(source.authorization_scope_digest, "authorization_scope_digest");
  const freshness = stringMap(source.freshness, "freshness");
  const dependencyCompleteness = source.dependency_completeness === undefined ? true : source.dependency_completeness as boolean;
  if (typeof dependencyCompleteness !== "boolean") fail("dependency_completeness must be boolean");
  const validatorIdentity = source.validator_identity === undefined ? null : text(source.validator_identity, "validator_identity", true);
  const raw: Record<string, JsonValue> = {
    schema_version: ACTION_SCHEMA,
    operation_identity: operationIdentity,
    operation_version: operationVersion,
    input_digest: inputDigest,
    trust_scope: trustScope,
    environment,
    dependencies: parsedDependencies,
    side_effect_class: sideEffectClass,
    authorization_scope_digest: authorizationScopeDigest,
    freshness,
    dependency_completeness: dependencyCompleteness,
    validator_identity: validatorIdentity,
  };
  return { raw, digest: sha256(canonicalJson(raw)), operationIdentity, operationVersion, inputDigest, trustScope, authorizationScopeDigest, sideEffectClass, dependencies: parsedDependencies, dependencyCompleteness, validatorIdentity };
}

export function parseReceipt(value: unknown, allowMissingDigest = false): Receipt {
  const source = object(value, "reuse receipt");
  const required = ["schema_version", "action", "action_digest", "result_digest", "media_type", "producer_identity", "reuse_class", "created_at", "dependency_snapshot", "trust_scope", "cache_scope"];
  if (!allowMissingDigest) required.push("receipt_digest");
  allowed(source, required, ["result_reference", "provenance", "revocation_ref", "validator_identity", "execution_metadata", "economics", "receipt_digest"], "reuse receipt");
  const schema = text(source.schema_version, "schema_version");
  if (schema !== RECEIPT_SCHEMA) fail(`unsupported receipt schema ${schema}`);
  const action = parseAction(source.action);
  if (digest(source.action_digest, "action_digest") !== action.digest) fail("receipt action digest mismatch");
  const resultDigest = digest(source.result_digest, "result_digest");
  const reuseClass = text(source.reuse_class, "reuse_class")!;
  if (!REUSE_CLASSES.has(reuseClass)) fail("unknown reuse class");
  const createdAt = text(source.created_at, "created_at")!;
  if (!/[zZ]|[+-][0-9]{2}:[0-9]{2}$/.test(createdAt) || Number.isNaN(Date.parse(createdAt))) fail("created_at must be a timezone-aware timestamp");
  const snapshot = dependencies(source.dependency_snapshot, "dependency_snapshot");
  const trustScope = text(source.trust_scope, "trust_scope")!;
  const cacheScope = text(source.cache_scope, "cache_scope")!;
  const resultReference = source.result_reference === undefined ? null : text(source.result_reference, "result_reference", true);
  const provenance = stringMap(source.provenance, "provenance");
  const revocationRef = source.revocation_ref === undefined ? null : text(source.revocation_ref, "revocation_ref", true);
  const validatorIdentity = source.validator_identity === undefined ? null : text(source.validator_identity, "validator_identity", true);
  const executionMetadata = stringMap(source.execution_metadata, "execution_metadata");
  const economics = stringMap(source.economics, "economics");
  const raw: Record<string, JsonValue> = {
    schema_version: RECEIPT_SCHEMA,
    action: action.raw,
    action_digest: action.digest,
    result_digest: resultDigest,
    result_reference: resultReference,
    media_type: text(source.media_type, "media_type")!,
    producer_identity: text(source.producer_identity, "producer_identity")!,
    reuse_class: reuseClass,
    created_at: createdAt,
    dependency_snapshot: snapshot,
    provenance,
    trust_scope: trustScope,
    cache_scope: cacheScope,
    revocation_ref: revocationRef,
    validator_identity: validatorIdentity,
    execution_metadata: executionMetadata,
    economics,
  };
  const receiptDigest = sha256(canonicalJson(raw));
  if (!allowMissingDigest && digest(source.receipt_digest, "receipt_digest") !== receiptDigest) fail("receipt digest mismatch");
  return { raw, digest: receiptDigest, action, resultDigest, reuseClass, trustScope, revocationRef, validatorIdentity, dependencySnapshot: snapshot };
}

export function evaluate(action: Action, receipt: Receipt, options: { revoked?: boolean; availableResultDigest?: string; validatorResult?: boolean } = {}): Decision {
  const receiptDigest = receipt.digest;
  if (options.revoked || receipt.revocationRef !== null) return { state: "REVOKED", reason: "receipt revoked", receiptDigest };
  if (action.trustScope !== receipt.trustScope || action.trustScope !== receipt.action.trustScope || action.authorizationScopeDigest !== receipt.action.authorizationScopeDigest) return { state: "SCOPE_MISMATCH", reason: "scope mismatch", receiptDigest };
  if (action.sideEffectClass !== "READ_ONLY" || receipt.action.sideEffectClass !== "READ_ONLY") return { state: "UNSAFE", reason: "non-read-only action is not reusable", receiptDigest };
  if (receipt.reuseClass === "UNSAFE") return { state: "UNSAFE", reason: "receipt is marked unsafe", receiptDigest };
  if (!action.dependencyCompleteness || !receipt.action.dependencyCompleteness) return { state: "UNKNOWN", reason: "dependency declaration is incomplete", receiptDigest };
  if (action.digest !== receipt.action.digest) return { state: "STALE", reason: "action identity mismatch", receiptDigest };
  if (canonicalJson(action.dependencies) !== canonicalJson(receipt.dependencySnapshot)) return { state: "STALE", reason: "dependency snapshot mismatch", receiptDigest };
  if (options.availableResultDigest !== undefined && (!DIGEST.test(options.availableResultDigest) || options.availableResultDigest !== receipt.resultDigest)) return { state: "UNKNOWN", reason: "result digest mismatch", receiptDigest };
  if (receipt.reuseClass === "EXACT") return { state: "REUSABLE_EXACT", reason: "identity and dependencies match", receiptDigest };
  if (receipt.reuseClass === "VERIFIED") {
    if (receipt.validatorIdentity === null || receipt.validatorIdentity !== action.validatorIdentity) return { state: "REQUIRES_VALIDATION", reason: "matching validator identity required", receiptDigest };
    if (options.validatorResult === undefined) return { state: "REQUIRES_VALIDATION", reason: "current validator required", receiptDigest };
    return options.validatorResult ? { state: "REUSABLE_EXACT", reason: "current validator passed", receiptDigest } : { state: "STALE", reason: "current validator rejected receipt", receiptDigest };
  }
  if (receipt.reuseClass === "ADVISORY") return { state: "ADVISORY_ONLY", reason: "context only; not authoritative", receiptDigest };
  return { state: "UNSAFE", reason: "unknown reuse class", receiptDigest };
}

export function materializeReceipt(base: Record<string, JsonValue>, patch: Record<string, JsonValue>, recompute: boolean): Record<string, JsonValue> {
  const candidate: Record<string, JsonValue> = { ...base, ...patch };
  if (!recompute) return candidate;
  delete candidate.receipt_digest;
  const parsed = parseReceipt(candidate, true);
  return { ...candidate, receipt_digest: parsed.digest };
}
