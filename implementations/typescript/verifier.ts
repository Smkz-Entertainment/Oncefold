/*
 * Independent Oncefold consumer implementation.
 * It is intentionally self-contained: the only inputs are the public protocol,
 * schemas, and JSON conformance vectors. It does not import Oncefold's Python code.
 */
import { createHash } from "node:crypto";

export type JsonValue = null | boolean | string | JsonValue[] | { [key: string]: JsonValue };
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
const TIMESTAMP = /^[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$/;
const SIDE_EFFECTS = new Set(["READ_ONLY", "LOCAL_WRITE", "EXTERNAL_MUTATION", "UNKNOWN"]);
const REUSE_CLASSES = new Set(["EXACT", "VERIFIED", "ADVISORY", "UNSAFE"]);
const MAX_JSON_BYTES = 1_048_576;
const MAX_JSON_DEPTH = 32;

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
  producerIdentity: string;
  reuseClass: string;
  trustScope: string;
  cacheScope: string;
  provenance: Record<string, JsonValue>;
  revocationRef: string | null;
  validatorIdentity: string | null;
  dependencySnapshot: Record<string, JsonValue>[];
};

export type Decision = { state: DecisionState; reason: string; receiptDigest?: string };

export type TrustPolicy = {
  allowedProducers: readonly string[];
  allowedCacheScopes: readonly string[];
  requiredProvenance?: Record<string, string>;
};

function fail(message: string): never {
  throw new Error(message);
}

function assertWellFormed(value: string, name: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) fail(`${name} contains an invalid Unicode scalar`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${name} contains an invalid Unicode scalar`);
    }
  }
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, name: string, optional = false): string | null {
  if (value === null && optional) return null;
  if (typeof value !== "string" || (!optional && value.length === 0)) fail(`${name} must be a string`);
  assertWellFormed(value, name);
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
    if (typeof value === "string") {
      assertWellFormed(value, "canonical string");
      if ([...value].length > 4096 || [...value].some((char) => char.codePointAt(0)! < 0x20)) {
        fail("canonical string exceeds bounds");
      }
    }
    return typeof value === "string" ? value.normalize("NFC") : value;
  }
  if (typeof value === "number") fail("numbers are not canonicalizable; supply an opaque input digest");
  if (Array.isArray(value)) {
    if (value.length > 256) fail("canonical array exceeds bound");
    return value.map((item) => normalize(item, depth + 1));
  }
  const source = object(value, "canonical object");
  if (Object.keys(source).length > 256) fail("canonical object exceeds bound");
  const entries = Object.entries(source).map(([key, item]) => {
    const normalizedKey = key.normalize("NFC");
    assertWellFormed(normalizedKey, "canonical object key");
    if ([...normalizedKey].length > 4096 || [...normalizedKey].some((char) => char.codePointAt(0)! < 0x20)) {
      fail("canonical object key exceeds bounds");
    }
    return [normalizedKey, normalize(item, depth + 1)] as const;
  });
  entries.sort(([left], [right]) => compareUtf8(left, right));
  const result: Record<string, JsonValue> = {};
  for (let index = 0; index < entries.length; index += 1) {
    if (index > 0 && entries[index - 1][0] === entries[index][0]) fail("canonical key collision");
    result[entries[index][0]] = entries[index][1];
  }
  return result;
}

export function canonicalJson(value: unknown): string {
  return encodeCanonical(normalize(value));
}

function compareUtf8(left: string, right: string): number {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
  }
  return leftBytes.length - rightBytes.length;
}

function encodeCanonical(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value)!;
  }
  if (Array.isArray(value)) return `[${value.map(encodeCanonical).join(",")}]`;
  const entries = Object.entries(value).sort(([left], [right]) => compareUtf8(left, right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${encodeCanonical(item)}`).join(",")}}`;
}

export function canonicalTimestamp(value: unknown): string {
  const createdAt = text(value, "created_at")!;
  if (!TIMESTAMP.test(createdAt)) fail("created_at must be RFC 3339 UTC with Z and optional six-digit fractions");
  const base = `${createdAt.slice(0, 19)}Z`;
  const parsed = Date.parse(base);
  if (Number.isNaN(parsed) || new Date(parsed).toISOString().slice(0, 19) !== base.slice(0, 19)) {
    fail("created_at is not a valid timestamp");
  }
  const fraction = createdAt.length > 20 ? createdAt.slice(20, 26) : "";
  return fraction !== "" && !/^0{6}$/.test(fraction) ? `${base.slice(0, 19)}.${fraction}Z` : base;
}

class JsonParser {
  private position = 0;
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  parseObject(): Record<string, JsonValue> {
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.position !== this.source.length) fail("trailing JSON input");
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail("JSON document must be an object");
    return value as Record<string, JsonValue>;
  }

  private parseValue(depth: number): JsonValue {
    if (depth > MAX_JSON_DEPTH) fail("JSON nesting exceeds the input bound");
    this.skipWhitespace();
    const character = this.source[this.position];
    if (character === "{") return this.parseObjectValue(depth + 1);
    if (character === "[") return this.parseArrayValue(depth + 1);
    if (character === '"') return this.parseString();
    if (this.source.startsWith("true", this.position)) {
      this.position += 4;
      return true;
    }
    if (this.source.startsWith("false", this.position)) {
      this.position += 5;
      return false;
    }
    if (this.source.startsWith("null", this.position)) {
      this.position += 4;
      return null;
    }
    if (character === "-" || (character >= "0" && character <= "9")) {
      fail("numbers are not accepted in Oncefold JSON ingress");
    }
    fail("invalid JSON value");
  }

  private parseObjectValue(depth: number): Record<string, JsonValue> {
    this.position += 1;
    const result: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    this.skipWhitespace();
    if (this.take("}")) return result;
    while (true) {
      this.skipWhitespace();
      if (this.source[this.position] !== '"') fail("JSON object keys must be strings");
      const key = this.parseString();
      if (Object.prototype.hasOwnProperty.call(result, key)) fail(`duplicate JSON object key: ${key}`);
      this.skipWhitespace();
      if (!this.take(":")) fail("expected colon after JSON object key");
      result[key] = this.parseValue(depth);
      if (Object.keys(result).length > 256) fail("JSON object exceeds the input bound");
      this.skipWhitespace();
      if (this.take("}")) return result;
      if (!this.take(",")) fail("expected comma in JSON object");
    }
  }

  private parseArrayValue(depth: number): JsonValue[] {
    this.position += 1;
    const result: JsonValue[] = [];
    this.skipWhitespace();
    if (this.take("]")) return result;
    while (true) {
      result.push(this.parseValue(depth));
      if (result.length > 256) fail("JSON array exceeds the input bound");
      this.skipWhitespace();
      if (this.take("]")) return result;
      if (!this.take(",")) fail("expected comma in JSON array");
    }
  }

  private parseString(): string {
    const start = this.position;
    this.position += 1;
    let escaped = false;
    while (this.position < this.source.length) {
      const character = this.source[this.position];
      if (escaped) {
        escaped = false;
        this.position += 1;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        this.position += 1;
        continue;
      }
      if (character === '"') {
        this.position += 1;
        const value = JSON.parse(this.source.slice(start, this.position)) as unknown;
        if (typeof value !== "string") fail("invalid JSON string");
        assertWellFormed(value, "JSON string");
        return value;
      }
      this.position += 1;
    }
    fail("unterminated JSON string");
  }

  private skipWhitespace(): void {
    while (this.position < this.source.length && /[\u0020\u0009\u000a\u000d]/.test(this.source[this.position])) {
      this.position += 1;
    }
  }

  private take(expected: string): boolean {
    if (this.source.startsWith(expected, this.position)) {
      this.position += expected.length;
      return true;
    }
    return false;
  }
}

export function parseJsonObject(source: string): Record<string, JsonValue> {
  if (new TextEncoder().encode(source).length > MAX_JSON_BYTES) fail(`JSON input exceeds ${MAX_JSON_BYTES} bytes`);
  return new JsonParser(source).parseObject();
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
  parsed.sort((left, right) => {
    for (const key of ["kind", "identity", "digest"] as const) {
      const difference = compareUtf8(String(left[key]), String(right[key]));
      if (difference !== 0) return difference;
    }
    return 0;
  });
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
  const trustScope = text(source.trust_scope === undefined ? "local" : source.trust_scope, "trust_scope")!;
  const environment = stringMap(source.environment, "environment");
  const parsedDependencies = dependencies(source.dependencies === undefined ? [] : source.dependencies, "dependencies");
  const sideEffectClass = text(source.side_effect_class === undefined ? "UNKNOWN" : source.side_effect_class, "side_effect_class")!;
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
  const createdAt = canonicalTimestamp(source.created_at);
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
  return { raw, digest: receiptDigest, action, resultDigest, producerIdentity: text(source.producer_identity, "producer_identity")!, reuseClass, trustScope, cacheScope, provenance, revocationRef, validatorIdentity, dependencySnapshot: snapshot };
}

function admits(receipt: Receipt, policy: TrustPolicy | undefined): boolean {
  if (policy === undefined || !policy.allowedProducers.includes(receipt.producerIdentity)) return false;
  if (!policy.allowedCacheScopes.includes(receipt.cacheScope)) return false;
  return Object.entries(policy.requiredProvenance ?? {}).every(([key, value]) => receipt.provenance[key] === value);
}

export function evaluate(action: Action, receipt: Receipt, options: { revoked?: boolean; availableResultDigest?: string; validatorResult?: boolean; trustPolicy?: TrustPolicy } = {}): Decision {
  const receiptDigest = receipt.digest;
  if (options.revoked || receipt.revocationRef !== null) return { state: "REVOKED", reason: "receipt revoked", receiptDigest };
  if (action.trustScope !== receipt.trustScope || action.trustScope !== receipt.action.trustScope || action.authorizationScopeDigest !== receipt.action.authorizationScopeDigest) return { state: "SCOPE_MISMATCH", reason: "scope mismatch", receiptDigest };
  if (action.sideEffectClass !== "READ_ONLY" || receipt.action.sideEffectClass !== "READ_ONLY") return { state: "UNSAFE", reason: "non-read-only action is not reusable", receiptDigest };
  if (receipt.reuseClass === "UNSAFE") return { state: "UNSAFE", reason: "receipt is marked unsafe", receiptDigest };
  if (!action.dependencyCompleteness || !receipt.action.dependencyCompleteness) return { state: "UNKNOWN", reason: "dependency declaration is incomplete", receiptDigest };
  if (action.digest !== receipt.action.digest) return { state: "STALE", reason: "action identity mismatch", receiptDigest };
  if (canonicalJson(action.dependencies) !== canonicalJson(receipt.dependencySnapshot)) return { state: "STALE", reason: "dependency snapshot mismatch", receiptDigest };
  if (options.availableResultDigest !== undefined && (!DIGEST.test(options.availableResultDigest) || options.availableResultDigest !== receipt.resultDigest)) return { state: "UNKNOWN", reason: "result digest mismatch", receiptDigest };
  if (receipt.reuseClass === "EXACT") {
    if (!admits(receipt, options.trustPolicy)) return { state: "UNKNOWN", reason: "receipt producer, cache scope, or provenance is not trusted", receiptDigest };
    return { state: "REUSABLE_EXACT", reason: "identity and dependencies match", receiptDigest };
  }
  if (receipt.reuseClass === "VERIFIED") {
    if (!admits(receipt, options.trustPolicy)) return { state: "UNKNOWN", reason: "receipt producer, cache scope, or provenance is not trusted", receiptDigest };
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
