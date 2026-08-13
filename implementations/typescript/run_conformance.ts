import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  canonicalJson,
  canonicalTimestamp,
  evaluate,
  materializeReceipt,
  parseAction,
  parseJsonObject,
  parseReceipt,
  type DecisionState,
  type JsonValue,
} from "./verifier.ts";

type Case = {
  id: string;
  action_patch?: Record<string, JsonValue>;
  receipt_patch?: Record<string, JsonValue>;
  recompute_receipt_digest?: boolean;
  revoked?: boolean;
  available_result_digest?: string;
  validator_result?: boolean;
  expected_state: DecisionState;
};
type RawCase = { id: string; json: string; accepted: boolean };
type TimestampCase = { value: string; accepted: boolean; canonical?: string };

const vectorPath = process.argv[2] ?? "conformance/vectors.json";
const document = parseJsonObject(readFileSync(vectorPath, "utf8")) as unknown as {
  canonicalization: {
    utf8_key_order: Record<string, JsonValue>;
    utf8_key_order_digest: string;
    prototype_key_object: Record<string, JsonValue>;
    prototype_key_object_digest: string;
  };
  base: { action: Record<string, JsonValue>; receipt: Record<string, JsonValue> };
  cases: Case[];
  trust_policy: { allowed_producers: string[]; allowed_cache_scopes: string[]; required_provenance: Record<string, string> };
  raw_json_cases: RawCase[];
  timestamp_cases: TimestampCase[];
};
const failures: string[] = [];

try {
  if (canonicalJson({ name: "cafe\u0301" }) !== canonicalJson({ name: "caf\u00e9" })) {
    failures.push("canonicalization: NFC mismatch");
  }
  if (
    canonicalJson({ "\ue000": "bmp", "\ud800\udc00": "astral" }) !==
    canonicalJson({ "\ud800\udc00": "astral", "\ue000": "bmp" })
  ) {
    failures.push("canonicalization: UTF-8 key order mismatch");
  }
  const keyOrderDigest = createHash("sha256").update(Buffer.from(canonicalJson(document.canonicalization.utf8_key_order), "utf8")).digest("hex");
  if (keyOrderDigest !== document.canonicalization.utf8_key_order_digest) failures.push("canonicalization: UTF-8 key order digest mismatch");
  const prototypeKeyDigest = createHash("sha256").update(Buffer.from(canonicalJson(document.canonicalization.prototype_key_object), "utf8")).digest("hex");
  if (prototypeKeyDigest !== document.canonicalization.prototype_key_object_digest) failures.push("canonicalization: prototype-key digest mismatch");
} catch {
  failures.push("canonicalization: scalar/key-order fixture rejected");
}

for (const item of document.timestamp_cases) {
  try {
    const actual = canonicalTimestamp(item.value);
    if (!item.accepted || (item.canonical !== undefined && actual !== item.canonical)) {
      failures.push(`timestamp ${item.value}`);
    }
  } catch {
    if (item.accepted) failures.push(`timestamp rejected ${item.value}`);
  }
}

for (const item of document.raw_json_cases) {
  let accepted = true;
  try {
    parseJsonObject(item.json);
  } catch {
    accepted = false;
  }
  if (accepted !== item.accepted) failures.push(`raw JSON ${item.id}`);
}

for (const item of document.cases) {
  let actual: DecisionState = "UNKNOWN";
  try {
    const actionPayload = { ...document.base.action, ...(item.action_patch ?? {}) };
    const receiptPayload = materializeReceipt(
      document.base.receipt,
      item.receipt_patch ?? {},
      item.recompute_receipt_digest ?? false,
    );
    const action = parseAction(actionPayload);
    const receipt = parseReceipt(receiptPayload);
    actual = evaluate(action, receipt, {
      revoked: item.revoked,
      availableResultDigest: item.available_result_digest,
      validatorResult: item.validator_result,
      trustPolicy: {
        allowedProducers: document.trust_policy.allowed_producers,
        allowedCacheScopes: document.trust_policy.allowed_cache_scopes,
        requiredProvenance: document.trust_policy.required_provenance,
      },
    }).state;
  } catch {
    actual = "UNKNOWN";
  }
  if (actual !== item.expected_state) failures.push(`${item.id}: expected ${item.expected_state}, got ${actual}`);
}

try {
  const verifiedPayload = materializeReceipt(
    document.base.receipt,
    { reuse_class: "VERIFIED" } as Record<string, JsonValue>,
    true,
  );
  const verifiedAction = parseAction(document.base.action);
  const verifiedReceipt = parseReceipt(verifiedPayload);
  const nonBooleanValidator = evaluate(verifiedAction, verifiedReceipt, {
    validatorResult: "pass",
    trustPolicy: {
      allowedProducers: document.trust_policy.allowed_producers,
      allowedCacheScopes: document.trust_policy.allowed_cache_scopes,
      requiredProvenance: document.trust_policy.required_provenance,
    },
  });
  if (nonBooleanValidator.state !== "UNKNOWN") failures.push("validator result: non-boolean value was accepted");
} catch {
  failures.push("validator result: runtime type-check fixture failed");
}

const output = {
  implementation: "typescript-independent",
  total: document.cases.length,
  passed: document.cases.length - failures.length,
  failures,
};
console.log(JSON.stringify(output, null, 2));
if (failures.length > 0) process.exitCode = 1;
