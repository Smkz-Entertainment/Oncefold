import { readFileSync } from "node:fs";
import { canonicalJson, evaluate, materializeReceipt, parseAction, parseReceipt, type JsonValue, type DecisionState } from "./verifier.ts";

type Case = { id: string; action_patch?: Record<string, JsonValue>; receipt_patch?: Record<string, JsonValue>; recompute_receipt_digest?: boolean; revoked?: boolean; available_result_digest?: string; validator_result?: boolean; expected_state: DecisionState };

const vectorPath = process.argv[2] ?? "conformance/vectors.json";
const document = JSON.parse(readFileSync(vectorPath, "utf8")) as { base: { action: Record<string, JsonValue>; receipt: Record<string, JsonValue> }; cases: Case[] };
const failures: string[] = [];
if (canonicalJson({ name: "cafe\u0301" }) !== canonicalJson({ name: "café" })) failures.push("canonicalization: NFC mismatch");
if (canonicalJson({ b: 2, a: 1 }) !== canonicalJson({ a: 1, b: 2 })) failures.push("canonicalization: key order mismatch");
for (const item of document.cases) {
  let actual: DecisionState = "UNKNOWN";
  try {
    const actionPayload = { ...document.base.action, ...(item.action_patch ?? {}) };
    const receiptPayload = materializeReceipt(document.base.receipt, item.receipt_patch ?? {}, item.recompute_receipt_digest ?? false);
    const action = parseAction(actionPayload);
    const receipt = parseReceipt(receiptPayload);
    actual = evaluate(action, receipt, { revoked: item.revoked, availableResultDigest: item.available_result_digest, validatorResult: item.validator_result }).state;
  } catch {
    actual = "UNKNOWN";
  }
  if (actual !== item.expected_state) failures.push(`${item.id}: expected ${item.expected_state}, got ${actual}`);
}
const output = { implementation: "typescript-independent", total: document.cases.length, passed: document.cases.length - failures.length, failures };
console.log(JSON.stringify(output, null, 2));
if (failures.length > 0) process.exitCode = 1;
