# Research history

Oncefold is publishing the part of a longer validation program that survived
negative results. Historical raw work is intentionally not included in this
public repository; this record keeps the decisions and their boundaries
without publishing runtime transcripts, prompts, local paths, or unrelated
repository data.

## V1 — broad exploration

The initial validation core explored typed work identity, local storage, policy,
and synthetic mechanics. It ended in a pivot rather than evidence for a
general-purpose cache. The source milestone was `277e737`.

## V2 — `GO_REUSE_INTEROP`

The portable Action Identity, Reuse Receipt, and deterministic decision contract
survived the bounded V2 interoperability experiment (`ecfdc45`). The result was
limited to contract interoperability. It did not establish real-agent quality,
honest dependency closure, production readiness, or automatic reuse of arbitrary
agent output.

## V3 / V3.1 — runtime validation remained incomplete

The language-neutral Python/TypeScript/Go conformance path and adversarial
controls were strengthened. Authentic runtime access was initially incomplete;
the V3.1 result remained `INCONCLUSIVE` (`5e6865d`, `15cd06b`, `cedce46`).
The lesson was to preserve missingness and never convert client startup failure
into interoperability evidence.

## V3.2 — `GO_INTEROP_ONLY`

Authentic Codex/OpenCode MCP integrations produced cross-runtime receipt-boundary
interoperability with the shared conformance corpus (`301f7c5`, `792ec1a`).
This was interoperability evidence only: no calls were suppressed, no live
canary was entered, and no economic or real-agent-quality claim followed.

## V4 — `GO_FEATURE_ONLY`

Cheap inspection workloads showed a strong theoretical reuse signal, but
validation overhead and weak task-quality relevance made the result unsuitable
for a broad cache product. The frozen/result milestones were `8235106`,
`e91982a`, and `08543d5`.

## V5 — `GO_FEATURE_ONLY`

Genuinely expensive repository checks produced a small natural-repeat signal,
but the first corpus was incomplete and below the adequacy threshold. The V5
milestones were `5a6e2d2`, `6c9b402`, and `36b25f5`.

## V5.1 — `KILL`

The final authorized continuation corrected a confirmed measurement-boundary
bug, predeclared 96 independent tasks, and met the completion-quality and
primary-observation gates:

- 70 eligible primary multi-second observations;
- 5 safe natural repeats;
- 7.1429% observation-weighted reuse;
- 12.8078% duration-weighted reuse;
- zero cross-runtime safe repeats; and
- both reuse measures below the frozen 15% standalone threshold.

The V5.1 result is summarized without private raw rows in
[`V51_ECONOMICS_SUMMARY.json`](V51_ECONOMICS_SUMMARY.json).

## Conclusion

The general standalone agent-cache thesis was falsified. The portable
reuse-evidence interoperability layer survived. Oncefold therefore publishes a
narrow protocol for deterministic evidence and fail-closed evaluation, not a
general cache, compute marketplace, remote CAS, or arbitrary LLM-result
authority.
