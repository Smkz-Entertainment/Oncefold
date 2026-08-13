# Conformance

Oncefold ships one language-neutral JSON corpus at
[`../conformance/vectors.json`](../conformance/vectors.json). The corpus has 60
cases covering exact reuse, direct and transitive dependency changes, unrelated
changes, tool and validator changes, freshness, scope, revocation, result
integrity, incomplete declarations, malformed fields, Unicode NFC, advisory and
verified classes, and duplicate dependencies.

The document also carries shared timestamp, duplicate-key, number-rejection,
invalid-Unicode/line-separator, prototype-key, and exact-depth ingress cases.
The trust policy in the document binds the
base producer, cache scope, and provenance so an exact result cannot pass only
because its self-declared digest is valid.

Each case contains an identifier and an expected decision state. A consumer
starts from the base action and receipt, applies the case patch, optionally
recomputes the receipt digest, and evaluates the result. Malformed cases must
fail closed as `UNKNOWN`.

The corpus contains no local paths, provider credentials, raw prompts, model
reasoning, external services, or private data. `conformance/stdlib_check.py`
validates the base canonical digests using only Python's standard library and
does not import the package.

Run every implementation from the repository root:

```powershell
python conformance/stdlib_check.py
python -m pytest
npm ci
npm run typecheck
node --experimental-strip-types implementations/typescript/run_conformance.ts conformance/vectors.json
go -C implementations/go test ./...
go -C implementations/go run ./cmd/conformance ../../conformance/vectors.json
dotnet run --project implementations/dotnet/Oncefold.DotNet.csproj -- conformance conformance/vectors.json
```

The TypeScript, Go, and .NET consumers are intentionally independent of the
Python reference. A protocol change is not complete until the vectors and all
four implementations agree. Vectors must not be weakened to make one
implementation pass; an actual ambiguity requires a documented protocol
decision, a regression case, and a fresh parity run.
