# TypeScript conformance implementation

This is an independent consumer implementation of the public Oncefold protocol.
It imports no Python code and is not presented as a full TypeScript SDK.

From the repository root, with Node.js 22 or newer:

```powershell
node --experimental-strip-types implementations/typescript/run_conformance.ts conformance/vectors.json
```

The runner prints a deterministic JSON result and exits nonzero on any vector
mismatch.
