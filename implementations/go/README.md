# Go conformance implementation

This is an independent consumer implementation of the public Oncefold protocol.
It uses the shared schemas and vectors and is not presented as a complete Go SDK.

From the repository root:

```powershell
go -C implementations/go test ./...
go -C implementations/go run ./cmd/conformance ../../conformance/vectors.json
```

The runner prints a deterministic JSON result and exits nonzero on any vector
mismatch.
