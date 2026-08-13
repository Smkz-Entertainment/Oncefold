# .NET conformance implementation

This is an independent .NET consumer of the public Oncefold protocol. It is
implemented without importing the Python reference package or the TypeScript
or Go consumers, and it is not presented as a complete .NET SDK.

The consumer uses only the public protocol documents and the shared
language-neutral corpus. It includes strict UTF-8 JSON ingress, NFC-aware
canonical JSON, action and receipt integrity checks, trust admission, and the
deterministic decision rules.

From the repository root, with the .NET 8 SDK installed:

```powershell
dotnet build implementations/dotnet/Oncefold.DotNet.csproj
dotnet run --project implementations/dotnet/Oncefold.DotNet.csproj -- conformance conformance/vectors.json
```

The runner prints a deterministic JSON result and exits nonzero on any vector
mismatch. Its conformance result is repository-controlled cross-runtime
evidence; it is not evidence of adoption by an external implementation or
organization.
