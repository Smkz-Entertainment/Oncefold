# Contributing

Contributions should make the reuse-evidence protocol clearer, safer, smaller,
or easier to implement independently.

Before opening a pull request:

1. read [`docs/PROTOCOL.md`](docs/PROTOCOL.md), the threat model, and the
   limitations;
2. add or update a focused test for changed behavior;
3. preserve fail-closed behavior and add a negative vector for protocol changes;
4. run the Python, TypeScript, Go, and standard-library conformance commands;
5. run `ruff check .`, `ruff format --check .`, and `mypy src`; and
6. review the staged diff for secrets, prompts, private reasoning, local paths,
   generated files, and unrelated research artifacts.

Do not add provider-specific dependencies to the core package. MCP integrations
belong at the optional boundary. Do not add automatic replay for external
mutations or treat a green local test suite as production validation.

Protocol changes must explain compatibility, update schemas or vectors when
needed, and show parity in the independent consumers. Do not weaken existing
vectors merely to accommodate one implementation.
