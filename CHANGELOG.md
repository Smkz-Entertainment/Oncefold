# Changelog

## [Unreleased] — pre-public hardening candidate

- Candidate baseline for the Oncefold Action Identity, Reuse Receipt, and
  deterministic Reuse Decision protocol.
- Added Python reference verification, JSON schemas, and a language-neutral
  53-case conformance corpus with raw-ingress fixtures.
- Added independent TypeScript and Go conformance consumers.
- Added an optional shadow-only MCP reference adapter that never suppresses the
  underlying call.
- Hardened consumer trust examples and CLI gates against receipt-derived policy
  and embedded-action reuse.
- Made dependency completeness explicit, froze Python protocol mappings, checked
  in-memory receipt keys, and aligned Unicode and dependency bounds across
  implementations.
- Documented the research conclusion that the broad standalone agent-cache
  thesis did not survive authentic V5.1 economics testing.
