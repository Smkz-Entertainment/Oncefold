# Security policy

Oncefold is an experimental pre-1.0 local protocol implementation, not a public
multi-tenant service. Do not use it as the sole safety control for payments,
email, deployment, package publication, destructive infrastructure changes, or
authorization-sensitive merges.

## Supported versions

Only the current `main` branch is supported before the first tagged release.
There is no supported 0.1.0 release yet; the repository remains a private
pre-release candidate.

## Reporting a vulnerability

Please do not publish secrets or an exploitable proof in an issue. Use the
repository's private GitHub security advisory channel when it is enabled. If it
is not enabled, contact the repository maintainer privately through the GitHub
organization account and do not include sensitive details in a public issue.
Include the affected version or commit, a minimal reproduction, impact, and
whether data could be exposed.

## Security boundaries

- A result digest is not semantic proof and does not grant reuse authority.
- Unknown, malformed, incomplete, stale, revoked, scope-mismatched, and unsafe
  evidence fails closed.
- External mutations are not eligible for automatic exact reuse.
- Trust and authorization scopes are exact opaque values; no wildcard or
  hierarchy is inferred.
- Raw prompts, private reasoning, credentials, secrets, and arbitrary repository
  contents are not protocol requirements.
- Validators are named deterministic contracts; an LLM judgment is not trust
  evidence.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for the detailed boundary.
