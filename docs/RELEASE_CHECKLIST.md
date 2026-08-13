# Release checklist

This is a reusable checklist for a tagged Oncefold release. Evidence must be
fresh for the exact candidate commit. A local pass does not replace hosted CI,
the active repository governance policy, or protected refs.

## Technical gates

- [ ] Python tests, schema validation, standard-library vectors, Ruff, format
      check, and mypy pass.
- [ ] TypeScript typecheck and independent conformance pass.
- [ ] Go `gofmt`, `go test ./...`, `go vet ./...`, and conformance pass.
- [ ] .NET build and independent conformance pass.
- [ ] Hosted CI runs every required job for the exact candidate commit; a
      billing, permissions, timeout, or skipped job is not a pass.
- [ ] Wheel and source distribution build, pass metadata checks, contain the
      intended files, and install successfully outside the source tree.
- [ ] Dependency audit passes in a clean CI environment.
- [ ] Canonicalization, bounded ingress, duplicate-key rejection, strict
      timestamps, trust admission, and fail-closed validator behavior remain
      covered by negative vectors.
- [ ] CodeQL analyzes Actions, Python, TypeScript/JavaScript, Go, and C# on the
      candidate or its exact release commit.
- [ ] A fresh all-history Gitleaks scan covers the exact release candidate.

## Repository gates

- [ ] `main` requires a pull request, the configured CI contexts, linear
      history, conversation resolution, and no force-push or deletion. Required
      approvals and bypass rules match the active repository policy.
- [ ] Actions are pinned to reviewed immutable references; repository SHA
      enforcement is enabled when the GitHub plan/API supports it.
- [ ] Dependabot updates cover Python, npm, Go modules, and Actions.
- [ ] Future releases are protected by release immutability and a `v*` tag
      ruleset; published tags are never moved or deleted.
- [ ] `SECURITY.md` and the repository security policy are visible on `main`.
- [ ] The repository description, topics, license, issue policy, and canonical
      documentation are correct.
- [ ] `CHANGELOG.md` contains the intended release entry before tagging.

## Review and publication gates

- [ ] The exact candidate receives a documented release review. Any
      correctness, security, interoperability, reproducibility, or
      documentation blockers are resolved before publication. Formal approval
      requirements follow the active branch-protection policy; this checklist
      does not invent an approval count.
- [ ] The release version, tag, release notes, and published artifacts are
      created together after all gates pass.
- [ ] Use a signed annotated tag where practical, and verify the tag points to
      the intended verified commit.
- [ ] Do not mutate an existing release or tag. The release is published only
      after the candidate is final, and future releases use the repository's
      immutable-release setting.
- [ ] After publication, verify the public release, tag, exact commit, tag CI,
      main CodeQL coverage, and anonymous source/archive access.
