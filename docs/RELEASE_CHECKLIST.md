# Release checklist

This checklist records the gates for a tagged Oncefold release. Repository
visibility is a separate governance state: a public repository may still be
pre-release. Evidence must be fresh for the exact candidate commit. A local
pass does not replace hosted CI, independent review, or repository protection.

## Technical gates

- [ ] Python tests, schema validation, standard-library vectors, Ruff, format
      check, and mypy pass.
- [ ] TypeScript typecheck and independent conformance pass.
- [ ] Go `gofmt`, `go test ./...`, `go vet ./...`, and conformance pass.
- [ ] Hosted CI runs every required job for the exact candidate commit; a
      billing, permissions, timeout, or skipped job is not a pass.
- [ ] Wheel and source distribution build, pass metadata checks, contain the
      intended files, and install successfully outside the source tree.
- [ ] Dependency audit passes in a clean CI environment.
- [ ] Canonicalization, bounded ingress, duplicate-key rejection, strict
      timestamps, trust admission, and fail-closed validator behavior remain
      covered by negative vectors.

## Repository gates

- [ ] `main` requires a pull request, required CI contexts, review, linear
      history, conversation resolution, and no force-push or deletion.
- [ ] Actions are pinned to reviewed immutable references; repository SHA
      enforcement is enabled when the GitHub plan/API supports it.
- [ ] Dependabot updates cover Python, npm, Go modules, and Actions.
- [ ] `SECURITY.md` and the repository security policy are visible on `main`.
- [ ] The repository description, topics, license, issue policy, and canonical
      documentation are correct.
- [ ] `CHANGELOG.md` contains the intended release entry before tagging.

## Publication gates

- [ ] An independent reviewer approves the exact candidate commit.
- [ ] The release version, tag, release notes, and published artifacts are
      created together after all gates pass.
- [ ] If the repository is public before tagging, its pre-release status is
      explicit and no tag or release is created while the candidate is on hold.
