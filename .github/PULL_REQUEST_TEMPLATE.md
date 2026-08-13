## Summary

## Validation

- [ ] Focused tests or conformance vectors updated
- [ ] `python -m pytest`
- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy src`
- [ ] Standard-library corpus check
- [ ] TypeScript conformance
- [ ] Go conformance
- [ ] .NET conformance
- [ ] Package artifact build/install check, when packaging changes
- [ ] Documentation/link audit, when documentation changes

## Safety and scope

- [ ] No prompts, private reasoning, credentials, secrets, or local paths
- [ ] No provider-specific dependency added to the core package
- [ ] No external-mutation replay or suppression path added
- [ ] Protocol, threat model, and limitations updated if behavior changed
