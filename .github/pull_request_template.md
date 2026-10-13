## Summary

Describe the change and why it is needed.

## Verification

- [ ] `python -m pytest --cov=app --cov-report=term-missing`
- [ ] `ruff check app tests`
- [ ] Documentation and `CHANGELOG.md` updated
- [ ] Staged diff reviewed for secrets, scan data, and generated files

## Security impact

Describe changes to target validation, authentication, scan behavior, network access, dependencies, or stored data. Write `None` if there is no security impact.

## Deployment or migration notes

List required settings, database migrations, or operator actions. Write `None` if not applicable.
