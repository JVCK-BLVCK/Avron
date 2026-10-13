# Contributing to Avron

Thanks for helping improve Avron. Contributions should preserve the project's safe-by-default behavior and must not weaken target validation, authentication, or scan limits without a clear security review.

## Before you start

- Check existing issues and pull requests for related work.
- For a vulnerability report, follow [SECURITY.md](SECURITY.md); do not open a public issue with exploitable details.
- Keep changes focused. Discuss broad changes before investing in a large patch.

## Development setup

Use Python 3.13 or later. Create a virtual environment and install the pinned development dependencies:

```sh
python -m venv .venv
python -m pip install -r requirements-test.txt
```

Tests set a local test API key and mock scan execution. They do not run Nuclei against a live target. Run:

```sh
python -m pytest --cov=app --cov-report=term-missing
ruff check app tests
```

For an integration run, use the Docker Compose setup in [docs/installation.md](docs/installation.md). Only use targets you own or are explicitly authorized to test.

## Pull requests

- Use a conventional commit subject such as `feat: add report export` or `fix: reject mixed public and private DNS answers`.
- Add or update tests for changed behavior. Keep tests deterministic and avoid live network calls.
- Update the relevant docs and `CHANGELOG.md` under `Unreleased`.
- Run the test suite and lint command before opening a pull request.
- Describe the change, its security impact, and any configuration or migration steps.
- Do not include secrets, `.env` files, scan output, credentials, or real target data. Review `git diff --cached` before committing.

By submitting a contribution, you agree that it may be distributed under the repository's MIT License.
