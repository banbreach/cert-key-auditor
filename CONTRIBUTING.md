# Contributing

Thanks for helping! This tool processes untrusted input, so changes are reviewed with
security in mind.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev,test,pdf]"
pre-commit install --install-hooks && pre-commit install --hook-type pre-push
```

## Before opening a pull request

```bash
pytest                                                # offline, no token or network
ruff check . && ruff format --check . && mypy
pre-commit run --all-files --hook-stage pre-push      # includes pip-audit
```

## Guidelines

- **Tests are offline.** Build synthetic certificates, CRLs and PDFs (see `tests/helpers.py`);
  mock HTTP with `responses`. Never commit real certificates, tokens or private keys.
- **Isolate failures.** One bad certificate, block, extension, CRL or PDF object must not end
  a run: record it in the report's `errors` and continue.
- **Treat everything from a certificate as hostile.** Escape it before printing
  (`render.clean`), neutralize it in CSV (`render.csv_cell`), and bound every download/parse.
- **Never weaken network safety silently.** Changes to `crl.py` URL validation, redirects or
  size limits need tests for the bypass they could introduce.
- **Be honest about checks.** Wording must say "no X found within the tested bounds", not
  "secure".
- `# nosec` annotations must carry a specific reason (`# nosec - <why this is safe>`).
- Update `README.md` and `CHANGELOG.md` for user-visible changes.

## Releasing (maintainers)

1. Update `__version__` in `src/cert_key_auditor/__init__.py` and `CHANGELOG.md`.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. The `Release` workflow builds, attests provenance, publishes to PyPI via Trusted
   Publishing (approve the `pypi` environment) and creates the GitHub release.
