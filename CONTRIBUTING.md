# Contributing

Thanks for contributing to FormalCloud.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional developer tooling:

```bash
pre-commit install
pre-commit run --all-files
```

## Running tests

```bash
PYTHONPATH=. python -m unittest discover -s tests -p 'test_*.py'
```

## Contribution workflow

1. Open an issue (or reference an existing one) for substantial changes.
2. Create a focused branch and keep changes scoped.
3. Add or update tests for behavior changes.
4. Update docs/examples when user-facing behavior changes.
5. Open a pull request with:
   - problem statement
   - change summary
   - testing evidence
   - migration notes (if breaking behavior)

## Commit and PR expectations

1. Keep commits atomic and messages descriptive.
2. Avoid unrelated refactors in feature PRs.
3. Preserve deterministic behavior in certificate output unless intentionally changed.
4. If certificate schema/digest behavior changes, include regression updates and rationale.

## Policy and schema changes

When changing policy or certificate semantics:

1. Add tests for both secure and insecure paths.
2. Validate replay/benchmark determinism where relevant.
3. Update docs in `README.md` and `docs/`.

## Security reports

Do not report vulnerabilities in public issues.
Use the process in `SECURITY.md`.
