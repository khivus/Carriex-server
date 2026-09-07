# Contributing

Create a branch and install development dependencies using the README.
Keep changes focused and add integration tests for changes in API behavior.

```sh
python -m ruff check .
python -m pytest -q
python -m build
```

For container changes, also run `docker compose up --build -d`, check `/health`
and logs, then run `docker compose down`.

Document user-visible changes under `Unreleased` in `CHANGELOG.md`. Only bump
`src/_version.py` when preparing a release, following the README procedure.
Include a summary and validation results in pull requests.
