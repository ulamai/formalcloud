# Release And Publish Channels

FormalCloud includes release automation in `.github/workflows/release-publish.yml` for:

1. Python package build artifacts (`sdist` and `wheel`).
2. Optional publish to PyPI.
3. Container image publish to GHCR.

## Trigger

Workflow triggers on tags matching `v*` and on manual dispatch.

## Prerequisites

1. PyPI token configured as `PYPI_API_TOKEN` (if publishing Python package).
2. Repository packages permission enabled for GHCR publishing.

## Expected outputs

1. `dist/*` artifacts uploaded to workflow run.
2. PyPI package published when token is present.
3. GHCR image pushed as:
   - `ghcr.io/<org>/formalcloud:<tag>`
   - `ghcr.io/<org>/formalcloud:latest`

## Local verification

```bash
python -m pip install --upgrade pip build
python -m build
docker build -t formalcloud:local .
```
