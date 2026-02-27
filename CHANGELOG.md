# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

1. OSS governance/legal docs: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
2. Release/publish assets: `Dockerfile`, `.dockerignore`, and release workflow for PyPI/GHCR.
3. Production deployment assets: Helm chart for admission webhook with TLS sidecar and cert-manager pattern.
4. Starter policy packs: SOC2, CIS AWS, and NIST 800-53 templates.
5. CI templates for GitHub Actions, GitLab CI, and Jenkins with artifact retention examples.
6. New docs for release channels, policy packs, CI templates, and production admission operations.

## v0.1.5 - 2026-02-27

### Added

1. Rollout profiles with `audit`/`enforce` staging in policy metadata.
2. Profile-aware verifier behavior and rollout summary in certificates.
3. `formal-cloud policy test` command for fixture/golden-based policy lifecycle tests.
4. Evidence-pack control-oriented view for control owners.
5. Control-mapped policy metadata (`controls`, `guideline_url`) and control coverage summaries.

### Changed

1. Expanded docs for production admission deployment and support/upgrade policy.

## v0.1.4 - 2026-02-27

### Added

1. Control-mapped metadata and certificate summaries for audit workflows.

## v0.1.3 - 2026-02-27

### Added

1. Terraform pilot profile with 15 high-value controls.

## v0.1.2 - 2026-02-27

### Added

1. Differentiation wave: replay, attestation export, IR diff, confidence model, exception governance metrics, CI exports, benchmarks, migration docs.

## v0.1.1 - 2026-02-27

### Added

1. Exceptions with expiry/owner/reason.
2. SARIF export.
3. Signed policy bundles with version pinning.
4. Kyverno validate-subset adapter.

## v0.1.0 - 2026-02-26

### Added

1. Initial release with policy compiler, deterministic verifier, traces, and certificate artifacts.
