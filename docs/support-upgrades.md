# Support And Upgrade Policy

This document defines compatibility, deprecation, and upgrade expectations for FormalCloud.

## Scope

The policy applies to:

1. CLI behavior and exit codes.
2. Policy schema (`formal-cloud.policy/*`).
3. Certificate schema (`formal-cloud/v1`).
4. Bundle schema (`formal-cloud.bundle/*`).
5. Evidence-pack schema (`formal-cloud.evidence-pack/*`).

## Versioning model

FormalCloud uses semantic-style versioning with prerelease latitude while major version is `0`.

Interpretation for current phase (`0.x`):

1. Patch release (`0.x.y`): bug fixes and non-breaking improvements expected.
2. Minor release (`0.y.0`): new features; limited breaking changes may occur with clear migration notes.
3. Major `1.0.0`: stricter long-term compatibility guarantees.

## Compatibility commitments (current)

1. Policy files:
   - `formal-cloud.policy/v1` remains the primary stable input format.
   - Legacy `version + rules` format remains accepted through deterministic migration until explicitly removed.
2. Certificates:
   - `schema_version: formal-cloud/v1` output shape is kept compatible across patch releases.
3. Bundles and evidence:
   - Existing schema versions stay readable unless deprecation window has passed.
4. Exit codes:
   - Existing non-zero meaning should remain stable; additions may occur for new commands.

## Deprecation process

When a field/command/format is planned for removal:

1. Add deprecation notice to `README.md` and migration docs.
2. Keep behavior available for at least two subsequent minor releases when feasible.
3. Provide an explicit replacement path and examples.
4. Remove only after deprecation window and release-note notice.

## Upgrade workflow for operators

Recommended release upgrade process:

1. Read release notes and schema-related changes.
2. Run `formal-cloud policy test --cases ...` against your golden suite.
3. Run benchmark/regression checks in CI before promotion.
4. Roll out to audit profile first, then enforce.
5. Pin bundle versions and verify signatures in production gates.

## Security and support channel

1. Report vulnerabilities privately to repository maintainers (see `SECURITY.md` when available).
2. Include affected version, reproduction steps, and impact details.
3. For production incidents, capture certificate IDs and traces to accelerate triage.
