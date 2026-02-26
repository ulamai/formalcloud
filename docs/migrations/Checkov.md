# Migration Guide: Checkov to FormalCloud

## Mapping strategy

1. Identify high-signal checks currently enforced in Checkov.
2. Recreate those controls in FormalCloud IR-compatible policies.
3. Export SARIF/JUnit from FormalCloud certificates to preserve CI integrations.

## Suggested rollout

1. Dual-run Checkov and FormalCloud.
2. Compare false-positive/false-negative behavior on change sets.
3. Promote deterministic FormalCloud gates for critical invariants.

## Notes

- Keep broad scanner coverage in parallel where FormalCloud semantics are not yet modeled.
