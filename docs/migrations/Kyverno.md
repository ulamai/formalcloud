# Migration Guide: Kyverno to FormalCloud

## Mapping strategy

1. Start with validate rules that map to built-in FormalCloud Kubernetes checks.
2. Compile Kyverno policies through the validate-subset adapter.
3. Compare admission decisions in non-blocking environments.

## Suggested rollout

1. Run adapter-compiled policies in CI first.
2. Validate parity with cluster admission outcomes.
3. Introduce FormalCloud-native exceptions and bundle governance.

## Notes

- Mutate/generate flows are out of scope for the current adapter.
- Use native FormalCloud policy docs for exception policy constraints.
