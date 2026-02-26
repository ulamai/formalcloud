# Migration Guide: tfsec to FormalCloud

## Mapping strategy

1. Preserve fast local checks by running FormalCloud on changed Terraform plans.
2. Map key tfsec controls to FormalCloud rules and confidence-aware semantics.
3. Use bundle pinning and certificate attestations for CI promotion.

## Suggested rollout

1. Introduce `formal-cloud verify terraform` in pre-merge CI.
2. Add replay checks for deterministic gate stability.
3. Gate production branches on signed, pinned policy bundles.

## Notes

- tfsec remains useful for broad lint-style checks during transition.
