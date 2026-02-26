# Migration Guide: OPA to FormalCloud

## Mapping strategy

1. Keep Rego as authoring format for mapped controls.
2. Add FormalCloud metadata annotations to `deny` rules.
3. Compile Rego subset to the FormalCloud IR and verify against Terraform/Kubernetes inputs.

## Suggested rollout

1. Start in `audit` mode using certificate exports.
2. Compare decision parity for selected controls.
3. Move high-confidence controls to `enforce`.

## Notes

- Unsupported Rego features should remain in OPA until adapter coverage expands.
- Use `formal-cloud policy diff` to compare adapter outputs against native policy packs.
