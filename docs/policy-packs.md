# Starter Policy Packs

FormalCloud ships starter policy packs to accelerate first rollout:

1. `examples/policy-packs/soc2-starter.yaml`
2. `examples/policy-packs/cis-aws-starter.yaml`
3. `examples/policy-packs/nist-800-53-starter.yaml`

These are baseline mappings and should be tailored to your threat model and control interpretation.

## Compile a pack

```bash
formal-cloud compile \
  --policies examples/policy-packs/soc2-starter.yaml \
  --out out/soc2-pack-compiled.json
```

## Use a pack in a Terraform gate

```bash
formal-cloud verify terraform \
  --policies examples/policy-packs/cis-aws-starter.yaml \
  --plan examples/terraform-plan.json \
  --workspace prod \
  --out out/cis-terraform-certificate.json
```

## Build signed bundle artifacts from packs

```bash
formal-cloud bundle create \
  --bundle-id org.formalcloud.starter-packs \
  --bundle-version 1.0.0 \
  --policy-file examples/policy-packs/soc2-starter.yaml \
  --policy-file examples/policy-packs/cis-aws-starter.yaml \
  --policy-file examples/policy-packs/nist-800-53-starter.yaml \
  --signing-key-file examples/signing.key \
  --signing-key-id release \
  --out out/starter-packs-bundle.json
```

## Recommended adoption pattern

1. Start in audit-oriented profile.
2. Collect violation trends and false-positive feedback.
3. Introduce scoped exceptions with owner/reason/expiry.
4. Move high-confidence controls to enforce mode.
