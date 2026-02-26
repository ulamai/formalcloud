# Deterministic Replay

FormalCloud replay mode recomputes a certificate from the same policy + subject input and checks it against an expected certificate artifact.

## Terraform

```bash
formal-cloud replay terraform \
  --policies examples/policies.yaml \
  --plan examples/terraform-plan.json \
  --workspace prod \
  --expected-certificate out/terraform-certificate.json \
  --out out/replay-report.json
```

## Kubernetes

```bash
formal-cloud replay kubernetes \
  --policies examples/policies.yaml \
  --manifest examples/k8s-manifest.yaml \
  --expected-certificate out/k8s-certificate.json \
  --out out/replay-report-k8s.json
```

Replay report checks:

1. `certificate_id`
2. `decision`
3. `policy_digest`
4. `subject_digest`
