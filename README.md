# formal-cloud

`formal-cloud` is an MVP proof-carrying policy gate for cloud infrastructure changes.

It compiles typed policy rules, evaluates Terraform plan JSON and Kubernetes manifests with deterministic checkers, and emits certificate-style evidence artifacts plus trace logs for audit use.

## Why this exists

This project is built around three goals:

1. Deterministic checks over machine-readable infra changes.
2. Proof-carrying decisions (`accept` / `reject`) with reproducible hashes.
3. Audit-ready evidence attached to CI runs.

## Implemented formalization artifacts

- Normalized representations:
  - Terraform plan normalization from `terraform show -json` output.
  - Kubernetes manifest normalization from YAML docs.
- Policy compilation:
  - Stable policy schema: `formal-cloud.policy/v1`.
  - Typed rule schema (target + check + severity + params).
  - Legacy policy migration (`legacy/v0` -> `formal-cloud.policy/v1`).
  - Stable policy digest for reproducibility.
- Verifier loop:
  - Deterministic check dispatch by rule ID.
  - Rule-level proof object with hash commitments.
- Trace logs:
  - JSONL event stream for compilation and verification phases.
- Attestation:
  - HMAC-signed certificates.
  - Offline signature/integrity verification.
- Reproducibility benchmarking:
  - Corpus runner that checks stable decision and certificate IDs across repeated runs.

## Supported checks

Terraform:

- `no_public_s3`
- `require_encryption`
- `no_destructive_changes`

Kubernetes:

- `no_privileged_containers`
- `require_resources_limits`
- `disallow_latest_tag`
- `require_non_root`

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

`PyYAML` is optional. If unavailable, the tool falls back to Ruby's built-in Psych parser for YAML.

## Usage

Policy schema example (`formal-cloud.policy/v1`):

```yaml
schema_version: formal-cloud.policy/v1
policy:
  id: org.baseline.cloud-security
  version: 1
  revision: 1.0.0
  compatibility:
    min_engine_version: 0.1.0
rules:
  - id: TF001
    title: No public S3 buckets
    target: terraform
    check: no_public_s3
    severity: critical
```

Backward compatibility:

- Legacy files using top-level `version` + `rules` are still accepted.
- Compiler migrates them to `formal-cloud.policy/v1` deterministically.

Compile policy file:

```bash
formal-cloud compile \
  --policies examples/policies.yaml \
  --out out/compiled-policies.json \
  --trace out/compile-trace.jsonl
```

Verify Terraform plan:

```bash
formal-cloud verify terraform \
  --policies examples/policies.yaml \
  --plan examples/terraform-plan.json \
  --workspace prod \
  --out out/terraform-certificate.json \
  --trace out/terraform-trace.jsonl
```

Verify + sign Terraform certificate:

```bash
formal-cloud verify terraform \
  --policies examples/policies.yaml \
  --plan examples/terraform-plan.json \
  --workspace prod \
  --out out/terraform-certificate.signed.json \
  --trace out/terraform-trace.jsonl \
  --signing-key-file examples/signing.key \
  --signing-key-id ci
```

Verify Kubernetes manifests:

```bash
formal-cloud verify kubernetes \
  --policies examples/policies.yaml \
  --manifest examples/k8s-manifest.yaml \
  --out out/k8s-certificate.json \
  --trace out/k8s-trace.jsonl
```

Offline attestation verification:

```bash
formal-cloud attest verify \
  --certificate out/terraform-certificate.signed.json \
  --key-file examples/signing.key \
  --out out/terraform-verify-report.json
```

Benchmark reproducibility corpus:

```bash
formal-cloud benchmark run \
  --cases benchmarks/corpus/cases.yaml \
  --iterations 5 \
  --out out/benchmark-report.json
```

Run admission webhook:

```bash
formal-cloud admission-webhook \
  --policies examples/policies.yaml \
  --host 0.0.0.0 \
  --port 8443
```

The webhook serves `/healthz` and admission POSTs. For production, terminate TLS in front of the service.

Exit codes:

- `0`: verification accepted
- `3`: verification rejected
- `1`: execution error
- `4`: certificate attestation verification failed
- `5`: benchmark corpus failed

Run tests (stdlib only):

```bash
PYTHONPATH=. python -m unittest discover -s tests -p 'test_*.py'
```

## CI integration idea

Terraform gate job (GitHub Actions):

```yaml
- name: Terraform plan JSON
  run: terraform show -json tfplan.binary > tfplan.json

- name: Formal policy check
  run: |
    formal-cloud verify terraform \
      --policies policy/policies.yaml \
      --plan tfplan.json \
      --workspace ${{ github.ref_name }} \
      --out artifacts/terraform-certificate.json \
      --trace artifacts/terraform-trace.jsonl

- name: Upload evidence
  uses: actions/upload-artifact@v4
  with:
    name: compliance-evidence
    path: artifacts/
```

Shipped GitHub Action assets:

- Composite action: `.github/actions/formal-cloud-gate/action.yml`
- Workflow example: `.github/workflows/formal-cloud-gate.yml`

## Security note

`terraform show -json` can contain plaintext sensitive values. Treat plan JSON and generated evidence artifacts as sensitive build artifacts and scope retention/access appropriately.

## Roadmap (next)

- Rego subset parser and compilation to this rule IR.
- Signature support for certificates.
- Admission webhook wrapper for Kubernetes.
- Lean/Coq proof export for selected rule classes.
