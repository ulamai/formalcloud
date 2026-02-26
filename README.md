# FormalCloud

FormalCloud is an open-source formal compliance engine for cloud infrastructure and policy-as-code workflows. It evaluates Terraform plans and Kubernetes manifests with deterministic rule semantics, then produces machine-checkable certificates that explain why a change was accepted or rejected.

Instead of relying on periodic scanner snapshots, FormalCloud is designed for per-change enforcement in CI/CD and admission pipelines. Every decision is reproducible, traceable, and attestable, so teams can ship faster while preserving high-assurance evidence for security reviews, audits, and incident investigations.

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
  - Rego subset adapter (`formal-cloud.rego-subset/v1`).
  - Kyverno validate-subset adapter (`formal-cloud.kyverno-subset/v1`).
  - Exception model (`owner`, `reason`, `expires_at`, `entity_patterns`).
  - Stable policy digest for reproducibility.
- Verifier loop:
  - Deterministic check dispatch by rule ID.
  - Exception-aware rule evaluation with waived violation evidence.
  - Rule-level proof object with hash commitments.
- Trace logs:
  - JSONL event stream for compilation and verification phases.
- Attestation:
  - HMAC-signed certificates.
  - Offline signature/integrity verification.
- Policy bundles:
  - Signed bundle format with version pinning (`formal-cloud.bundle/v1`).
- Evidence exports:
  - SARIF export for code scanning workflows.
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
- Rego subset files (`.rego`) are accepted through adapter-based compilation.
- Kyverno policy files (`kyverno.io/v1`, `Policy` or `ClusterPolicy`) are accepted through validate-subset compilation.

Rego subset adapter example (`deny` rules first):

```rego
package formalcloud.policies

# fc.policy.id: org.baseline.cloud-security.rego
# fc.policy.version: 1
# fc.policy.revision: 1.0.0-rego
# fc.policy.min_engine_version: 0.1.0

# fc.id: TF001
# fc.target: terraform
# fc.check: no_public_s3
deny["TF001"] {
  input.target == "terraform"
}
```

Compile policy file:

```bash
formal-cloud compile \
  --policies examples/policies.yaml \
  --out out/compiled-policies.json \
  --trace out/compile-trace.jsonl
```

Compile Rego subset policy:

```bash
formal-cloud compile \
  --policies examples/policies.rego \
  --out out/compiled-rego-policies.json \
  --trace out/compile-rego-trace.jsonl
```

Compile Kyverno validate-subset policy:

```bash
formal-cloud compile \
  --policies examples/kyverno-policy.yaml \
  --out out/compiled-kyverno-policies.json \
  --trace out/compile-kyverno-trace.jsonl
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

Verify using signed + pinned policy bundle:

```bash
formal-cloud bundle create \
  --bundle-id org.formalcloud.bundle \
  --bundle-version 1.0.0 \
  --policy-file examples/policies.yaml \
  --policy-file examples/policies.rego \
  --signing-key-file examples/signing.key \
  --signing-key-id local-dev \
  --out out/policy-bundle.json

formal-cloud verify terraform \
  --bundle out/policy-bundle.json \
  --policy-set-id org.baseline.cloud-security \
  --bundle-version 1.0.0 \
  --bundle-key-file examples/signing.key \
  --bundle-require-signature \
  --plan examples/terraform-plan.json \
  --workspace prod \
  --out out/terraform-certificate-from-bundle.json
```

Create/verify bundle explicitly:

```bash
formal-cloud bundle verify \
  --bundle out/policy-bundle.json \
  --expected-version 1.0.0 \
  --key-file examples/signing.key \
  --require-signature \
  --out out/policy-bundle-verify-report.json
```

Offline attestation verification:

```bash
formal-cloud attest verify \
  --certificate out/terraform-certificate.signed.json \
  --key-file examples/signing.key \
  --out out/terraform-verify-report.json
```

Export certificate to SARIF:

```bash
formal-cloud export sarif \
  --certificate out/terraform-certificate.json \
  --out out/terraform-results.sarif.json
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

Run admission webhook with bundle policy source:

```bash
formal-cloud admission-webhook \
  --bundle out/policy-bundle.json \
  --policy-set-id org.baseline.cloud-security \
  --bundle-version 1.0.0 \
  --bundle-key-file examples/signing.key \
  --bundle-require-signature \
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
- `6`: bundle verification failed

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

- Exception governance workflows (`audit` vs `enforce`, approval lifecycle).
- Signed bundle distribution and remote registry support.
- Differential evaluation against OPA/Kyverno for adapter parity.
- Lean/Coq proof export for selected rule classes.
