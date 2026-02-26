# formal-cloud Delivery Pipeline

## Full Version Roadmap

1. Policy language + compiler:
   - Stable typed policy DSL.
   - Schema versioning + migrations.
   - Backward compatibility guarantees.
2. Formal semantics + proof layer:
   - Explicit Terraform/Kubernetes change semantics.
   - Proof-producing decisions.
   - Independently checkable verifier path.
3. Coverage expansion:
   - AWS/GCP/Azure resource models.
   - Terraform unknown/module-aware reasoning.
   - Broader Kubernetes object and admission coverage.
4. Runtime enforcement:
   - Kubernetes validating admission webhook.
   - CI gates for GitHub/GitLab/Jenkins.
5. Trustworthy evidence:
   - Signed policy certificates.
   - Tamper-evident traces.
   - Immutable audit storage and control mappings.
6. Security hardening:
   - Secret redaction and data minimization.
   - Tenant isolation and RBAC.
   - Key management and retention controls.
7. Policy operations:
   - Exception workflow with expiry/approvals.
   - Policy pack rollout (`audit` and `enforce`).
   - Change impact previews.
8. Reliability and scale:
   - Horizontal workers, queueing, retries, idempotency.
   - SLOs and full observability.
9. Verification quality:
   - Golden corpus and differential testing.
   - Fuzz/property testing.
   - Deterministic regression suites.
10. Product/commercialization:
   - Multi-tenant SaaS control plane.
   - On-prem agent packaging.
   - Metering, billing, and support operations.

## Current Focus: Item 1

### Phase 1 Goals

- Introduce a stable policy schema: `formal-cloud.policy/v1`.
- Add policy metadata (`id`, `version`, `revision`, compatibility constraints).
- Keep legacy policy format working through migration at compile time.
- Emit schema metadata in compiled artifacts and verification certificates.
- Add tests that enforce compatibility behavior.

### Exit Criteria

- New schema compiles and verifies successfully.
- Legacy schema compiles via deterministic migration.
- Certificates include policy schema + metadata.
- Test suite passes for both new and legacy policy inputs.

## Ecosystem Aggregation Strategy

### What to adopt from OPA

- Keep policy and data separated to support reusable rule packs.
- Add policy bundle distribution and version pinning.
- Use partial evaluation patterns for faster deterministic checks.
- Preserve rich decision logs and explain traces.

### What to adopt from Kyverno

- Keep Kubernetes-native policy UX and admission-first ergonomics.
- Support policy exceptions with owner, reason, and expiry.
- Emit policy report style summaries for cluster governance workflows.

### What to adopt from Checkov

- Enrich checks with metadata: check ID, severity, guideline URL.
- Add graph/context-aware checks across related infrastructure objects.
- Export CI-friendly formats (SARIF and JUnit).
- Support controlled skips with mandatory justification.

### What to adopt from tfsec

- Prioritize fast local feedback for Terraform authors.
- Keep CLI ergonomics simple and pre-commit friendly.
- Retain focused Terraform heuristics where they improve signal.

### How we combine these in formal-cloud

- Keep one canonical typed IR and one certificate schema as the source of truth.
- Add policy adapters:
  - Rego subset -> IR.
  - Kyverno `validate` subset -> IR.
  - Native formal-cloud DSL -> IR.
- Execute in two stages:
  - Stage 1: fast scanner-style checks.
  - Stage 2: formal proof-carrying checks for high-impact invariants.
- Standardize policy operations:
  - `audit` and `enforce` modes.
  - Exception objects with expiry/approval metadata.
  - Signed policy bundles and signed decision certificates.
- Keep evidence interoperability:
  - Canonical JSON certificate.
  - SARIF and JUnit adapters for existing CI ecosystems.

### Prioritized implementation order

1. Rego subset adapter -> IR (`deny` rules first).
2. Exception model with expiry/owner/reason in compiler and verifier.
3. SARIF exporter for code scanning UX.
4. Policy bundle format with version pinning and signature verification.
5. Kyverno `validate` subset adapter for admission parity.
