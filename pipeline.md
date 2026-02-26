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

## Sprint Plan (Differentiation Wave)

### Milestone M1: Verifiable Decision Plane

- Issue FC-101: replay command to recompute and assert certificate ID determinism.
- Issue FC-102: in-toto/SLSA-style attestation export from certificate artifacts.
- Issue FC-103: offline verification docs and deterministic replay examples.

### Milestone M2: One Semantics, Many Policy Languages

- Issue FC-201: policy IR diff command (`source A` vs `source B`) with machine-readable output.
- Issue FC-202: adapter parity tests across native/Rego/Kyverno for overlapping rule semantics.
- Issue FC-203: published compatibility matrix for adapter subsets and caveats.

### Milestone M3: Deep Change Semantics

- Issue FC-301: Terraform confidence model (`proven`/`assumed`/`unknown`) from plan characteristics.
- Issue FC-302: certificate-level confidence summary and subject risk context.
- Issue FC-303: unknown/module-driven semantics regression tests.

### Milestone M4: Exception Governance

- Issue FC-401: mandatory exception fields (`owner`, `reason`, `approved_by`, `expires_at`).
- Issue FC-402: exception policy constraints (`max_ttl_days`, `approver_regex`).
- Issue FC-403: exception debt metrics in certificate summary.

### Milestone M5: CI/Audit Workflow Fit

- Issue FC-501: JUnit export for CI test-report ingestion.
- Issue FC-502: GitHub Checks annotations export.
- Issue FC-503: evidence-pack export (certificate + trace + bundle verification + metadata manifest).
- Issue FC-504: changed-files fast path for Kubernetes verification and pre-commit workflow.

### Milestone M6: Public Proof Assets

- Issue FC-601: benchmark regression mode with expected certificate IDs.
- Issue FC-602: incident-style examples demonstrating stronger guarantees than scanner-only checks.
- Issue FC-603: migration guides from OPA/Kyverno/Checkov/tfsec to FormalCloud adapters and IR.

## Implementation Status (Current Branch)

1. M1 Verifiable Decision Plane: implemented.
   - `formal-cloud replay terraform|kubernetes`
   - `formal-cloud export intoto`
2. M2 One Semantics, Many Policy Languages: implemented baseline.
   - `formal-cloud policy diff`
   - Adapter parity tests for native/Rego/Kyverno overlap
   - `docs/compatibility-matrix.md`
3. M3 Deep Change Semantics: implemented baseline.
   - Terraform confidence model (`proven` / `assumed` / `unknown`)
   - Certificate confidence summary + subject analysis metadata
4. M4 Exception Governance: implemented baseline.
   - Mandatory exception fields (`owner`, `reason`, `approved_by`, `expires_at`)
   - Exception policy constraints (`max_ttl_days`, `required_approver_regex`)
   - Exception debt metrics in certificate summary
5. M5 CI/Audit Workflow Fit: implemented.
   - Exports: SARIF, JUnit, GitHub Checks, evidence-pack
   - Changed-files fast path for Kubernetes verification
   - Pre-commit hook assets (`.pre-commit-hooks.yaml`, script)
6. M6 Public Proof Assets: implemented baseline.
   - Benchmark corpus with fixed expected certificate IDs
   - Incident examples in `docs/incidents/`
   - Migration guides in `docs/migrations/`
