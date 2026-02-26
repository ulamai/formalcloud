# Incident Example: Public S3 During Migration

## Scenario

A team migrates a legacy static website bucket and temporarily keeps ACL `public-read`. Baseline policy `TF001` blocks this change.

## FormalCloud Value

- Without exception: change is rejected with deterministic evidence (`TF001` violation).
- With governed exception: change can proceed while preserving audit controls (`owner`, `reason`, `approved_by`, `expires_at`).
- Certificate captures both active violations and waived violations, so reviewers can see policy debt explicitly instead of losing signal.

## Outcome

- Short-term delivery unblock.
- Explicit exception debt tracked in certificate summary.
- Deterministic replay and attestation support post-incident RCA.
