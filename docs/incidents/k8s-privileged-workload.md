# Incident Example: Privileged Kubernetes Workload

## Scenario

A Deployment enters a cluster with `securityContext.privileged: true`, missing resource limits, `:latest` tag, and no `runAsNonRoot` controls.

## FormalCloud Value

- A single admission-time decision rejects the object.
- Rule-level evidence identifies each failing invariant and container entity.
- SARIF/JUnit/GitHub Checks exports allow the same result to surface in CI and code review workflows.

## Outcome

- Misconfiguration blocked before runtime.
- Same decision artifact reused for security triage and compliance evidence.
