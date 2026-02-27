# Admission Webhook Production Guide

This guide covers a production deployment pattern for the FormalCloud Kubernetes admission webhook.

## Deployment goals

1. TLS for all webhook traffic.
2. Restricted network and identity boundaries.
3. High availability and predictable rollout behavior.
4. Clear fail-open vs fail-closed policy by environment.

## TLS and certificate management

The built-in webhook server is plain HTTP. In production, terminate TLS in front of it (for example with an ingress/controller or service mesh) and register the TLS endpoint in `ValidatingWebhookConfiguration`.

Recommended patterns:

1. Cert-manager managed certificate with automatic rotation.
2. CA bundle injection into `ValidatingWebhookConfiguration` from the same trust chain.
3. Short certificate TTL with automated renewal.

Example webhook policy choice:

1. `failurePolicy: Fail` for enforced profiles in production namespaces.
2. `failurePolicy: Ignore` only for early audit-only rollout.

## Authentication and authorization boundaries

Use least-privilege defaults:

1. Dedicated namespace (for example `formal-cloud-system`).
2. Dedicated ServiceAccount for webhook pods.
3. Minimal RBAC; no cluster-admin permissions required for pure validation path.
4. NetworkPolicy allowing ingress only from kube-apiserver/control-plane CIDRs or trusted ingress proxy.
5. Egress restricted to required endpoints only (typically none for local policy execution).

If your platform supports mTLS (service mesh), enforce mTLS between API server path and webhook endpoint.

## High availability and rollout safety

Minimum baseline:

1. At least 2 replicas.
2. PodDisruptionBudget (`minAvailable: 1` or higher).
3. Anti-affinity across nodes/zones.
4. Readiness/liveness probes on `/healthz`.
5. Resource requests/limits set explicitly.

Operational recommendations:

1. Roll out with canary namespace selector first.
2. Start in audit-oriented profile where possible.
3. Switch to enforce profile after violation rate stabilizes.
4. Monitor webhook latency and error rates before expanding scope.

## Webhook configuration strategy

Use namespace/object selectors to scope blast radius:

1. Label namespaces for staged enrollment.
2. Run separate webhook entries for `audit` and `enforce` tracks if needed.
3. Keep timeout budget conservative (for example `timeoutSeconds: 5`) to protect API server stability.

## Observability and incident response

Track at minimum:

1. Admission request count, allowed/denied split.
2. P95/P99 webhook latency.
3. Error rate by reason.
4. Certificate IDs for denied requests (for traceability).

Incident playbook:

1. If webhook instability impacts cluster operations, switch to `failurePolicy: Ignore` temporarily.
2. Capture denied object samples and certificate IDs.
3. Reproduce with `formal-cloud verify kubernetes` locally from manifests.
4. Restore `Fail` once regression is fixed and verified.

## Suggested production checklist

1. TLS termination configured and validated.
2. `failurePolicy` explicitly chosen by environment.
3. NetworkPolicy and RBAC applied.
4. HA settings (replicas/PDB/anti-affinity) in place.
5. SLOs and alerts configured for webhook latency/error rate.
6. Rollback procedure documented and tested.
