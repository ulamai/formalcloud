# formal-cloud-admission Helm Chart

Deploys FormalCloud as a Kubernetes validating admission webhook using:

1. FormalCloud webhook container on localhost HTTP (`127.0.0.1:8080`).
2. TLS sidecar (Caddy) terminating webhook TLS on `9443`.
3. Optional cert-manager resources for certificate issuance and CA injection.

## Prerequisites

1. Kubernetes 1.24+
2. Helm 3.10+
3. cert-manager (when `tls.certManager.enabled=true`)

## Install

```bash
helm upgrade --install formal-cloud-admission \
  deploy/helm/formal-cloud-admission \
  --namespace formal-cloud-system \
  --create-namespace
```

## Bring your own policy set

By default the chart creates a policy ConfigMap from `values.yaml`.
To use your own ConfigMap:

```bash
helm upgrade --install formal-cloud-admission \
  deploy/helm/formal-cloud-admission \
  --namespace formal-cloud-system \
  --set policy.configMapName=my-formal-cloud-policies \
  --set policy.fileName=policies.yaml
```

## Rollout recommendation

1. Start with `webhook.failurePolicy=Ignore` and audit-oriented policy profile.
2. Monitor rejects/latency.
3. Move to `webhook.failurePolicy=Fail` for enforced rollout.
