# Adapter Compatibility Matrix

| Capability | Native Policy YAML | Rego Subset Adapter | Kyverno Validate Subset Adapter |
|---|---:|---:|---:|
| Target selection (`terraform` / `kubernetes`) | Yes | Yes (metadata annotations) | Kubernetes only |
| Built-in check mapping | Yes | Yes | Yes (validate pattern subset) |
| Exception objects | Yes | No (author in native policy or bundle) | No (author in native policy or bundle) |
| Exception policy constraints | Yes | No | No |
| Policy metadata (`id`, `version`, `revision`) | Yes | Yes | Yes (annotations) |
| Bundle inclusion/signing | Yes | Yes | Yes |
| Deterministic certificate generation | Yes | Yes | Yes |

## Notes

- Rego adapter currently compiles metadata-annotated `deny` rules into the FormalCloud IR.
- Kyverno adapter currently supports a validate subset mapped to the built-in Kubernetes checks:
  - `no_privileged_containers`
  - `require_resources_limits`
  - `require_non_root`
  - `disallow_latest_tag`
- For advanced policy operations (exceptions, exception-policy governance), keep source-of-truth in native FormalCloud policy documents or bundled policy sets.
