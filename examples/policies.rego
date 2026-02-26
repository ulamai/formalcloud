package formalcloud.policies

# fc.policy.id: org.baseline.cloud-security.rego
# fc.policy.version: 1
# fc.policy.revision: 1.0.0-rego
# fc.policy.min_engine_version: 0.1.0
# fc.policy.notes: Rego subset adapter metadata only; deny bodies are placeholders.

# fc.id: TF001
# fc.title: No public S3 buckets
# fc.target: terraform
# fc.check: no_public_s3
# fc.severity: critical
deny["TF001"] {
  input.target == "terraform"
}

# fc.id: TF002
# fc.title: Encryption required for S3 and RDS
# fc.target: terraform
# fc.check: require_encryption
# fc.severity: high
# fc.params: {"resource_types": ["aws_s3_bucket", "aws_db_instance"]}
deny["TF002"] {
  input.target == "terraform"
}

# fc.id: TF003
# fc.title: No destructive changes in protected workspaces
# fc.target: terraform
# fc.check: no_destructive_changes
# fc.severity: high
# fc.params: {"protected_workspaces": ["prod", "production"]}
deny["TF003"] {
  input.target == "terraform"
}

# fc.id: K8S001
# fc.title: Privileged containers are forbidden
# fc.target: kubernetes
# fc.check: no_privileged_containers
# fc.severity: critical
deny["K8S001"] {
  input.target == "kubernetes"
}

# fc.id: K8S002
# fc.title: Containers require resource limits
# fc.target: kubernetes
# fc.check: require_resources_limits
# fc.severity: medium
deny["K8S002"] {
  input.target == "kubernetes"
}

# fc.id: K8S003
# fc.title: Disallow mutable image tags
# fc.target: kubernetes
# fc.check: disallow_latest_tag
# fc.severity: high
deny["K8S003"] {
  input.target == "kubernetes"
}

# fc.id: K8S004
# fc.title: Require non-root runtime
# fc.target: kubernetes
# fc.check: require_non_root
# fc.severity: high
deny["K8S004"] {
  input.target == "kubernetes"
}
