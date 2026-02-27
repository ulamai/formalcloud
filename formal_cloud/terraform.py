from __future__ import annotations

import json
from typing import Any

from .models import RuleViolation

PUBLIC_S3_ACLS = {
    "public-read",
    "public-read-write",
    "website",
    "authenticated-read",
}
PUBLIC_IPV4_CIDR = "0.0.0.0/0"
PUBLIC_IPV6_CIDR = "::/0"


def normalize_plan(plan: dict[str, Any]) -> dict[str, Any]:
    resource_changes = plan.get("resource_changes") or []
    normalized_changes: list[dict[str, Any]] = []

    for rc in resource_changes:
        change = rc.get("change") or {}
        normalized_changes.append(
            {
                "address": rc.get("address", ""),
                "type": rc.get("type", ""),
                "name": rc.get("name", ""),
                "provider_name": rc.get("provider_name", ""),
                "actions": list(change.get("actions") or []),
                "before": change.get("before"),
                "after": change.get("after"),
                "after_unknown": change.get("after_unknown"),
            }
        )

    normalized_changes.sort(key=lambda item: item["address"])

    return {
        "format_version": plan.get("format_version"),
        "terraform_version": plan.get("terraform_version"),
        "resource_changes": normalized_changes,
    }


def check_no_public_s3(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []

    for resource in resource_changes:
        resource_type = resource.get("type")
        actions = set(resource.get("actions") or [])
        after = resource.get("after") or {}

        if "delete" in actions and "create" not in actions:
            continue

        if resource_type == "aws_s3_bucket":
            acl = after.get("acl")
            if isinstance(acl, str) and acl in PUBLIC_S3_ACLS:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="S3 bucket ACL is public",
                        details={"acl": acl},
                    )
                )

            policy_str = after.get("policy")
            if isinstance(policy_str, str):
                try:
                    policy_obj = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy_obj = None
                if policy_obj and _policy_allows_public_access(policy_obj):
                    violations.append(
                        RuleViolation(
                            entity=resource.get("address", ""),
                            message="S3 bucket policy allows public access",
                            details={"policy_detected": True},
                        )
                    )

        if resource_type == "aws_s3_bucket_acl":
            acl = after.get("acl")
            if isinstance(acl, str) and acl in PUBLIC_S3_ACLS:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="S3 bucket ACL resource is public",
                        details={"acl": acl},
                    )
                )

        if resource_type == "aws_s3_bucket_public_access_block":
            keys = [
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ]
            unset = [key for key in keys if after.get(key) is not True]
            if unset:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="S3 public access block is not fully enabled",
                        details={"missing_controls": unset},
                    )
                )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_encryption(
    resource_changes: list[dict[str, Any]], params: dict[str, Any]
) -> list[RuleViolation]:
    default_types = ["aws_s3_bucket", "aws_db_instance", "aws_ebs_volume"]
    configured_types = params.get("resource_types")
    resource_types = set(configured_types if isinstance(configured_types, list) else default_types)

    violations: list[RuleViolation] = []
    for resource in resource_changes:
        resource_type = resource.get("type")
        if resource_type not in resource_types:
            continue

        actions = set(resource.get("actions") or [])
        after = resource.get("after") or {}

        if actions == {"no-op"}:
            continue
        if "delete" in actions and "create" not in actions:
            continue

        if resource_type == "aws_s3_bucket":
            sse = after.get("server_side_encryption_configuration")
            if not sse:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="S3 bucket encryption is not configured",
                        details={"expected": "server_side_encryption_configuration"},
                    )
                )
            continue

        if resource_type == "aws_db_instance":
            if after.get("storage_encrypted") is not True:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="RDS storage must be encrypted",
                        details={"storage_encrypted": after.get("storage_encrypted")},
                    )
                )
            continue

        if resource_type == "aws_ebs_volume":
            if after.get("encrypted") is not True:
                violations.append(
                    RuleViolation(
                        entity=resource.get("address", ""),
                        message="EBS volume must be encrypted",
                        details={"encrypted": after.get("encrypted")},
                    )
                )
            continue

        encrypted = after.get("encrypted", after.get("storage_encrypted"))
        if encrypted is not True:
            violations.append(
                RuleViolation(
                    entity=resource.get("address", ""),
                    message="Resource encryption field must be enabled",
                    details={"encrypted": encrypted},
                )
            )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_no_destructive_changes(
    resource_changes: list[dict[str, Any]],
    workspace: str,
    protected_workspaces: list[str],
) -> list[RuleViolation]:
    if workspace not in set(protected_workspaces):
        return []

    violations: list[RuleViolation] = []
    for resource in resource_changes:
        actions = list(resource.get("actions") or [])
        if "delete" in actions:
            violations.append(
                RuleViolation(
                    entity=resource.get("address", ""),
                    message="Destructive action is blocked in protected workspace",
                    details={"workspace": workspace, "actions": actions},
                )
            )

    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_disallow_wide_cidr_ingress(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for entity, rule in _iter_security_group_rules(resource_changes, direction="ingress"):
        if not _rule_has_public_cidr(rule):
            continue
        violations.append(
            RuleViolation(
                entity=entity,
                message="Security group ingress allows public CIDR",
                details={
                    "cidr_ipv4": _extract_rule_ipv4_cidrs(rule),
                    "cidr_ipv6": _extract_rule_ipv6_cidrs(rule),
                    "protocol": _rule_protocol(rule),
                    "from_port": rule.get("from_port"),
                    "to_port": rule.get("to_port"),
                },
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_disallow_wide_cidr_egress(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for entity, rule in _iter_security_group_rules(resource_changes, direction="egress"):
        if not _rule_has_public_cidr(rule):
            continue
        violations.append(
            RuleViolation(
                entity=entity,
                message="Security group egress allows public CIDR",
                details={
                    "cidr_ipv4": _extract_rule_ipv4_cidrs(rule),
                    "cidr_ipv6": _extract_rule_ipv6_cidrs(rule),
                    "protocol": _rule_protocol(rule),
                    "from_port": rule.get("from_port"),
                    "to_port": rule.get("to_port"),
                },
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_disallow_ssh_from_internet(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    return _check_disallow_internet_port(
        resource_changes=resource_changes,
        port=22,
        message="Security group ingress allows SSH (22) from the internet",
    )


def check_disallow_rdp_from_internet(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    return _check_disallow_internet_port(
        resource_changes=resource_changes,
        port=3389,
        message="Security group ingress allows RDP (3389) from the internet",
    )


def check_require_s3_versioning(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    enabled_buckets = _collect_bucket_set(
        resource_changes=resource_changes,
        resource_type="aws_s3_bucket_versioning",
        extractor=_bucket_name_from_versioning_resource,
    )
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_s3_bucket"}):
        after = resource.get("after") or {}
        bucket_name = _bucket_name_from_bucket_resource(resource)
        if _bucket_versioning_enabled(after) or (bucket_name and bucket_name in enabled_buckets):
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="S3 bucket versioning must be enabled",
                details={"bucket": bucket_name},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_s3_bucket_logging(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    logged_buckets = _collect_bucket_set(
        resource_changes=resource_changes,
        resource_type="aws_s3_bucket_logging",
        extractor=_bucket_name_from_logging_resource,
    )
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_s3_bucket"}):
        after = resource.get("after") or {}
        bucket_name = _bucket_name_from_bucket_resource(resource)
        if _bucket_logging_enabled(after) or (bucket_name and bucket_name in logged_buckets):
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="S3 bucket access logging must be enabled",
                details={"bucket": bucket_name},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_rds_backup_retention(
    resource_changes: list[dict[str, Any]], params: dict[str, Any]
) -> list[RuleViolation]:
    min_days = _as_int(params.get("min_days"), default=7)
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_db_instance"}):
        after = resource.get("after") or {}
        retention = _as_int(after.get("backup_retention_period"), default=0)
        if retention >= min_days:
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message=f"RDS backup retention must be at least {min_days} days",
                details={"backup_retention_period": retention, "min_days": min_days},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_rds_multi_az(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_db_instance"}):
        after = resource.get("after") or {}
        if after.get("multi_az") is True:
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="RDS must enable multi_az",
                details={"multi_az": after.get("multi_az")},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_rds_deletion_protection(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_db_instance"}):
        after = resource.get("after") or {}
        if after.get("deletion_protection") is True:
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="RDS must enable deletion protection",
                details={"deletion_protection": after.get("deletion_protection")},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_imdsv2(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(
        resource_changes, {"aws_instance", "aws_launch_template"}
    ):
        after = resource.get("after") or {}
        tokens = _http_tokens_value(after.get("metadata_options"))
        if tokens == "required":
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="EC2 metadata service must require IMDSv2 tokens",
                details={"http_tokens": tokens},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_kms_key_rotation(resource_changes: list[dict[str, Any]]) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_kms_key"}):
        after = resource.get("after") or {}
        if after.get("enable_key_rotation") is True:
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message="KMS keys must enable automatic key rotation",
                details={"enable_key_rotation": after.get("enable_key_rotation")},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def check_require_log_retention_min_days(
    resource_changes: list[dict[str, Any]], params: dict[str, Any]
) -> list[RuleViolation]:
    min_days = _as_int(params.get("min_days"), default=30)
    violations: list[RuleViolation] = []
    for resource in _iter_active_resources(resource_changes, {"aws_cloudwatch_log_group"}):
        after = resource.get("after") or {}
        retention = _as_int(after.get("retention_in_days"), default=0)
        if retention >= min_days:
            continue
        violations.append(
            RuleViolation(
                entity=resource.get("address", ""),
                message=f"CloudWatch log group retention must be at least {min_days} days",
                details={"retention_in_days": retention, "min_days": min_days},
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def _policy_allows_public_access(policy_obj: dict[str, Any]) -> bool:
    statements = policy_obj.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        if _principal_is_public(statement.get("Principal")):
            return True

    return False


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*":
                return True
            if isinstance(value, list) and "*" in value:
                return True
    return False


def _iter_active_resources(
    resource_changes: list[dict[str, Any]], resource_types: set[str]
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for resource in resource_changes:
        if resource.get("type") not in resource_types:
            continue
        actions = set(resource.get("actions") or [])
        if not actions or actions == {"no-op"}:
            continue
        if "delete" in actions and "create" not in actions:
            continue
        selected.append(resource)
    return selected


def _iter_security_group_rules(
    resource_changes: list[dict[str, Any]], direction: str
) -> list[tuple[str, dict[str, Any]]]:
    selected: list[tuple[str, dict[str, Any]]] = []
    for resource in _iter_active_resources(
        resource_changes,
        {
            "aws_security_group",
            "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_egress_rule",
        },
    ):
        resource_type = resource.get("type")
        after = resource.get("after") or {}
        address = str(resource.get("address", ""))

        if resource_type == "aws_security_group":
            rules = after.get(direction) or []
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict):
                        selected.append((address, rule))
            continue

        if resource_type == "aws_security_group_rule":
            if str(after.get("type", "")).lower() == direction:
                selected.append((address, after))
            continue

        if resource_type == "aws_vpc_security_group_ingress_rule" and direction == "ingress":
            selected.append((address, after))
            continue
        if resource_type == "aws_vpc_security_group_egress_rule" and direction == "egress":
            selected.append((address, after))

    return selected


def _rule_has_public_cidr(rule: dict[str, Any]) -> bool:
    return (
        PUBLIC_IPV4_CIDR in _extract_rule_ipv4_cidrs(rule)
        or PUBLIC_IPV6_CIDR in _extract_rule_ipv6_cidrs(rule)
    )


def _extract_rule_ipv4_cidrs(rule: dict[str, Any]) -> list[str]:
    values = rule.get("cidr_blocks")
    cidrs: list[str] = []
    if isinstance(values, list):
        cidrs.extend([str(item) for item in values if isinstance(item, str)])
    cidr_ipv4 = rule.get("cidr_ipv4")
    if isinstance(cidr_ipv4, str):
        cidrs.append(cidr_ipv4)
    return cidrs


def _extract_rule_ipv6_cidrs(rule: dict[str, Any]) -> list[str]:
    values = rule.get("ipv6_cidr_blocks")
    cidrs: list[str] = []
    if isinstance(values, list):
        cidrs.extend([str(item) for item in values if isinstance(item, str)])
    cidr_ipv6 = rule.get("cidr_ipv6")
    if isinstance(cidr_ipv6, str):
        cidrs.append(cidr_ipv6)
    return cidrs


def _rule_protocol(rule: dict[str, Any]) -> str:
    protocol = rule.get("protocol")
    if isinstance(protocol, str):
        return protocol
    ip_protocol = rule.get("ip_protocol")
    if isinstance(ip_protocol, str):
        return ip_protocol
    return ""


def _rule_allows_port(rule: dict[str, Any], port: int) -> bool:
    protocol = _rule_protocol(rule).lower()
    if protocol in {"-1", "all"}:
        return True
    from_port = _as_int(rule.get("from_port"), default=None)
    to_port = _as_int(rule.get("to_port"), default=None)
    if from_port is None or to_port is None:
        return False
    lower = min(from_port, to_port)
    upper = max(from_port, to_port)
    return lower <= port <= upper


def _check_disallow_internet_port(
    resource_changes: list[dict[str, Any]], port: int, message: str
) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for entity, rule in _iter_security_group_rules(resource_changes, direction="ingress"):
        if not _rule_has_public_cidr(rule):
            continue
        if not _rule_allows_port(rule, port):
            continue
        violations.append(
            RuleViolation(
                entity=entity,
                message=message,
                details={
                    "port": port,
                    "cidr_ipv4": _extract_rule_ipv4_cidrs(rule),
                    "cidr_ipv6": _extract_rule_ipv6_cidrs(rule),
                    "protocol": _rule_protocol(rule),
                    "from_port": rule.get("from_port"),
                    "to_port": rule.get("to_port"),
                },
            )
        )
    return sorted(violations, key=lambda item: (item.entity, item.message))


def _collect_bucket_set(
    resource_changes: list[dict[str, Any]],
    resource_type: str,
    extractor: Any,
) -> set[str]:
    result: set[str] = set()
    for resource in _iter_active_resources(resource_changes, {resource_type}):
        after = resource.get("after") or {}
        bucket_name = extractor(after)
        if bucket_name:
            result.add(bucket_name)
    return result


def _bucket_name_from_bucket_resource(resource: dict[str, Any]) -> str | None:
    after = resource.get("after") or {}
    bucket = after.get("bucket")
    if isinstance(bucket, str) and bucket.strip():
        return bucket
    name = resource.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return None


def _bucket_name_from_versioning_resource(after: dict[str, Any]) -> str | None:
    if not _bucket_versioning_config_enabled(after):
        return None
    bucket = after.get("bucket")
    if isinstance(bucket, str) and bucket.strip():
        return bucket
    return None


def _bucket_name_from_logging_resource(after: dict[str, Any]) -> str | None:
    target_bucket = after.get("target_bucket")
    if not isinstance(target_bucket, str) or not target_bucket.strip():
        return None
    bucket = after.get("bucket")
    if isinstance(bucket, str) and bucket.strip():
        return bucket
    return None


def _bucket_versioning_enabled(after: dict[str, Any]) -> bool:
    versioning = after.get("versioning")
    if isinstance(versioning, dict):
        enabled = versioning.get("enabled")
        status = versioning.get("status")
        return enabled is True or status == "Enabled"
    if isinstance(versioning, list):
        for item in versioning:
            if isinstance(item, dict):
                enabled = item.get("enabled")
                status = item.get("status")
                if enabled is True or status == "Enabled":
                    return True
    return False


def _bucket_versioning_config_enabled(after: dict[str, Any]) -> bool:
    cfg = after.get("versioning_configuration")
    if isinstance(cfg, dict):
        status = cfg.get("status")
        return status == "Enabled"
    if isinstance(cfg, list):
        for item in cfg:
            if isinstance(item, dict) and item.get("status") == "Enabled":
                return True
    return False


def _bucket_logging_enabled(after: dict[str, Any]) -> bool:
    logging = after.get("logging")
    if isinstance(logging, dict):
        target_bucket = logging.get("target_bucket")
        return isinstance(target_bucket, str) and bool(target_bucket.strip())
    if isinstance(logging, list):
        for item in logging:
            if isinstance(item, dict):
                target_bucket = item.get("target_bucket")
                if isinstance(target_bucket, str) and bool(target_bucket.strip()):
                    return True
    return False


def _http_tokens_value(metadata_options: Any) -> str | None:
    if isinstance(metadata_options, dict):
        value = metadata_options.get("http_tokens")
        if isinstance(value, str):
            return value
    if isinstance(metadata_options, list):
        for item in metadata_options:
            if isinstance(item, dict):
                value = item.get("http_tokens")
                if isinstance(value, str):
                    return value
    return None


def _as_int(value: Any, default: int | None) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return default
    return default
