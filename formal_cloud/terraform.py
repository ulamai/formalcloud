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
