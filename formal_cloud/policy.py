from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import CompiledPolicySet, PolicyRule
from .trace import TraceLogger
from .utils import load_yaml, sha256_obj

SUPPORTED_CHECKS: dict[str, set[str]] = {
    "terraform": {
        "no_public_s3",
        "require_encryption",
        "no_destructive_changes",
    },
    "kubernetes": {
        "no_privileged_containers",
        "require_resources_limits",
        "disallow_latest_tag",
        "require_non_root",
    },
}

LATEST_SCHEMA_VERSION = "formal-cloud.policy/v1"
LEGACY_SCHEMA_VERSION = "legacy/v0"


def compile_policy_file(path: Path, trace: TraceLogger | None = None) -> CompiledPolicySet:
    doc = load_yaml(path)
    if trace:
        trace.event("policy.load", {"path": str(path)})
    return compile_policy_document(doc, source=str(path), trace=trace)


def compile_policy_document(
    doc: dict[str, Any], source: str = "<memory>", trace: TraceLogger | None = None
) -> CompiledPolicySet:
    if not isinstance(doc, dict):
        raise ValueError(f"policy document in {source} must be a mapping")

    canonical = _normalize_policy_document(doc, source=source, trace=trace)
    version = canonical["version"]
    rules = canonical["rules"]

    if not isinstance(rules, list) or not rules:
        raise ValueError(f"policy rules in {source} must be a non-empty list")

    seen_ids: set[str] = set()
    compiled_rules: list[PolicyRule] = []

    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            raise ValueError(f"every rule in {source} must be a mapping")

        rule_id = raw_rule.get("id")
        title = raw_rule.get("title") or str(rule_id)
        target = raw_rule.get("target")
        check = raw_rule.get("check")
        severity = raw_rule.get("severity", "medium")
        params = raw_rule.get("params") or {}

        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(f"rule id must be a non-empty string in {source}")
        if rule_id in seen_ids:
            raise ValueError(f"duplicate rule id '{rule_id}' in {source}")
        if target not in SUPPORTED_CHECKS:
            raise ValueError(f"unsupported target '{target}' in rule '{rule_id}'")
        if check not in SUPPORTED_CHECKS[target]:
            raise ValueError(
                f"unsupported check '{check}' for target '{target}' in rule '{rule_id}'"
            )
        if not isinstance(title, str):
            raise ValueError(f"title for rule '{rule_id}' must be a string")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(
                f"severity for rule '{rule_id}' must be one of low|medium|high|critical"
            )
        if not isinstance(params, dict):
            raise ValueError(f"params for rule '{rule_id}' must be a mapping")

        seen_ids.add(rule_id)
        compiled_rules.append(
            PolicyRule(
                rule_id=rule_id,
                title=title,
                target=target,
                check=check,
                severity=severity,
                params=params,
            )
        )

    compiled_rules.sort(key=lambda rule: rule.rule_id)
    compiled = CompiledPolicySet(
        schema_version=canonical["schema_version"],
        policy_set_id=canonical["policy_set_id"],
        policy_revision=canonical["policy_revision"],
        compatibility=canonical["compatibility"],
        version=version,
        rules=tuple(compiled_rules),
        digest=sha256_obj(
            {
                "schema_version": canonical["schema_version"],
                "policy_set_id": canonical["policy_set_id"],
                "policy_revision": canonical["policy_revision"],
                "compatibility": canonical["compatibility"],
                "version": version,
                "rules": [rule.to_dict() for rule in compiled_rules],
            }
        ),
    )

    if trace:
        trace.event(
            "policy.compile",
            {
                "source": source,
                "schema_version": compiled.schema_version,
                "policy_set_id": compiled.policy_set_id,
                "policy_revision": compiled.policy_revision,
                "policy_digest": compiled.digest,
                "rule_count": len(compiled.rules),
            },
        )

    return compiled


def _normalize_policy_document(
    doc: dict[str, Any], source: str, trace: TraceLogger | None
) -> dict[str, Any]:
    schema_version = doc.get("schema_version")

    if schema_version is None:
        return _migrate_legacy_document(doc, source=source, trace=trace)

    if schema_version != LATEST_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version '{schema_version}' in {source}; "
            f"expected '{LATEST_SCHEMA_VERSION}'"
        )

    policy_meta = doc.get("policy")
    rules = doc.get("rules")

    if not isinstance(policy_meta, dict):
        raise ValueError(f"policy metadata in {source} must be a mapping")

    policy_set_id = policy_meta.get("id")
    version = policy_meta.get("version")
    policy_revision = policy_meta.get("revision")
    compatibility = policy_meta.get("compatibility") or {}

    if not isinstance(policy_set_id, str) or not policy_set_id.strip():
        raise ValueError(f"policy.id in {source} must be a non-empty string")
    if not isinstance(version, int):
        raise ValueError(f"policy.version in {source} must be an integer")
    if not isinstance(policy_revision, str) or not policy_revision.strip():
        raise ValueError(f"policy.revision in {source} must be a non-empty string")
    if not isinstance(compatibility, dict):
        raise ValueError(f"policy.compatibility in {source} must be a mapping")

    normalized_compatibility = _normalize_compatibility(compatibility, source=source)

    return {
        "schema_version": schema_version,
        "policy_set_id": policy_set_id,
        "policy_revision": policy_revision,
        "compatibility": normalized_compatibility,
        "version": version,
        "rules": rules,
    }


def _migrate_legacy_document(
    doc: dict[str, Any], source: str, trace: TraceLogger | None
) -> dict[str, Any]:
    version = doc.get("version")
    rules = doc.get("rules")

    if not isinstance(version, int):
        raise ValueError(f"legacy policy version in {source} must be an integer")

    migrated = {
        "schema_version": LATEST_SCHEMA_VERSION,
        "policy_set_id": "legacy.default",
        "policy_revision": f"legacy-{version}",
        "compatibility": {
            "migrated_from": LEGACY_SCHEMA_VERSION,
        },
        "version": version,
        "rules": rules,
    }

    if trace:
        trace.event(
            "policy.migrate",
            {
                "source": source,
                "from_schema": LEGACY_SCHEMA_VERSION,
                "to_schema": LATEST_SCHEMA_VERSION,
                "legacy_version": version,
            },
        )

    return migrated


def _normalize_compatibility(compatibility: dict[str, Any], source: str) -> dict[str, str]:
    allowed_keys = {
        "min_engine_version",
        "max_engine_version",
        "min_policy_version",
        "notes",
    }
    normalized: dict[str, str] = {}

    for key, value in compatibility.items():
        if key not in allowed_keys:
            raise ValueError(f"unsupported compatibility key '{key}' in {source}")
        if not isinstance(value, str):
            raise ValueError(f"compatibility value for '{key}' in {source} must be a string")
        normalized[key] = value

    return normalized
