from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .kyverno_adapter import (
    compile_kyverno_validate_subset_document,
    is_kyverno_policy_document,
)
from .models import CompiledPolicySet, PolicyException, PolicyRule
from .rego_adapter import compile_rego_subset_file
from .trace import TraceLogger
from .utils import load_yaml, sha256_obj

SUPPORTED_CHECKS: dict[str, set[str]] = {
    "terraform": {
        "no_public_s3",
        "require_encryption",
        "no_destructive_changes",
        "disallow_wide_cidr_ingress",
        "disallow_wide_cidr_egress",
        "disallow_ssh_from_internet",
        "disallow_rdp_from_internet",
        "require_s3_versioning",
        "require_s3_bucket_logging",
        "require_rds_backup_retention",
        "require_rds_multi_az",
        "require_rds_deletion_protection",
        "require_imdsv2",
        "require_kms_key_rotation",
        "require_log_retention_min_days",
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
    if trace:
        trace.event("policy.load", {"path": str(path)})
    if path.suffix.lower() == ".rego":
        doc = compile_rego_subset_file(path, trace=trace)
    else:
        doc = load_yaml(path)
        if is_kyverno_policy_document(doc):
            doc = compile_kyverno_validate_subset_document(
                doc,
                source=str(path),
                trace=trace,
            )
    return compile_policy_document(doc, source=str(path), trace=trace)


def compile_policy_document(
    doc: dict[str, Any], source: str = "<memory>", trace: TraceLogger | None = None
) -> CompiledPolicySet:
    if not isinstance(doc, dict):
        raise ValueError(f"policy document in {source} must be a mapping")

    canonical = _normalize_policy_document(doc, source=source, trace=trace)
    version = canonical["version"]
    rules = canonical["rules"]
    exceptions = canonical["exceptions"]
    exception_policy = canonical["exception_policy"]
    rollout = canonical["rollout"]

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
        guideline_url = _read_rule_guideline_url(raw_rule, source=source, rule_id=rule_id)
        controls = _read_rule_controls(raw_rule, source=source, rule_id=rule_id)

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
                guideline_url=guideline_url,
                controls=controls,
            )
        )

    rule_ids = {rule.rule_id for rule in compiled_rules}

    compiled_exceptions = _compile_exceptions(
        exceptions=exceptions,
        rule_ids=rule_ids,
        exception_policy=exception_policy,
        source=source,
        now_utc=datetime.now(timezone.utc),
    )
    normalized_rollout = _normalize_rollout_policy(
        rollout=rollout,
        rule_ids=rule_ids,
        source=source,
    )
    sorted_exceptions = sorted(compiled_exceptions, key=lambda item: item.exception_id)

    compiled_rules.sort(key=lambda rule: rule.rule_id)
    digest_seed: dict[str, Any] = {
        "schema_version": canonical["schema_version"],
        "policy_set_id": canonical["policy_set_id"],
        "policy_revision": canonical["policy_revision"],
        "compatibility": canonical["compatibility"],
        "exception_policy": exception_policy,
        "version": version,
        "rules": [rule.to_dict() for rule in compiled_rules],
        "exceptions": [exc.to_dict() for exc in sorted_exceptions],
    }
    if normalized_rollout:
        digest_seed["rollout"] = normalized_rollout

    compiled = CompiledPolicySet(
        schema_version=canonical["schema_version"],
        policy_set_id=canonical["policy_set_id"],
        policy_revision=canonical["policy_revision"],
        compatibility=canonical["compatibility"],
        exception_policy=exception_policy,
        rollout=normalized_rollout,
        version=version,
        rules=tuple(compiled_rules),
        exceptions=tuple(sorted_exceptions),
        digest=sha256_obj(digest_seed),
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
                "exception_count": len(compiled.exceptions),
                "exception_policy": compiled.exception_policy,
                "rollout_profiles": sorted(compiled.rollout.get("profiles", {}).keys())
                if compiled.rollout
                else [],
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
    exceptions = doc.get("exceptions") or []

    if not isinstance(policy_meta, dict):
        raise ValueError(f"policy metadata in {source} must be a mapping")

    policy_set_id = policy_meta.get("id")
    version = policy_meta.get("version")
    policy_revision = policy_meta.get("revision")
    compatibility = policy_meta.get("compatibility") or {}
    exception_policy = policy_meta.get("exception_policy") or {}
    rollout = policy_meta.get("rollout") or {}

    if not isinstance(policy_set_id, str) or not policy_set_id.strip():
        raise ValueError(f"policy.id in {source} must be a non-empty string")
    if not isinstance(version, int):
        raise ValueError(f"policy.version in {source} must be an integer")
    if not isinstance(policy_revision, str) or not policy_revision.strip():
        raise ValueError(f"policy.revision in {source} must be a non-empty string")
    if not isinstance(compatibility, dict):
        raise ValueError(f"policy.compatibility in {source} must be a mapping")
    if not isinstance(exception_policy, dict):
        raise ValueError(f"policy.exception_policy in {source} must be a mapping")
    if not isinstance(rollout, dict):
        raise ValueError(f"policy.rollout in {source} must be a mapping")

    normalized_compatibility = _normalize_compatibility(compatibility, source=source)
    normalized_exception_policy = _normalize_exception_policy(exception_policy, source=source)

    return {
        "schema_version": schema_version,
        "policy_set_id": policy_set_id,
        "policy_revision": policy_revision,
        "compatibility": normalized_compatibility,
        "exception_policy": normalized_exception_policy,
        "rollout": rollout,
        "version": version,
        "rules": rules,
        "exceptions": exceptions,
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
        "exception_policy": {},
        "rollout": {},
        "version": version,
        "rules": rules,
        "exceptions": [],
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


def _read_rule_guideline_url(raw_rule: dict[str, Any], source: str, rule_id: Any) -> str | None:
    guideline_url = raw_rule.get("guideline_url")
    guideline_alias = raw_rule.get("guideline")
    if guideline_url is not None and guideline_alias is not None and guideline_url != guideline_alias:
        raise ValueError(
            f"rule '{rule_id}' in {source} has conflicting guideline_url and guideline values"
        )
    value = guideline_url if guideline_url is not None else guideline_alias
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"guideline_url for rule '{rule_id}' must be a non-empty string")
    return value


def _read_rule_controls(raw_rule: dict[str, Any], source: str, rule_id: Any) -> tuple[str, ...]:
    controls = raw_rule.get("controls")
    if controls is None:
        return ()
    if not isinstance(controls, list):
        raise ValueError(f"controls for rule '{rule_id}' in {source} must be a list")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in controls:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"every controls entry for rule '{rule_id}' in {source} must be a non-empty string"
            )
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return tuple(sorted(normalized))


def _normalize_rollout_policy(
    rollout: dict[str, Any], rule_ids: set[str], source: str
) -> dict[str, Any]:
    if not rollout:
        return {}
    if not isinstance(rollout, dict):
        raise ValueError(f"policy.rollout in {source} must be a mapping")

    allowed_keys = {"default_mode", "rules", "controls", "profiles"}
    unknown = sorted(key for key in rollout if key not in allowed_keys)
    if unknown:
        raise ValueError(f"unsupported rollout keys in {source}: {unknown}")

    normalized: dict[str, Any] = {}
    default_mode = _normalize_rollout_mode(rollout.get("default_mode"), source=source, scope="policy")
    if default_mode != "enforce":
        normalized["default_mode"] = default_mode

    rules = _normalize_rollout_rules(
        rollout.get("rules") or {},
        rule_ids=rule_ids,
        source=source,
        scope="policy.rules",
    )
    if rules:
        normalized["rules"] = rules

    controls = _normalize_rollout_controls(
        rollout.get("controls") or {},
        source=source,
        scope="policy.controls",
    )
    if controls:
        normalized["controls"] = controls

    profiles = rollout.get("profiles") or {}
    if profiles:
        if not isinstance(profiles, dict):
            raise ValueError(f"policy.rollout.profiles in {source} must be a mapping")
        normalized_profiles: dict[str, Any] = {}
        for profile_name in sorted(profiles):
            raw_profile = profiles[profile_name]
            if not isinstance(profile_name, str) or not profile_name.strip():
                raise ValueError(f"policy.rollout profile names in {source} must be non-empty strings")
            if not isinstance(raw_profile, dict):
                raise ValueError(
                    f"policy.rollout.profiles.{profile_name} in {source} must be a mapping"
                )

            profile_allowed_keys = {"default_mode", "rules", "controls"}
            profile_unknown = sorted(key for key in raw_profile if key not in profile_allowed_keys)
            if profile_unknown:
                raise ValueError(
                    f"unsupported rollout profile keys for '{profile_name}' in {source}: {profile_unknown}"
                )

            normalized_profile: dict[str, Any] = {}
            profile_mode = _normalize_rollout_mode(
                raw_profile.get("default_mode"),
                source=source,
                scope=f"policy.rollout.profiles.{profile_name}",
            )
            if profile_mode != "enforce":
                normalized_profile["default_mode"] = profile_mode

            profile_rules = _normalize_rollout_rules(
                raw_profile.get("rules") or {},
                rule_ids=rule_ids,
                source=source,
                scope=f"policy.rollout.profiles.{profile_name}.rules",
            )
            if profile_rules:
                normalized_profile["rules"] = profile_rules

            profile_controls = _normalize_rollout_controls(
                raw_profile.get("controls") or {},
                source=source,
                scope=f"policy.rollout.profiles.{profile_name}.controls",
            )
            if profile_controls:
                normalized_profile["controls"] = profile_controls

            if normalized_profile:
                normalized_profiles[profile_name] = normalized_profile

        if normalized_profiles:
            normalized["profiles"] = normalized_profiles

    return normalized


def _normalize_rollout_mode(value: Any, source: str, scope: str) -> str:
    if value is None:
        return "enforce"
    if value not in {"audit", "enforce"}:
        raise ValueError(
            f"{scope} in {source} must be one of audit|enforce when provided"
        )
    return value


def _normalize_rollout_rules(
    value: Any, rule_ids: set[str], source: str, scope: str
) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{scope} in {source} must be a mapping")
    normalized: dict[str, str] = {}
    for rule_id in sorted(value):
        if rule_id not in rule_ids:
            raise ValueError(f"{scope} in {source} references unknown rule id '{rule_id}'")
        normalized[rule_id] = _normalize_rollout_mode(value[rule_id], source=source, scope=scope)
    return normalized


def _normalize_rollout_controls(value: Any, source: str, scope: str) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{scope} in {source} must be a mapping")
    normalized: dict[str, str] = {}
    for control_id in sorted(value):
        if not isinstance(control_id, str) or not control_id.strip():
            raise ValueError(f"{scope} in {source} must use non-empty string control ids")
        normalized[control_id] = _normalize_rollout_mode(
            value[control_id], source=source, scope=scope
        )
    return normalized


def _compile_exceptions(
    exceptions: Any,
    rule_ids: set[str],
    exception_policy: dict[str, Any],
    source: str,
    now_utc: datetime,
) -> list[PolicyException]:
    if exceptions is None:
        return []
    if not isinstance(exceptions, list):
        raise ValueError(f"policy exceptions in {source} must be a list")

    compiled: list[PolicyException] = []
    seen_ids: set[str] = set()
    for raw_exception in exceptions:
        if not isinstance(raw_exception, dict):
            raise ValueError(f"each policy exception in {source} must be a mapping")

        exception_id = raw_exception.get("id")
        rule_id = raw_exception.get("rule_id")
        reason = raw_exception.get("reason")
        owner = raw_exception.get("owner")
        expires_at = raw_exception.get("expires_at")
        approved_by = raw_exception.get("approved_by")
        ticket = raw_exception.get("ticket")
        entity_patterns = raw_exception.get("entity_patterns") or ["*"]

        if not isinstance(exception_id, str) or not exception_id.strip():
            raise ValueError(f"exception id in {source} must be a non-empty string")
        if exception_id in seen_ids:
            raise ValueError(f"duplicate exception id '{exception_id}' in {source}")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(
                f"exception '{exception_id}' in {source} must define non-empty rule_id"
            )
        if rule_id not in rule_ids:
            raise ValueError(
                f"exception '{exception_id}' in {source} references unknown rule_id '{rule_id}'"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(
                f"exception '{exception_id}' in {source} must define non-empty reason"
            )
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError(
                f"exception '{exception_id}' in {source} must define non-empty owner"
            )
        normalized_expires_at = _normalize_exception_expiry(
            expires_at, source=source, exception_id=exception_id
        )

        if not isinstance(entity_patterns, list) or not entity_patterns:
            raise ValueError(
                f"exception '{exception_id}' in {source} must define non-empty entity_patterns"
            )
        for pattern in entity_patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(
                    f"exception '{exception_id}' in {source} has invalid entity pattern"
                )

        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError(
                f"exception '{exception_id}' in {source} approved_by must be non-empty string"
            )
        if ticket is not None and (not isinstance(ticket, str) or not ticket.strip()):
            raise ValueError(
                f"exception '{exception_id}' in {source} ticket must be non-empty string"
            )

        _enforce_exception_policy(
            exception_id=exception_id,
            approved_by=approved_by,
            expires_at=normalized_expires_at,
            exception_policy=exception_policy,
            source=source,
            now_utc=now_utc,
        )

        seen_ids.add(exception_id)
        compiled.append(
            PolicyException(
                exception_id=exception_id,
                rule_id=rule_id,
                reason=reason,
                owner=owner,
                expires_at=normalized_expires_at,
                entity_patterns=tuple(entity_patterns),
                approved_by=approved_by,
                ticket=ticket,
            )
        )

    return compiled


def _normalize_exception_expiry(expires_at: Any, source: str, exception_id: str) -> str:
    if isinstance(expires_at, datetime):
        parsed = expires_at
    elif isinstance(expires_at, str) and expires_at.strip():
        try:
            parsed = _parse_exception_expiry(expires_at)
        except ValueError as exc:
            raise ValueError(
                f"exception '{exception_id}' in {source} has invalid expires_at '{expires_at}'"
            ) from exc
    else:
        raise ValueError(
            f"exception '{exception_id}' in {source} must define non-empty expires_at"
        )

    if parsed.tzinfo is None:
        raise ValueError(
            f"exception '{exception_id}' in {source} expires_at must include timezone"
        )

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_exception_expiry(expires_at: str) -> datetime:
    normalized = expires_at.strip()
    normalized = normalized.replace(" UTC", "+00:00")
    normalized = normalized.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid expires_at '{expires_at}'") from exc


def _normalize_exception_policy(exception_policy: dict[str, Any], source: str) -> dict[str, Any]:
    allowed_keys = {"max_ttl_days", "required_approver_regex"}
    normalized: dict[str, Any] = {}

    for key, value in exception_policy.items():
        if key not in allowed_keys:
            raise ValueError(f"unsupported exception_policy key '{key}' in {source}")

        if key == "max_ttl_days":
            if not isinstance(value, int) or value < 1:
                raise ValueError(
                    f"exception_policy.max_ttl_days in {source} must be integer >= 1"
                )
            normalized[key] = value
            continue

        if key == "required_approver_regex":
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"exception_policy.required_approver_regex in {source} must be non-empty string"
                )
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(
                    f"invalid exception_policy.required_approver_regex in {source}: {exc}"
                ) from exc
            normalized[key] = value
            continue

    return normalized


def _enforce_exception_policy(
    exception_id: str,
    approved_by: str,
    expires_at: str,
    exception_policy: dict[str, Any],
    source: str,
    now_utc: datetime,
) -> None:
    approver_pattern = exception_policy.get("required_approver_regex")
    if isinstance(approver_pattern, str) and not re.match(approver_pattern, approved_by):
        raise ValueError(
            f"exception '{exception_id}' in {source} approved_by '{approved_by}' "
            "does not satisfy exception_policy.required_approver_regex"
        )

    max_ttl_days = exception_policy.get("max_ttl_days")
    if isinstance(max_ttl_days, int):
        expiry = _parse_utc_datetime(expires_at)
        max_expiry = now_utc + timedelta(days=max_ttl_days)
        if expiry > max_expiry:
            raise ValueError(
                f"exception '{exception_id}' in {source} exceeds max_ttl_days={max_ttl_days}"
            )


def _parse_utc_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
