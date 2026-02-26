from __future__ import annotations

from pathlib import Path
from typing import Any

from .trace import TraceLogger

KYVERNO_ADAPTER_SCHEMA = "formal-cloud.kyverno-subset/v1"
POLICY_SCHEMA_VERSION = "formal-cloud.policy/v1"


def is_kyverno_policy_document(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False

    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    if not isinstance(api_version, str) or not isinstance(kind, str):
        return False

    return api_version.startswith("kyverno.io/") and kind in {"ClusterPolicy", "Policy"}


def compile_kyverno_validate_subset_document(
    doc: dict[str, Any],
    *,
    source: str,
    trace: TraceLogger | None,
) -> dict[str, Any]:
    if not is_kyverno_policy_document(doc):
        raise ValueError(f"document in {source} is not a supported Kyverno policy")

    metadata = doc.get("metadata") or {}
    annotations = metadata.get("annotations") or {}
    spec = doc.get("spec") or {}

    policy_name = str(metadata.get("name") or Path(source).stem)
    policy_id = _annotation_string(annotations, "formalcloud.io/policy-id") or f"kyverno.{policy_name}"
    policy_version = _annotation_int(annotations, "formalcloud.io/policy-version") or 1
    policy_revision = (
        _annotation_string(annotations, "formalcloud.io/policy-revision") or "kyverno-1"
    )

    compatibility: dict[str, str] = {
        "notes": f"compiled from {KYVERNO_ADAPTER_SCHEMA}",
    }
    min_engine_version = _annotation_string(annotations, "formalcloud.io/min-engine-version")
    if min_engine_version:
        compatibility["min_engine_version"] = min_engine_version

    raw_rules = spec.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError(f"Kyverno policy in {source} must define non-empty spec.rules")

    compiled_rules: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            continue

        rule_name = str(raw_rule.get("name") or f"rule-{index + 1}")
        validate = raw_rule.get("validate")
        if not isinstance(validate, dict):
            continue

        checks = _extract_checks_from_validate(validate)
        if not checks:
            continue

        title_base = str(validate.get("message") or rule_name)
        severity = _extract_severity(raw_rule=raw_rule, policy_annotations=annotations)

        for check in sorted(checks):
            rule_id = _build_rule_id(rule_name, check)
            if rule_id in seen_rule_ids:
                rule_id = f"{rule_id}_{len(seen_rule_ids)}"

            compiled_rules.append(
                {
                    "id": rule_id,
                    "title": f"{title_base} [{check}]",
                    "target": "kubernetes",
                    "check": check,
                    "severity": severity,
                    "params": {},
                }
            )
            seen_rule_ids.add(rule_id)

    if not compiled_rules:
        raise ValueError(
            f"Kyverno policy in {source} did not produce supported validate-subset rules"
        )

    canonical = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy": {
            "id": policy_id,
            "version": policy_version,
            "revision": policy_revision,
            "compatibility": compatibility,
        },
        "rules": compiled_rules,
        "exceptions": [],
    }

    if trace:
        trace.event(
            "policy.adapter.kyverno",
            {
                "source": source,
                "adapter_schema": KYVERNO_ADAPTER_SCHEMA,
                "policy_id": policy_id,
                "rule_count": len(compiled_rules),
            },
        )

    return canonical


def _extract_checks_from_validate(validate: dict[str, Any]) -> set[str]:
    checks: set[str] = set()

    pattern = validate.get("pattern")
    if isinstance(pattern, dict):
        if _contains_field_with_exact_value(pattern, "privileged", False):
            checks.add("no_privileged_containers")
        if _contains_resource_limits(pattern):
            checks.add("require_resources_limits")
        if _contains_field_with_exact_value(pattern, "runAsNonRoot", True):
            checks.add("require_non_root")
        if _contains_disallow_latest(pattern):
            checks.add("disallow_latest_tag")

    deny = validate.get("deny")
    if isinstance(deny, dict) and _contains_disallow_latest(deny):
        checks.add("disallow_latest_tag")

    return checks


def _contains_field_with_exact_value(data: Any, key: str, value: Any) -> bool:
    if isinstance(data, dict):
        if data.get(key) == value:
            return True
        return any(_contains_field_with_exact_value(item, key, value) for item in data.values())
    if isinstance(data, list):
        return any(_contains_field_with_exact_value(item, key, value) for item in data)
    return False


def _contains_resource_limits(data: Any) -> bool:
    if isinstance(data, dict):
        resources = data.get("resources")
        if isinstance(resources, dict):
            limits = resources.get("limits")
            if isinstance(limits, dict) and "cpu" in limits and "memory" in limits:
                return True
        return any(_contains_resource_limits(item) for item in data.values())
    if isinstance(data, list):
        return any(_contains_resource_limits(item) for item in data)
    return False


def _contains_disallow_latest(data: Any) -> bool:
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "image" and isinstance(value, str) and _image_value_disallows_latest(value):
                return True
            if _contains_disallow_latest(value):
                return True
        return False

    if isinstance(data, list):
        return any(_contains_disallow_latest(item) for item in data)

    if isinstance(data, str):
        return _image_value_disallows_latest(data)

    return False


def _image_value_disallows_latest(value: str) -> bool:
    normalized = value.strip()
    return normalized.startswith("!") and ":latest" in normalized


def _extract_severity(raw_rule: dict[str, Any], policy_annotations: dict[str, Any]) -> str:
    allowed = {"low", "medium", "high", "critical"}

    rule_severity = raw_rule.get("severity")
    if isinstance(rule_severity, str) and rule_severity.lower() in allowed:
        return rule_severity.lower()

    policy_severity = policy_annotations.get("policies.kyverno.io/severity")
    if isinstance(policy_severity, str) and policy_severity.lower() in allowed:
        return policy_severity.lower()

    return "medium"


def _build_rule_id(rule_name: str, check: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in rule_name).strip("_")
    if not cleaned:
        cleaned = "rule"
    return f"KYV_{cleaned}_{check}"


def _annotation_string(annotations: dict[str, Any], key: str) -> str | None:
    value = annotations.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"annotation {key} must be a non-empty string")
    return value


def _annotation_int(annotations: dict[str, Any], key: str) -> int | None:
    value = annotations.get(key)
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError(f"annotation {key} must be an integer")
