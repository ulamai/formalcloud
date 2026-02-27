from __future__ import annotations

from typing import Any

from .utils import sha256_obj

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
)


def certificate_to_sarif(
    certificate: dict[str, Any],
    tool_name: str = "FormalCloud",
    include_waived: bool = False,
) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    certificate_id = str(certificate.get("certificate_id", ""))
    target = str(certificate.get("target", ""))

    for rule_result in certificate.get("results") or []:
        rule_id = str(rule_result.get("id", "UNKNOWN"))
        severity = str(rule_result.get("severity", "medium"))
        guideline_url = rule_result.get("guideline_url")
        controls = [
            str(control_id)
            for control_id in (rule_result.get("controls") or [])
            if isinstance(control_id, str)
        ]

        rule_entry: dict[str, Any] = {
            "id": rule_id,
            "name": str(rule_result.get("title", rule_id)),
            "shortDescription": {"text": str(rule_result.get("title", rule_id))},
            "fullDescription": {
                "text": (
                    f"target={rule_result.get('target')} "
                    f"check={rule_result.get('check')} severity={severity}"
                )
            },
            "properties": {
                "severity": severity,
                "target": rule_result.get("target"),
                "check": rule_result.get("check"),
                "controls": controls,
            },
        }
        if isinstance(guideline_url, str) and guideline_url:
            rule_entry["helpUri"] = guideline_url
        if controls:
            rule_entry["properties"]["tags"] = controls
        rules[rule_id] = rule_entry

        for violation in rule_result.get("violations") or []:
            results.append(
                _build_result(
                    rule_id=rule_id,
                    severity=severity,
                    violation=violation,
                    certificate_id=certificate_id,
                    target=target,
                    suppressed=False,
                    suppression_payload=None,
                )
            )

        if include_waived:
            applied_by_entity = {
                item.get("entity"): item for item in rule_result.get("applied_exceptions") or []
            }
            for violation in rule_result.get("waived_violations") or []:
                entity = str(violation.get("entity", ""))
                results.append(
                    _build_result(
                        rule_id=rule_id,
                        severity=severity,
                        violation=violation,
                        certificate_id=certificate_id,
                        target=target,
                        suppressed=True,
                        suppression_payload=applied_by_entity.get(entity),
                    )
                )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/ulamai/formalcloud",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def _build_result(
    rule_id: str,
    severity: str,
    violation: dict[str, Any],
    certificate_id: str,
    target: str,
    suppressed: bool,
    suppression_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    entity = str(violation.get("entity", ""))
    message = str(violation.get("message", "Policy violation"))
    details = violation.get("details") or {}

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _severity_to_level(severity),
        "message": {"text": f"{message} [{entity}]"},
        "properties": {
            "entity": entity,
            "details": details,
            "certificate_id": certificate_id,
            "target": target,
            "severity": severity,
        },
        "partialFingerprints": {
            "formalcloud/entity-rule": sha256_obj(
                {
                    "rule_id": rule_id,
                    "entity": entity,
                    "message": message,
                    "details": details,
                }
            )
        },
    }

    if entity:
        result["locations"] = [
            {
                "logicalLocations": [
                    {
                        "fullyQualifiedName": entity,
                        "name": entity,
                    }
                ]
            }
        ]

    if suppressed:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": _suppression_justification(suppression_payload),
            }
        ]

    return result


def _suppression_justification(suppression_payload: dict[str, Any] | None) -> str:
    if not suppression_payload:
        return "Waived by FormalCloud exception"
    reason = suppression_payload.get("reason")
    owner = suppression_payload.get("owner")
    expires_at = suppression_payload.get("expires_at")
    return f"Waived by exception owner={owner} expires_at={expires_at}: {reason}"


def _severity_to_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity, "warning")
