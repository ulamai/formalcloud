from __future__ import annotations

from typing import Any


def replay_check(
    expected_certificate: dict[str, Any],
    replayed_certificate: dict[str, Any],
) -> dict[str, Any]:
    expected_id = expected_certificate.get("certificate_id")
    replayed_id = replayed_certificate.get("certificate_id")

    expected_decision = expected_certificate.get("decision")
    replayed_decision = replayed_certificate.get("decision")

    checks = [
        {
            "name": "certificate_id",
            "ok": expected_id == replayed_id,
            "expected": expected_id,
            "actual": replayed_id,
        },
        {
            "name": "decision",
            "ok": expected_decision == replayed_decision,
            "expected": expected_decision,
            "actual": replayed_decision,
        },
    ]

    expected_policy_digest = ((expected_certificate.get("policy") or {}).get("policy_digest"))
    replayed_policy_digest = ((replayed_certificate.get("policy") or {}).get("policy_digest"))
    checks.append(
        {
            "name": "policy_digest",
            "ok": expected_policy_digest == replayed_policy_digest,
            "expected": expected_policy_digest,
            "actual": replayed_policy_digest,
        }
    )

    expected_subject_digest = ((expected_certificate.get("subject") or {}).get("digest"))
    replayed_subject_digest = ((replayed_certificate.get("subject") or {}).get("digest"))
    checks.append(
        {
            "name": "subject_digest",
            "ok": expected_subject_digest == replayed_subject_digest,
            "expected": expected_subject_digest,
            "actual": replayed_subject_digest,
        }
    )

    valid = all(check.get("ok") for check in checks)
    return {
        "valid": valid,
        "expected_certificate_id": expected_id,
        "replayed_certificate_id": replayed_id,
        "checks": checks,
    }
