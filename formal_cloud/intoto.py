from __future__ import annotations

from typing import Any


def certificate_to_intoto_statement(
    certificate: dict[str, Any],
    predicate_type: str = "https://formalcloud.dev/attestation/policy-decision/v1",
) -> dict[str, Any]:
    subject = certificate.get("subject") or {}
    policy = certificate.get("policy") or {}

    subject_digest = str(subject.get("digest", ""))
    subject_name = str(subject.get("type", "infrastructure-change"))

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": subject_name,
                "digest": {
                    "sha256": subject_digest,
                },
            }
        ],
        "predicateType": predicate_type,
        "predicate": {
            "tool": {
                "name": "FormalCloud",
            },
            "decision": {
                "certificate_id": certificate.get("certificate_id"),
                "decision": certificate.get("decision"),
                "target": certificate.get("target"),
                "confidence": certificate.get("confidence"),
                "summary": certificate.get("summary"),
            },
            "policy": {
                "policy_set_id": policy.get("policy_set_id"),
                "policy_revision": policy.get("policy_revision"),
                "policy_digest": policy.get("policy_digest"),
                "schema_version": policy.get("schema_version"),
                "exception_count": policy.get("exception_count"),
            },
            "subject_metadata": subject.get("metadata"),
            "results": certificate.get("results"),
        },
    }
