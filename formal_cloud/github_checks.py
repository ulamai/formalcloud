from __future__ import annotations

from typing import Any


def certificate_to_github_checks(certificate: dict[str, Any]) -> dict[str, Any]:
    annotations: list[dict[str, Any]] = []
    max_annotations = 50

    for result in certificate.get("results") or []:
        severity = str(result.get("severity", "medium"))
        level = "failure" if severity in {"high", "critical"} else "warning"

        for violation in result.get("violations") or []:
            annotations.append(
                {
                    "path": "infrastructure",
                    "start_line": 1,
                    "end_line": 1,
                    "annotation_level": level,
                    "title": str(result.get("id", "POLICY")),
                    "message": (
                        f"{violation.get('message')} [{violation.get('entity')}]"
                    ),
                    "raw_details": str(violation.get("details") or {}),
                }
            )
            if len(annotations) >= max_annotations:
                break
        if len(annotations) >= max_annotations:
            break

    summary = certificate.get("summary") or {}
    return {
        "name": "FormalCloud",
        "head_sha": None,
        "status": "completed",
        "conclusion": "success" if certificate.get("decision") == "accept" else "failure",
        "output": {
            "title": f"FormalCloud decision={certificate.get('decision')}",
            "summary": (
                f"rules={summary.get('total_rules')} failed={summary.get('failed_rules')} "
                f"violations={summary.get('total_violations')}"
            ),
            "text": f"certificate_id={certificate.get('certificate_id')}",
            "annotations": annotations,
        },
    }
