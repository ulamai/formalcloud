from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .utils import load_json, sha256_text, utc_now_iso, write_json


def create_evidence_pack(
    certificate_path: Path,
    out_dir: Path,
    trace_path: Path | None = None,
    bundle_report_path: Path | None = None,
    extra_files: list[Path] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    extra_files = extra_files or []

    certificate = load_json(certificate_path)

    copied_files: list[dict[str, Any]] = []
    copied_files.append(_copy_with_hash(certificate_path, out_dir / "certificate.json"))

    if trace_path is not None and trace_path.exists():
        copied_files.append(_copy_with_hash(trace_path, out_dir / "trace.jsonl"))

    if bundle_report_path is not None and bundle_report_path.exists():
        copied_files.append(
            _copy_with_hash(bundle_report_path, out_dir / "bundle-verify-report.json")
        )

    for idx, extra in enumerate(extra_files):
        if not extra.exists():
            continue
        target = out_dir / f"extra-{idx + 1}-{extra.name}"
        copied_files.append(_copy_with_hash(extra, target))

    manifest = {
        "schema_version": "formal-cloud.evidence-pack/v1",
        "generated_at": utc_now_iso(),
        "certificate_id": certificate.get("certificate_id"),
        "decision": certificate.get("decision"),
        "policy": certificate.get("policy"),
        "subject": certificate.get("subject"),
        "summary": certificate.get("summary"),
        "controls": _control_view(certificate),
        "files": copied_files,
    }

    write_json(out_dir / "manifest.json", manifest)
    return manifest


def _copy_with_hash(source: Path, target: Path) -> dict[str, Any]:
    shutil.copy2(source, target)
    text = target.read_text(encoding="utf-8")
    return {
        "source": str(source),
        "path": str(target),
        "sha256": sha256_text(text),
        "bytes": target.stat().st_size,
    }


def _control_view(certificate: dict[str, Any]) -> dict[str, Any]:
    summary = certificate.get("summary") or {}
    coverage = summary.get("control_coverage") or {}
    raw_controls = coverage.get("controls") or []
    if not isinstance(raw_controls, list):
        raw_controls = []

    controls: list[dict[str, Any]] = []
    for control in raw_controls:
        if not isinstance(control, dict):
            continue
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id:
            continue
        status = str(control.get("status") or "unknown")
        controls.append(
            {
                "id": control_id,
                "status": status,
                "rules": sorted(str(rule_id) for rule_id in (control.get("rules") or [])),
                "failed_rules": int(control.get("failed_rules") or 0),
                "passed_rules": int(control.get("passed_rules") or 0),
                "violations": int(control.get("violations") or 0),
                "waived_violations": int(control.get("waived_violations") or 0),
            }
        )

    controls.sort(key=lambda item: item["id"])
    failing_ids = [item["id"] for item in controls if item["status"] == "fail"]
    passing_ids = [item["id"] for item in controls if item["status"] == "pass"]
    return {
        "mapped_controls": len(controls),
        "failing_controls": len(failing_ids),
        "passing_controls": len(passing_ids),
        "failing_control_ids": failing_ids,
        "passing_control_ids": passing_ids,
        "controls": controls,
    }
