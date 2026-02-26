from __future__ import annotations

import statistics
import time
from pathlib import Path
from typing import Any

from .kubernetes import load_and_normalize_manifests
from .policy import compile_policy_file
from .terraform import normalize_plan
from .utils import load_json, load_yaml, utc_now_iso
from .verifier import verify_kubernetes, verify_terraform

BENCHMARK_SCHEMA_VERSION = "formal-cloud.benchmark/v1"


def run_benchmark(cases_file: Path, iterations: int) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    doc = load_yaml(cases_file)
    if not isinstance(doc, dict):
        raise ValueError(f"benchmark corpus in {cases_file} must be a mapping")
    if doc.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported benchmark schema '{doc.get('schema_version')}', "
            f"expected '{BENCHMARK_SCHEMA_VERSION}'"
        )

    raw_cases = doc.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"benchmark corpus in {cases_file} must define non-empty cases")

    base_dir = cases_file.parent
    case_reports: list[dict[str, Any]] = []
    for raw_case in raw_cases:
        case_reports.append(_run_case(raw_case, base_dir=base_dir, iterations=iterations))

    passed_cases = [case for case in case_reports if case["pass"]]
    failed_cases = [case for case in case_reports if not case["pass"]]

    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "cases_file": str(cases_file),
        "iterations": iterations,
        "summary": {
            "total_cases": len(case_reports),
            "passed_cases": len(passed_cases),
            "failed_cases": len(failed_cases),
            "pass": len(failed_cases) == 0,
        },
        "cases": case_reports,
    }


def _run_case(raw_case: Any, base_dir: Path, iterations: int) -> dict[str, Any]:
    if not isinstance(raw_case, dict):
        raise ValueError("every benchmark case must be a mapping")

    case_id = _require_str(raw_case, "id")
    target = _require_str(raw_case, "target")
    expected_decision = _require_str(raw_case, "expected_decision")
    policies_path = _resolve_path(base_dir, _require_str(raw_case, "policies"))

    if target not in {"terraform", "kubernetes"}:
        raise ValueError(f"case '{case_id}' has unsupported target '{target}'")
    if expected_decision not in {"accept", "reject"}:
        raise ValueError(
            f"case '{case_id}' has unsupported expected_decision '{expected_decision}'"
        )

    decisions: list[str] = []
    certificate_ids: list[str] = []
    durations_ms: list[float] = []

    for _ in range(iterations):
        start = time.perf_counter()
        compiled = compile_policy_file(policies_path)

        if target == "terraform":
            plan_path = _resolve_path(base_dir, _require_str(raw_case, "plan"))
            workspace = str(raw_case.get("workspace") or "default")
            plan = load_json(plan_path)
            normalized_plan = normalize_plan(plan)
            certificate = verify_terraform(
                compiled=compiled,
                normalized_plan=normalized_plan,
                workspace=workspace,
                trace=None,
            )
        else:
            manifests = raw_case.get("manifests")
            if not isinstance(manifests, list) or not manifests:
                raise ValueError(f"case '{case_id}' requires non-empty manifests list")
            manifest_paths = [_resolve_path(base_dir, str(path)) for path in manifests]
            normalized = load_and_normalize_manifests(manifest_paths)
            certificate = verify_kubernetes(
                compiled=compiled,
                normalized_manifests=normalized,
                trace=None,
            )

        duration_ms = (time.perf_counter() - start) * 1000.0
        durations_ms.append(duration_ms)
        decisions.append(certificate["decision"])
        certificate_ids.append(certificate["certificate_id"])

    stable_decision = len(set(decisions)) == 1
    stable_certificate = len(set(certificate_ids)) == 1
    expected_match = all(decision == expected_decision for decision in decisions)

    return {
        "id": case_id,
        "target": target,
        "expected_decision": expected_decision,
        "decisions": decisions,
        "certificate_ids": certificate_ids,
        "stable_decision": stable_decision,
        "stable_certificate": stable_certificate,
        "expected_match": expected_match,
        "pass": stable_decision and stable_certificate and expected_match,
        "timing_ms": {
            "min": round(min(durations_ms), 3),
            "max": round(max(durations_ms), 3),
            "mean": round(statistics.mean(durations_ms), 3),
        },
    }


def _resolve_path(base_dir: Path, path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing required string field '{key}'")
    return value
