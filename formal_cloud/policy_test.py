from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .kubernetes import load_and_normalize_manifests
from .policy import compile_policy_file
from .terraform import normalize_plan
from .utils import load_json, load_yaml, write_json
from .verifier import verify_kubernetes, verify_terraform

POLICY_TEST_SCHEMA = "formal-cloud.policy-tests/v1"


def run_policy_tests(cases_path: Path, update_golden: bool) -> dict[str, Any]:
    document = load_yaml(cases_path)
    if not isinstance(document, dict):
        raise ValueError(f"policy test cases in {cases_path} must be a mapping")

    schema = document.get("schema_version")
    if schema is not None and schema != POLICY_TEST_SCHEMA:
        raise ValueError(
            f"unsupported policy test schema '{schema}' in {cases_path}; "
            f"expected '{POLICY_TEST_SCHEMA}'"
        )

    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"policy test cases in {cases_path} must define a non-empty cases list")

    base_dir = cases_path.parent.resolve()
    case_reports: list[dict[str, Any]] = []
    for raw_case in raw_cases:
        case_reports.append(
            _run_case(
                raw_case=raw_case,
                base_dir=base_dir,
                update_golden=update_golden,
            )
        )

    failed_cases = [case for case in case_reports if not case["pass"]]
    return {
        "schema_version": POLICY_TEST_SCHEMA,
        "source": str(cases_path),
        "updated_golden": update_golden,
        "summary": {
            "total_cases": len(case_reports),
            "passed_cases": len(case_reports) - len(failed_cases),
            "failed_cases": len(failed_cases),
            "pass": len(failed_cases) == 0,
        },
        "cases": case_reports,
    }


def _run_case(raw_case: Any, base_dir: Path, update_golden: bool) -> dict[str, Any]:
    if not isinstance(raw_case, dict):
        raise ValueError("each policy test case must be a mapping")

    case_id = _require_str(raw_case, "id")
    target = _require_str(raw_case, "target")
    if target not in {"terraform", "kubernetes"}:
        raise ValueError(f"case '{case_id}' has unsupported target '{target}'")

    policy_path = _resolve_path(base_dir, _require_str(raw_case, "policies"))
    profile = _optional_str(raw_case.get("profile"))
    golden_path = _resolve_path(base_dir, _require_str(raw_case, "golden"))

    compiled = compile_policy_file(policy_path)
    if target == "terraform":
        plan_path = _resolve_path(base_dir, _require_str(raw_case, "plan"))
        workspace = _optional_str(raw_case.get("workspace")) or "default"
        plan = normalize_plan(load_json(plan_path))
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan=plan,
            workspace=workspace,
            profile=profile,
        )
    else:
        manifest_paths = _case_manifest_paths(raw_case, base_dir, case_id)
        manifests = load_and_normalize_manifests(manifest_paths)
        certificate = verify_kubernetes(
            compiled=compiled,
            normalized_manifests=manifests,
            profile=profile,
        )

    stable_actual = _stable_certificate(certificate)
    result: dict[str, Any] = {
        "id": case_id,
        "target": target,
        "decision": certificate.get("decision"),
        "certificate_id": certificate.get("certificate_id"),
        "profile": profile,
        "golden": str(golden_path),
        "updated": False,
        "pass": True,
    }

    if update_golden:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(golden_path, stable_actual)
        result["updated"] = True
        return result

    if not golden_path.exists():
        result["pass"] = False
        result["reason"] = "missing golden file"
        return result

    expected = load_json(golden_path)
    stable_expected = _stable_certificate(expected)
    if stable_expected != stable_actual:
        result["pass"] = False
        result["reason"] = "golden mismatch"
        result["expected_certificate_id"] = stable_expected.get("certificate_id")
        result["actual_certificate_id"] = stable_actual.get("certificate_id")

    return result


def _stable_certificate(certificate: Any) -> Any:
    stable = deepcopy(certificate)
    if isinstance(stable, dict):
        stable["generated_at"] = "1970-01-01T00:00:00Z"
        if "trace_log" in stable:
            stable["trace_log"] = "<trace-log>"
        signature = stable.get("signature")
        if isinstance(signature, dict) and "signed_at" in signature:
            signature["signed_at"] = "1970-01-01T00:00:00Z"
    return stable


def _case_manifest_paths(raw_case: dict[str, Any], base_dir: Path, case_id: str) -> list[Path]:
    manifests = raw_case.get("manifests")
    if manifests is None:
        manifest = raw_case.get("manifest")
        if manifest is None:
            raise ValueError(
                f"case '{case_id}' requires 'manifest' or non-empty 'manifests' for kubernetes target"
            )
        manifests = [manifest]

    if not isinstance(manifests, list) or not manifests:
        raise ValueError(f"case '{case_id}' manifests must be a non-empty list")
    return [_resolve_path(base_dir, str(item)) for item in manifests]


def _resolve_path(base_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (base_dir / path).resolve()


def _require_str(raw_case: dict[str, Any], key: str) -> str:
    value = raw_case.get(key)
    if not isinstance(value, str) or not value.strip():
        case_id = raw_case.get("id", "<unknown>")
        raise ValueError(f"case '{case_id}' field '{key}' must be a non-empty string")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip():
        return value
    raise ValueError("optional string fields must be non-empty strings when provided")
