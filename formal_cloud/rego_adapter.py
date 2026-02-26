from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .trace import TraceLogger

REGO_SUBSET_SCHEMA_VERSION = "formal-cloud.rego-subset/v1"
POLICY_SCHEMA_VERSION = "formal-cloud.policy/v1"

_NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")


def compile_rego_subset_file(path: Path, trace: TraceLogger | None = None) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8").splitlines()

    policy_meta: dict[str, Any] = {
        "id": f"rego.{path.stem}",
        "version": 1,
        "revision": "rego-1",
        "compatibility": {},
    }
    pending_rule_meta: dict[str, Any] = {}
    rules: list[dict[str, Any]] = []

    line_no = 0
    while line_no < len(lines):
        stripped = lines[line_no].strip()

        if not stripped:
            line_no += 1
            continue

        metadata = _parse_metadata_line(stripped)
        if metadata is not None:
            key, value = metadata
            if key.startswith("policy."):
                _assign_policy_meta(policy_meta, key, value, path=path, line_no=line_no + 1)
            else:
                pending_rule_meta[key] = value
            line_no += 1
            continue

        if stripped.startswith("package ") or stripped.startswith("import "):
            line_no += 1
            continue

        if _is_deny_start(stripped):
            if not pending_rule_meta:
                raise ValueError(
                    f"deny rule in {path}:{line_no + 1} is missing metadata annotations "
                    "(expected '# fc.id', '# fc.target', '# fc.check')"
                )

            rules.append(_build_rule_from_meta(pending_rule_meta, path=path, line_no=line_no + 1))
            pending_rule_meta = {}
            line_no = _skip_rule_block(lines, line_no, path)
            continue

        if pending_rule_meta:
            raise ValueError(
                f"metadata block in {path} is not followed by a deny rule "
                f"(unexpected line {line_no + 1}: {stripped})"
            )

        line_no += 1

    if pending_rule_meta:
        raise ValueError(f"trailing metadata block in {path} without deny rule")
    if not rules:
        raise ValueError(f"rego policy in {path} contains no deny rules")

    compatibility = dict(policy_meta["compatibility"])
    if "notes" not in compatibility:
        compatibility["notes"] = f"compiled from {REGO_SUBSET_SCHEMA_VERSION}"

    canonical = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy": {
            "id": policy_meta["id"],
            "version": policy_meta["version"],
            "revision": policy_meta["revision"],
            "compatibility": compatibility,
        },
        "rules": rules,
    }

    if trace:
        trace.event(
            "policy.adapter.rego",
            {
                "source": str(path),
                "rego_schema": REGO_SUBSET_SCHEMA_VERSION,
                "rule_count": len(rules),
            },
        )

    return canonical


def _parse_metadata_line(line: str) -> tuple[str, Any] | None:
    body = _strip_comment(line)
    if body is None:
        return None

    prefixes = ("fc.", "formalcloud.")
    for prefix in prefixes:
        if body.startswith(prefix):
            payload = body[len(prefix) :].strip()
            break
    else:
        return None

    if ":" not in payload:
        raise ValueError(
            "metadata comment must use 'key: value' format, "
            f"got '{line}'"
        )

    raw_key, raw_value = payload.split(":", maxsplit=1)
    key = raw_key.strip()
    if not key:
        raise ValueError(f"metadata key cannot be empty in '{line}'")

    value = _parse_literal(raw_value.strip())
    return key, value


def _strip_comment(line: str) -> str | None:
    if line.startswith("#"):
        return line[1:].strip()
    if line.startswith("//"):
        return line[2:].strip()
    return None


def _parse_literal(value: str) -> Any:
    if not value:
        return ""

    candidate = value.strip()
    if candidate[0] in "{[\"" or candidate in {"true", "false", "null"}:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return candidate

    if _NUMERIC_RE.match(candidate):
        try:
            if "." in candidate:
                return float(candidate)
            return int(candidate)
        except ValueError:
            return candidate

    return candidate


def _assign_policy_meta(
    policy_meta: dict[str, Any],
    key: str,
    value: Any,
    path: Path,
    line_no: int,
) -> None:
    suffix = key[len("policy.") :]

    if suffix == "id":
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"policy id in {path}:{line_no} must be a non-empty string")
        policy_meta["id"] = value
        return

    if suffix == "version":
        if not isinstance(value, int):
            raise ValueError(f"policy version in {path}:{line_no} must be an integer")
        policy_meta["version"] = value
        return

    if suffix == "revision":
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"policy revision in {path}:{line_no} must be a non-empty string")
        policy_meta["revision"] = value
        return

    compatibility_key_map = {
        "min_engine_version": "min_engine_version",
        "max_engine_version": "max_engine_version",
        "min_policy_version": "min_policy_version",
        "notes": "notes",
    }
    if suffix in compatibility_key_map:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"policy compatibility value in {path}:{line_no} for '{suffix}' "
                "must be a non-empty string"
            )
        policy_meta["compatibility"][compatibility_key_map[suffix]] = value
        return

    raise ValueError(f"unsupported policy metadata key 'policy.{suffix}' in {path}:{line_no}")


def _build_rule_from_meta(meta: dict[str, Any], path: Path, line_no: int) -> dict[str, Any]:
    required_keys = ("id", "target", "check")
    missing = [key for key in required_keys if key not in meta]
    if missing:
        raise ValueError(
            f"missing required metadata keys {missing} in {path}:{line_no} for deny rule"
        )

    rule_id = meta["id"]
    target = meta["target"]
    check = meta["check"]
    title = meta.get("title") or str(rule_id)
    severity = meta.get("severity", "medium")
    params = meta.get("params", {})

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError(f"rule id in {path}:{line_no} must be a non-empty string")
    if not isinstance(target, str) or not target.strip():
        raise ValueError(f"rule target in {path}:{line_no} must be a non-empty string")
    if not isinstance(check, str) or not check.strip():
        raise ValueError(f"rule check in {path}:{line_no} must be a non-empty string")
    if not isinstance(title, str):
        raise ValueError(f"rule title in {path}:{line_no} must be a string")
    if not isinstance(severity, str) or not severity.strip():
        raise ValueError(f"rule severity in {path}:{line_no} must be a non-empty string")
    if not isinstance(params, dict):
        raise ValueError(
            f"rule params in {path}:{line_no} must be a JSON object (dictionary)"
        )

    return {
        "id": rule_id,
        "title": title,
        "target": target,
        "check": check,
        "severity": severity,
        "params": params,
    }


def _is_deny_start(line: str) -> bool:
    return line.startswith("deny") and "{" in line


def _skip_rule_block(lines: list[str], start_line: int, path: Path) -> int:
    line_no = start_line
    brace_depth = 0
    saw_open = False

    while line_no < len(lines):
        line = lines[line_no]
        opens = line.count("{")
        closes = line.count("}")
        if opens > 0:
            saw_open = True
        brace_depth += opens
        brace_depth -= closes
        line_no += 1

        if saw_open and brace_depth <= 0:
            return line_no

    raise ValueError(
        f"unterminated deny rule block in {path} starting around line {start_line + 1}"
    )
