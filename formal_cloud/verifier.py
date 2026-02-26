from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Any

from . import kubernetes, terraform
from .models import CompiledPolicySet, PolicyException, PolicyRule, RuleResult, RuleViolation
from .trace import TraceLogger
from .utils import sha256_obj, utc_now_iso


def compute_certificate_id(
    policy_digest: str,
    target: str,
    subject_type: str,
    subject_digest: str,
    results: list[dict[str, Any]],
    decision: str,
) -> str:
    certificate_seed = {
        "policy_digest": policy_digest,
        "target": target,
        "subject_type": subject_type,
        "subject_digest": subject_digest,
        "results": results,
        "decision": decision,
    }
    return sha256_obj(certificate_seed)


def compute_certificate_id_from_certificate(certificate: dict[str, Any]) -> str:
    policy = certificate.get("policy") or {}
    subject = certificate.get("subject") or {}
    return compute_certificate_id(
        policy_digest=policy["policy_digest"],
        target=certificate["target"],
        subject_type=subject["type"],
        subject_digest=subject["digest"],
        results=certificate["results"],
        decision=certificate["decision"],
    )


def verify_terraform(
    compiled: CompiledPolicySet,
    normalized_plan: dict[str, Any],
    workspace: str,
    trace: TraceLogger | None = None,
) -> dict[str, Any]:
    resource_changes = normalized_plan.get("resource_changes") or []
    rules = [rule for rule in compiled.rules if rule.target == "terraform"]
    if not rules:
        raise ValueError("no terraform rules found in policy set")

    subject_digest = sha256_obj(normalized_plan)
    if trace:
        trace.event(
            "verify.terraform.start",
            {
                "workspace": workspace,
                "resource_change_count": len(resource_changes),
                "subject_digest": subject_digest,
            },
        )

    evaluation_time = datetime.now(timezone.utc)
    results: list[RuleResult] = []
    for rule in rules:
        if trace:
            trace.event("verify.rule.start", {"rule_id": rule.rule_id, "check": rule.check})

        if rule.check == "no_public_s3":
            violations = terraform.check_no_public_s3(resource_changes)
        elif rule.check == "require_encryption":
            violations = terraform.check_require_encryption(resource_changes, rule.params)
        elif rule.check == "no_destructive_changes":
            protected_workspaces = rule.params.get("protected_workspaces") or []
            violations = terraform.check_no_destructive_changes(
                resource_changes,
                workspace=workspace,
                protected_workspaces=protected_workspaces,
            )
        else:
            raise ValueError(f"unsupported terraform check: {rule.check}")

        active_rule_exceptions = _active_rule_exceptions(
            compiled.exceptions, rule.rule_id, evaluation_time
        )
        effective_violations, waived_violations, applied_exceptions = _apply_exceptions(
            violations=violations,
            exceptions=active_rule_exceptions,
        )

        result = _build_rule_result(
            rule=rule,
            evaluated_entities=len(resource_changes),
            violations=effective_violations,
            waived_violations=waived_violations,
            applied_exceptions=applied_exceptions,
            subject_digest=subject_digest,
        )
        if trace:
            trace.event(
                "verify.rule.finish",
                {
                    "rule_id": rule.rule_id,
                    "passed": result.passed,
                    "violation_count": len(result.violations),
                    "waived_violation_count": len(result.waived_violations),
                },
            )
        results.append(result)

    return _build_certificate(
        compiled=compiled,
        target="terraform",
        subject_type="terraform_plan",
        subject_digest=subject_digest,
        subject_metadata={
            "workspace": workspace,
            "resource_change_count": len(resource_changes),
        },
        results=results,
    )


def verify_kubernetes(
    compiled: CompiledPolicySet,
    normalized_manifests: dict[str, Any],
    trace: TraceLogger | None = None,
) -> dict[str, Any]:
    resources = normalized_manifests.get("resources") or []
    rules = [rule for rule in compiled.rules if rule.target == "kubernetes"]
    if not rules:
        raise ValueError("no kubernetes rules found in policy set")

    subject_digest = sha256_obj(normalized_manifests)
    if trace:
        trace.event(
            "verify.kubernetes.start",
            {
                "resource_count": len(resources),
                "subject_digest": subject_digest,
            },
        )

    evaluation_time = datetime.now(timezone.utc)
    results: list[RuleResult] = []
    for rule in rules:
        if trace:
            trace.event("verify.rule.start", {"rule_id": rule.rule_id, "check": rule.check})

        if rule.check == "no_privileged_containers":
            violations = kubernetes.check_no_privileged_containers(resources)
        elif rule.check == "require_resources_limits":
            violations = kubernetes.check_require_resources_limits(resources)
        elif rule.check == "disallow_latest_tag":
            violations = kubernetes.check_disallow_latest_tag(resources)
        elif rule.check == "require_non_root":
            violations = kubernetes.check_require_non_root(resources)
        else:
            raise ValueError(f"unsupported kubernetes check: {rule.check}")

        active_rule_exceptions = _active_rule_exceptions(
            compiled.exceptions, rule.rule_id, evaluation_time
        )
        effective_violations, waived_violations, applied_exceptions = _apply_exceptions(
            violations=violations,
            exceptions=active_rule_exceptions,
        )

        result = _build_rule_result(
            rule=rule,
            evaluated_entities=len(resources),
            violations=effective_violations,
            waived_violations=waived_violations,
            applied_exceptions=applied_exceptions,
            subject_digest=subject_digest,
        )
        if trace:
            trace.event(
                "verify.rule.finish",
                {
                    "rule_id": rule.rule_id,
                    "passed": result.passed,
                    "violation_count": len(result.violations),
                    "waived_violation_count": len(result.waived_violations),
                },
            )
        results.append(result)

    return _build_certificate(
        compiled=compiled,
        target="kubernetes",
        subject_type="kubernetes_manifests",
        subject_digest=subject_digest,
        subject_metadata={"resource_count": len(resources)},
        results=results,
    )


def _build_rule_result(
    rule: PolicyRule,
    evaluated_entities: int,
    violations: list[RuleViolation],
    waived_violations: list[RuleViolation],
    applied_exceptions: list[dict[str, Any]],
    subject_digest: str,
) -> RuleResult:
    sorted_violations = tuple(sorted(violations, key=lambda item: (item.entity, item.message)))
    sorted_waived_violations = tuple(
        sorted(waived_violations, key=lambda item: (item.entity, item.message))
    )
    sorted_applied_exceptions = tuple(
        sorted(applied_exceptions, key=lambda item: (item["exception_id"], item["entity"]))
    )
    proof_input = {
        "rule": rule.to_dict(),
        "subject_digest": subject_digest,
        "applied_exceptions": list(sorted_applied_exceptions),
        "violations": [violation.to_dict() for violation in sorted_violations],
        "waived_violations": [violation.to_dict() for violation in sorted_waived_violations],
    }

    proof = {
        "proof_type": "deterministic-rule-evaluation",
        "engine": "formal-cloud-mvp",
        "rule_hash": sha256_obj(rule.to_dict()),
        "violations_hash": sha256_obj([v.to_dict() for v in sorted_violations]),
        "waived_violations_hash": sha256_obj(
            [v.to_dict() for v in sorted_waived_violations]
        ),
        "applied_exceptions_hash": sha256_obj(list(sorted_applied_exceptions)),
        "proof_hash": sha256_obj(proof_input),
        "passed": len(sorted_violations) == 0,
    }

    return RuleResult(
        rule_id=rule.rule_id,
        title=rule.title,
        target=rule.target,
        check=rule.check,
        severity=rule.severity,
        passed=len(sorted_violations) == 0,
        evaluated_entities=evaluated_entities,
        violations=sorted_violations,
        waived_violations=sorted_waived_violations,
        applied_exceptions=sorted_applied_exceptions,
        proof=proof,
    )


def _build_certificate(
    compiled: CompiledPolicySet,
    target: str,
    subject_type: str,
    subject_digest: str,
    subject_metadata: dict[str, Any],
    results: list[RuleResult],
) -> dict[str, Any]:
    sorted_results = sorted(results, key=lambda item: item.rule_id)
    result_dicts = [result.to_dict() for result in sorted_results]

    failed_rules = [result for result in sorted_results if not result.passed]
    decision = "accept" if not failed_rules else "reject"

    summary = {
        "total_rules": len(sorted_results),
        "passed_rules": len(sorted_results) - len(failed_rules),
        "failed_rules": len(failed_rules),
        "total_violations": sum(len(result.violations) for result in sorted_results),
        "total_waived_violations": sum(
            len(result.waived_violations) for result in sorted_results
        ),
    }

    certificate_id = compute_certificate_id(
        policy_digest=compiled.digest,
        target=target,
        subject_type=subject_type,
        subject_digest=subject_digest,
        results=result_dicts,
        decision=decision,
    )

    return {
        "schema_version": "formal-cloud/v1",
        "certificate_id": certificate_id,
        "generated_at": utc_now_iso(),
        "target": target,
        "decision": decision,
        "policy": {
            "schema_version": compiled.schema_version,
            "policy_set_id": compiled.policy_set_id,
            "policy_revision": compiled.policy_revision,
            "compatibility": compiled.compatibility,
            "version": compiled.version,
            "policy_digest": compiled.digest,
            "exception_count": len(compiled.exceptions),
        },
        "subject": {
            "type": subject_type,
            "digest": subject_digest,
            "metadata": subject_metadata,
        },
        "summary": summary,
        "results": result_dicts,
    }


def _active_rule_exceptions(
    exceptions: tuple[PolicyException, ...], rule_id: str, evaluation_time: datetime
) -> list[PolicyException]:
    active: list[PolicyException] = []
    for exception in exceptions:
        if exception.rule_id != rule_id:
            continue
        expiry = _parse_utc_datetime(exception.expires_at)
        if expiry <= evaluation_time:
            continue
        active.append(exception)
    return active


def _apply_exceptions(
    violations: list[RuleViolation],
    exceptions: list[PolicyException],
) -> tuple[list[RuleViolation], list[RuleViolation], list[dict[str, Any]]]:
    remaining: list[RuleViolation] = []
    waived: list[RuleViolation] = []
    applied: list[dict[str, Any]] = []

    for violation in violations:
        matched_exception = _match_exception(violation, exceptions)
        if matched_exception is None:
            remaining.append(violation)
            continue

        waived.append(violation)
        applied.append(
            {
                "exception_id": matched_exception.exception_id,
                "rule_id": matched_exception.rule_id,
                "entity": violation.entity,
                "reason": matched_exception.reason,
                "owner": matched_exception.owner,
                "expires_at": matched_exception.expires_at,
                "approved_by": matched_exception.approved_by,
                "ticket": matched_exception.ticket,
            }
        )

    return remaining, waived, applied


def _match_exception(
    violation: RuleViolation, exceptions: list[PolicyException]
) -> PolicyException | None:
    for exception in exceptions:
        if any(fnmatch.fnmatch(violation.entity, pattern) for pattern in exception.entity_patterns):
            return exception
    return None


def _parse_utc_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
