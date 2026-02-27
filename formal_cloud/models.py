from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyException:
    exception_id: str
    rule_id: str
    reason: str
    owner: str
    expires_at: str
    entity_patterns: tuple[str, ...]
    approved_by: str | None
    ticket: str | None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.exception_id,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "owner": self.owner,
            "expires_at": self.expires_at,
            "entity_patterns": list(self.entity_patterns),
        }
        if self.approved_by:
            value["approved_by"] = self.approved_by
        if self.ticket:
            value["ticket"] = self.ticket
        return value


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    title: str
    target: str
    check: str
    severity: str
    params: dict[str, Any]
    guideline_url: str | None = None
    controls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.rule_id,
            "title": self.title,
            "target": self.target,
            "check": self.check,
            "severity": self.severity,
            "params": self.params,
        }
        if self.guideline_url:
            value["guideline_url"] = self.guideline_url
        if self.controls:
            value["controls"] = list(self.controls)
        return value


@dataclass(frozen=True)
class CompiledPolicySet:
    schema_version: str
    policy_set_id: str
    policy_revision: str
    compatibility: dict[str, Any]
    exception_policy: dict[str, Any]
    rollout: dict[str, Any]
    version: int
    rules: tuple[PolicyRule, ...]
    exceptions: tuple[PolicyException, ...]
    digest: str

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "policy_set_id": self.policy_set_id,
            "policy_revision": self.policy_revision,
            "compatibility": self.compatibility,
            "exception_policy": self.exception_policy,
            "version": self.version,
            "policy_digest": self.digest,
            "rules": [rule.to_dict() for rule in self.rules],
            "exceptions": [exc.to_dict() for exc in self.exceptions],
        }
        if self.rollout:
            value["rollout"] = self.rollout
        return value


@dataclass(frozen=True)
class RuleViolation:
    entity: str
    message: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "message": self.message,
            "details": self.details,
        }


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    title: str
    target: str
    check: str
    severity: str
    guideline_url: str | None
    controls: tuple[str, ...]
    passed: bool
    evaluated_entities: int
    violations: tuple[RuleViolation, ...]
    waived_violations: tuple[RuleViolation, ...]
    applied_exceptions: tuple[dict[str, Any], ...]
    proof: dict[str, Any]
    mode: str = "enforce"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.rule_id,
            "title": self.title,
            "target": self.target,
            "check": self.check,
            "severity": self.severity,
            "passed": self.passed,
            "evaluated_entities": self.evaluated_entities,
            "violations": [v.to_dict() for v in self.violations],
            "waived_violations": [v.to_dict() for v in self.waived_violations],
            "applied_exceptions": list(self.applied_exceptions),
            "proof": self.proof,
        }
        if self.guideline_url:
            value["guideline_url"] = self.guideline_url
        if self.controls:
            value["controls"] = list(self.controls)
        if self.mode != "enforce":
            value["mode"] = self.mode
        return value
