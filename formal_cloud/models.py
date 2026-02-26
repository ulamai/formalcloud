from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    title: str
    target: str
    check: str
    severity: str
    params: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "target": self.target,
            "check": self.check,
            "severity": self.severity,
            "params": self.params,
        }


@dataclass(frozen=True)
class CompiledPolicySet:
    schema_version: str
    policy_set_id: str
    policy_revision: str
    compatibility: dict[str, Any]
    version: int
    rules: tuple[PolicyRule, ...]
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_set_id": self.policy_set_id,
            "policy_revision": self.policy_revision,
            "compatibility": self.compatibility,
            "version": self.version,
            "policy_digest": self.digest,
            "rules": [rule.to_dict() for rule in self.rules],
        }


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
    passed: bool
    evaluated_entities: int
    violations: tuple[RuleViolation, ...]
    proof: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "target": self.target,
            "check": self.check,
            "severity": self.severity,
            "passed": self.passed,
            "evaluated_entities": self.evaluated_entities,
            "violations": [v.to_dict() for v in self.violations],
            "proof": self.proof,
        }
