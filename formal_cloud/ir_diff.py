from __future__ import annotations

from typing import Any

from .models import CompiledPolicySet


def diff_compiled_policies(left: CompiledPolicySet, right: CompiledPolicySet) -> dict[str, Any]:
    left_rules = {rule.rule_id: rule.to_dict() for rule in left.rules}
    right_rules = {rule.rule_id: rule.to_dict() for rule in right.rules}

    left_exceptions = {exc.exception_id: exc.to_dict() for exc in left.exceptions}
    right_exceptions = {exc.exception_id: exc.to_dict() for exc in right.exceptions}

    return {
        "left": _meta(left),
        "right": _meta(right),
        "rules": {
            "added": sorted([rule_id for rule_id in right_rules if rule_id not in left_rules]),
            "removed": sorted([rule_id for rule_id in left_rules if rule_id not in right_rules]),
            "changed": sorted(
                [
                    rule_id
                    for rule_id in left_rules
                    if rule_id in right_rules and left_rules[rule_id] != right_rules[rule_id]
                ]
            ),
        },
        "exceptions": {
            "added": sorted([exc_id for exc_id in right_exceptions if exc_id not in left_exceptions]),
            "removed": sorted([exc_id for exc_id in left_exceptions if exc_id not in right_exceptions]),
            "changed": sorted(
                [
                    exc_id
                    for exc_id in left_exceptions
                    if exc_id in right_exceptions
                    and left_exceptions[exc_id] != right_exceptions[exc_id]
                ]
            ),
        },
        "compatible": left.schema_version == right.schema_version,
    }


def _meta(compiled: CompiledPolicySet) -> dict[str, Any]:
    return {
        "schema_version": compiled.schema_version,
        "policy_set_id": compiled.policy_set_id,
        "policy_revision": compiled.policy_revision,
        "policy_digest": compiled.digest,
        "rule_count": len(compiled.rules),
        "exception_count": len(compiled.exceptions),
    }
