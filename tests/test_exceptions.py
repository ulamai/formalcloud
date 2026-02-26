import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_document
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class ExceptionModelTests(unittest.TestCase):
    def test_active_exception_waives_matching_violation(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.exceptions",
                "version": 1,
                "revision": "1",
                "compatibility": {},
                "exception_policy": {
                    "required_approver_regex": r"^[^@]+@example\.com$",
                    "max_ttl_days": 50000,
                },
            },
            "rules": [
                {
                    "id": "TF001",
                    "title": "No public S3 buckets",
                    "target": "terraform",
                    "check": "no_public_s3",
                    "severity": "critical",
                }
            ],
            "exceptions": [
                {
                    "id": "EXC-TF001-1",
                    "rule_id": "TF001",
                    "owner": "security@example.com",
                    "reason": "Temporary migration waiver",
                    "approved_by": "approver@example.com",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "entity_patterns": ["aws_s3_bucket.public_assets"],
                }
            ],
        }

        compiled = compile_policy_document(policy_doc, source="<test>")
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan=normalize_plan(plan),
            workspace="prod",
        )

        self.assertEqual(certificate["decision"], "accept")
        result = certificate["results"][0]
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["violations"]), 0)
        self.assertEqual(len(result["waived_violations"]), 1)
        self.assertEqual(len(result["applied_exceptions"]), 1)

    def test_expired_exception_is_not_applied(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.exceptions.expired",
                "version": 1,
                "revision": "1",
                "compatibility": {},
                "exception_policy": {
                    "required_approver_regex": r"^[^@]+@example\.com$",
                    "max_ttl_days": 50000,
                },
            },
            "rules": [
                {
                    "id": "TF001",
                    "title": "No public S3 buckets",
                    "target": "terraform",
                    "check": "no_public_s3",
                    "severity": "critical",
                }
            ],
            "exceptions": [
                {
                    "id": "EXC-TF001-EXPIRED",
                    "rule_id": "TF001",
                    "owner": "security@example.com",
                    "reason": "Expired exception",
                    "approved_by": "approver@example.com",
                    "expires_at": "2001-01-01T00:00:00Z",
                    "entity_patterns": ["aws_s3_bucket.public_assets"],
                }
            ],
        }

        compiled = compile_policy_document(policy_doc, source="<test>")
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan=normalize_plan(plan),
            workspace="prod",
        )

        self.assertEqual(certificate["decision"], "reject")
        result = certificate["results"][0]
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(len(result["waived_violations"]), 0)

    def test_exception_requires_approved_by(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.exceptions.invalid",
                "version": 1,
                "revision": "1",
                "compatibility": {},
            },
            "rules": [
                {
                    "id": "TF001",
                    "title": "No public S3 buckets",
                    "target": "terraform",
                    "check": "no_public_s3",
                    "severity": "critical",
                }
            ],
            "exceptions": [
                {
                    "id": "EXC-TF001-INVALID",
                    "rule_id": "TF001",
                    "owner": "security@example.com",
                    "reason": "Missing approver",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "entity_patterns": ["aws_s3_bucket.public_assets"],
                }
            ],
        }

        with self.assertRaises(ValueError):
            compile_policy_document(policy_doc, source="<test>")

    def test_exception_policy_rejects_non_matching_approver(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.exceptions.approver",
                "version": 1,
                "revision": "1",
                "compatibility": {},
                "exception_policy": {
                    "required_approver_regex": r"^[^@]+@formalcloud\.dev$",
                    "max_ttl_days": 50000,
                },
            },
            "rules": [
                {
                    "id": "TF001",
                    "title": "No public S3 buckets",
                    "target": "terraform",
                    "check": "no_public_s3",
                    "severity": "critical",
                }
            ],
            "exceptions": [
                {
                    "id": "EXC-TF001-APPROVER",
                    "rule_id": "TF001",
                    "owner": "security@example.com",
                    "reason": "Bad approver format",
                    "approved_by": "approver@example.com",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "entity_patterns": ["aws_s3_bucket.public_assets"],
                }
            ],
        }

        with self.assertRaises(ValueError):
            compile_policy_document(policy_doc, source="<test>")

    def test_exception_policy_rejects_ttl_over_max(self) -> None:
        policy_doc = {
            "schema_version": "formal-cloud.policy/v1",
            "policy": {
                "id": "test.exceptions.ttl",
                "version": 1,
                "revision": "1",
                "compatibility": {},
                "exception_policy": {
                    "required_approver_regex": r"^[^@]+@example\.com$",
                    "max_ttl_days": 1,
                },
            },
            "rules": [
                {
                    "id": "TF001",
                    "title": "No public S3 buckets",
                    "target": "terraform",
                    "check": "no_public_s3",
                    "severity": "critical",
                }
            ],
            "exceptions": [
                {
                    "id": "EXC-TF001-LONGTTL",
                    "rule_id": "TF001",
                    "owner": "security@example.com",
                    "reason": "TTL too long",
                    "approved_by": "approver@example.com",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "entity_patterns": ["aws_s3_bucket.public_assets"],
                }
            ],
        }

        with self.assertRaises(ValueError):
            compile_policy_document(policy_doc, source="<test>")


if __name__ == "__main__":
    unittest.main()
