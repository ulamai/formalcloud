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


if __name__ == "__main__":
    unittest.main()
