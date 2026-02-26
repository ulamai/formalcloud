import unittest

from formal_cloud.policy import compile_policy_document
from formal_cloud.verifier import verify_terraform


def _single_rule_policy() -> dict:
    return {
        "schema_version": "formal-cloud.policy/v1",
        "policy": {
            "id": "test.confidence",
            "version": 1,
            "revision": "1.0.0",
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
    }


class ConfidenceTests(unittest.TestCase):
    def test_terraform_confidence_proven(self) -> None:
        compiled = compile_policy_document(_single_rule_policy(), source="<test>")
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan={
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.private",
                        "type": "aws_s3_bucket",
                        "actions": ["create"],
                        "after": {"acl": "private"},
                        "after_unknown": {},
                    }
                ]
            },
            workspace="prod",
        )

        self.assertEqual(certificate["confidence"]["class"], "proven")
        self.assertEqual(certificate["summary"]["confidence_class"], "proven")

    def test_terraform_confidence_assumed(self) -> None:
        compiled = compile_policy_document(_single_rule_policy(), source="<test>")
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan={
                "resource_changes": [
                    {
                        "address": "module.storage.aws_s3_bucket.private",
                        "type": "aws_s3_bucket",
                        "actions": ["delete", "create"],
                        "after": {"acl": "private"},
                        "after_unknown": {},
                    }
                ]
            },
            workspace="prod",
        )

        confidence = certificate["confidence"]
        self.assertEqual(confidence["class"], "assumed")
        self.assertEqual(confidence["replace_resource_count"], 1)
        self.assertEqual(confidence["module_resource_count"], 1)

    def test_terraform_confidence_unknown(self) -> None:
        compiled = compile_policy_document(_single_rule_policy(), source="<test>")
        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan={
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.private",
                        "type": "aws_s3_bucket",
                        "actions": ["create"],
                        "after": {"acl": "private"},
                        "after_unknown": {"acl": True},
                    }
                ]
            },
            workspace="prod",
        )

        confidence = certificate["confidence"]
        self.assertEqual(confidence["class"], "unknown")
        self.assertEqual(confidence["unknown_resource_count"], 1)
        self.assertEqual(certificate["summary"]["confidence_class"], "unknown")


if __name__ == "__main__":
    unittest.main()
