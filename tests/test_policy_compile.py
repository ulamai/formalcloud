import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_document, compile_policy_file


class PolicyCompileTests(unittest.TestCase):
    def test_compile_example_policy_set(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        self.assertEqual(compiled.schema_version, "formal-cloud.policy/v1")
        self.assertEqual(compiled.policy_set_id, "org.baseline.cloud-security")
        self.assertEqual(compiled.policy_revision, "1.0.0")
        self.assertEqual(compiled.version, 1)
        self.assertEqual(len(compiled.rules), 7)
        self.assertEqual(len(compiled.exceptions), 0)
        self.assertEqual(len(compiled.digest), 64)

    def test_compile_legacy_policy_set_migrates_to_latest_schema(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-legacy-v0.yaml"))
        self.assertEqual(compiled.schema_version, "formal-cloud.policy/v1")
        self.assertEqual(compiled.policy_set_id, "legacy.default")
        self.assertEqual(compiled.policy_revision, "legacy-1")
        self.assertEqual(compiled.compatibility.get("migrated_from"), "legacy/v0")
        self.assertEqual(compiled.version, 1)
        self.assertEqual(len(compiled.rules), 7)

    def test_compile_policy_with_exceptions(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-with-exceptions.yaml"))
        self.assertEqual(compiled.policy_set_id, "org.baseline.cloud-security.exceptions")
        self.assertEqual(len(compiled.exceptions), 1)
        self.assertEqual(compiled.exceptions[0].rule_id, "TF001")
        self.assertEqual(compiled.exceptions[0].approved_by, "ciso@formalcloud.dev")
        self.assertEqual(compiled.exception_policy.get("max_ttl_days"), 30000)

    def test_compile_policy_rule_with_control_metadata(self) -> None:
        compiled = compile_policy_document(
            {
                "schema_version": "formal-cloud.policy/v1",
                "policy": {
                    "id": "org.controls.example",
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
                        "guideline": "https://example.com/security/tf001",
                        "controls": ["SOC2-CC6.1", "NIST-AC-3", "SOC2-CC6.1"],
                    }
                ],
            },
            source="<test>",
        )

        rule = compiled.rules[0]
        self.assertEqual(rule.guideline_url, "https://example.com/security/tf001")
        self.assertEqual(rule.controls, ("NIST-AC-3", "SOC2-CC6.1"))

    def test_compile_policy_rule_rejects_invalid_controls_type(self) -> None:
        with self.assertRaises(ValueError):
            compile_policy_document(
                {
                    "schema_version": "formal-cloud.policy/v1",
                    "policy": {
                        "id": "org.controls.invalid",
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
                            "controls": "SOC2-CC6.1",
                        }
                    ],
                },
                source="<test>",
            )

    def test_compile_policy_with_rollout_profiles(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-rollout.yaml"))
        self.assertEqual(compiled.rollout["controls"]["SOC2-CC6.1"], "audit")
        self.assertEqual(
            compiled.rollout["profiles"]["prod"]["controls"]["SOC2-CC6.1"],
            "enforce",
        )

    def test_compile_policy_rollout_rejects_unknown_rule_reference(self) -> None:
        with self.assertRaises(ValueError):
            compile_policy_document(
                {
                    "schema_version": "formal-cloud.policy/v1",
                    "policy": {
                        "id": "org.rollout.invalid",
                        "version": 1,
                        "revision": "1.0.0",
                        "compatibility": {},
                        "rollout": {"rules": {"DOES_NOT_EXIST": "audit"}},
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
                },
                source="<test>",
            )


if __name__ == "__main__":
    unittest.main()
