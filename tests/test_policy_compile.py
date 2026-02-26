import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file


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


if __name__ == "__main__":
    unittest.main()
