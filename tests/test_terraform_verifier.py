import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class TerraformVerifierTests(unittest.TestCase):
    def test_terraform_verification_rejects_insecure_plan(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        normalized = normalize_plan(plan)

        certificate = verify_terraform(compiled, normalized_plan=normalized, workspace="prod")

        self.assertEqual(certificate["decision"], "reject")
        self.assertGreaterEqual(certificate["summary"]["failed_rules"], 3)
        self.assertEqual(certificate["policy"]["schema_version"], "formal-cloud.policy/v1")
        self.assertEqual(certificate["policy"]["policy_set_id"], "org.baseline.cloud-security")
        self.assertEqual(certificate["policy"]["policy_revision"], "1.0.0")

        results = {result["id"]: result for result in certificate["results"]}
        self.assertFalse(results["TF001"]["passed"])
        self.assertFalse(results["TF002"]["passed"])
        self.assertFalse(results["TF003"]["passed"])

    def test_no_destructive_changes_only_applies_to_protected_workspace(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        normalized = normalize_plan(plan)

        certificate = verify_terraform(compiled, normalized_plan=normalized, workspace="dev")

        results = {result["id"]: result for result in certificate["results"]}
        self.assertTrue(results["TF003"]["passed"])


if __name__ == "__main__":
    unittest.main()
