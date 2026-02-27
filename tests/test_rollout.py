import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class RolloutProfileTests(unittest.TestCase):
    def test_compile_rollout_profile_policy(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-rollout.yaml"))
        self.assertEqual(compiled.policy_set_id, "org.rollout.cloud-security")
        self.assertEqual(compiled.rollout["controls"]["SOC2-CC6.1"], "audit")
        self.assertEqual(compiled.rollout["profiles"]["prod"]["controls"]["SOC2-CC6.1"], "enforce")
        self.assertEqual(compiled.rollout["profiles"]["dev"]["default_mode"], "audit")

    def test_dev_profile_allows_audit_failures(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-rollout.yaml"))
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))

        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan=plan,
            workspace="dev",
            profile="dev",
        )

        self.assertEqual(certificate["decision"], "accept")
        rollout = certificate["summary"]["rollout"]
        self.assertEqual(rollout["profile"], "dev")
        self.assertEqual(rollout["enforce_failed_rules"], 0)
        self.assertGreaterEqual(rollout["audit_failed_rules"], 2)

        results = {result["id"]: result for result in certificate["results"]}
        self.assertEqual(results["TF001"]["mode"], "audit")
        self.assertEqual(results["TF002"]["mode"], "audit")
        self.assertNotIn("mode", results["TF003"])

    def test_prod_profile_enforces_failures(self) -> None:
        compiled = compile_policy_file(Path("examples/policies-rollout.yaml"))
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))

        certificate = verify_terraform(
            compiled=compiled,
            normalized_plan=plan,
            workspace="prod",
            profile="prod",
        )

        self.assertEqual(certificate["decision"], "reject")
        rollout = certificate["summary"]["rollout"]
        self.assertEqual(rollout["profile"], "prod")
        self.assertGreaterEqual(rollout["enforce_failed_rules"], 3)
        self.assertEqual(rollout["audit_failed_rules"], 0)


if __name__ == "__main__":
    unittest.main()
