import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file
from formal_cloud.sarif import certificate_to_sarif
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class SarifExportTests(unittest.TestCase):
    def test_export_certificate_to_sarif(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(compiled, normalize_plan(plan), workspace="prod")

        sarif = certificate_to_sarif(certificate, tool_name="FormalCloud")

        self.assertEqual(sarif["version"], "2.1.0")
        runs = sarif.get("runs") or []
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["tool"]["driver"]["name"], "FormalCloud")
        self.assertGreater(len(runs[0].get("results") or []), 0)

        rule_ids = {result.get("ruleId") for result in runs[0].get("results") or []}
        self.assertIn("TF001", rule_ids)
        self.assertIn("TF002", rule_ids)
        self.assertIn("TF003", rule_ids)


if __name__ == "__main__":
    unittest.main()
