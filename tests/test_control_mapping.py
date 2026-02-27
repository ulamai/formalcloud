import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_document
from formal_cloud.sarif import certificate_to_sarif
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class ControlMappingTests(unittest.TestCase):
    def _compile_controls_policy(self):
        return compile_policy_document(
            {
                "schema_version": "formal-cloud.policy/v1",
                "policy": {
                    "id": "org.controls.audit",
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
                        "guideline_url": "https://example.com/guides/no-public-s3",
                        "controls": ["SOC2-CC6.1"],
                    },
                    {
                        "id": "TF003",
                        "title": "No destructive changes in protected workspaces",
                        "target": "terraform",
                        "check": "no_destructive_changes",
                        "severity": "high",
                        "params": {"protected_workspaces": ["prod"]},
                        "controls": ["SOC2-CC7.2"],
                    },
                ],
            },
            source="<test-controls>",
        )

    def test_certificate_contains_control_coverage_summary(self) -> None:
        compiled = self._compile_controls_policy()
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))
        certificate = verify_terraform(compiled, normalized_plan=plan, workspace="dev")

        coverage = certificate["summary"]["control_coverage"]
        self.assertEqual(coverage["mapped_controls"], 2)
        self.assertEqual(coverage["failing_controls"], 1)

        controls = {control["id"]: control for control in coverage["controls"]}
        self.assertEqual(controls["SOC2-CC6.1"]["status"], "fail")
        self.assertEqual(controls["SOC2-CC7.2"]["status"], "pass")
        self.assertEqual(controls["SOC2-CC6.1"]["rules"], ["TF001"])

        results = {result["id"]: result for result in certificate["results"]}
        self.assertEqual(results["TF001"]["controls"], ["SOC2-CC6.1"])
        self.assertEqual(
            results["TF001"]["guideline_url"],
            "https://example.com/guides/no-public-s3",
        )

    def test_sarif_includes_rule_controls_and_help_uri(self) -> None:
        compiled = self._compile_controls_policy()
        plan = normalize_plan(load_json(Path("examples/terraform-plan.json")))
        certificate = verify_terraform(compiled, normalized_plan=plan, workspace="prod")
        sarif = certificate_to_sarif(certificate)

        runs = sarif.get("runs") or []
        rules = runs[0]["tool"]["driver"]["rules"]
        by_id = {rule["id"]: rule for rule in rules}

        tf001 = by_id["TF001"]
        self.assertEqual(tf001["helpUri"], "https://example.com/guides/no-public-s3")
        self.assertEqual(tf001["properties"]["controls"], ["SOC2-CC6.1"])
        self.assertEqual(tf001["properties"]["tags"], ["SOC2-CC6.1"])


if __name__ == "__main__":
    unittest.main()
