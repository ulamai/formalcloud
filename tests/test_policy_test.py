import tempfile
import unittest
from pathlib import Path

from formal_cloud.cli import main
from formal_cloud.utils import load_json, write_json


class PolicyTestCommandTests(unittest.TestCase):
    def test_policy_test_update_and_verify_golden(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cases = root / "policy-tests.yaml"
            report = root / "policy-tests-report.json"
            golden = root / "golden" / "terraform-dev.json"
            rollout_policy = Path("examples/policies-rollout.yaml").resolve()
            terraform_plan = Path("examples/terraform-plan.json").resolve()

            cases.write_text(
                "\n".join(
                    [
                        "schema_version: formal-cloud.policy-tests/v1",
                        "cases:",
                        "  - id: terraform_dev_rollout",
                        "    target: terraform",
                        f"    policies: {rollout_policy}",
                        f"    plan: {terraform_plan}",
                        "    workspace: dev",
                        "    profile: dev",
                        "    golden: golden/terraform-dev.json",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            update_rc = main(
                [
                    "policy",
                    "test",
                    "--cases",
                    str(cases),
                    "--out",
                    str(report),
                    "--update-golden",
                ]
            )
            self.assertEqual(update_rc, 0)
            self.assertTrue(golden.exists())
            self.assertTrue(load_json(report)["summary"]["pass"])

            verify_rc = main(
                [
                    "policy",
                    "test",
                    "--cases",
                    str(cases),
                ]
            )
            self.assertEqual(verify_rc, 0)

            tampered = load_json(golden)
            tampered["decision"] = "reject" if tampered.get("decision") == "accept" else "accept"
            write_json(golden, tampered)

            mismatch_rc = main(
                [
                    "policy",
                    "test",
                    "--cases",
                    str(cases),
                ]
            )
            self.assertEqual(mismatch_rc, 9)


if __name__ == "__main__":
    unittest.main()
