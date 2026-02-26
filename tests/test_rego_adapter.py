import tempfile
import unittest
from pathlib import Path

from formal_cloud.policy import compile_policy_file
from formal_cloud.kubernetes import load_and_normalize_manifests
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_kubernetes, verify_terraform


class RegoAdapterTests(unittest.TestCase):
    def test_compile_rego_policy_set(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.rego"))
        self.assertEqual(compiled.schema_version, "formal-cloud.policy/v1")
        self.assertEqual(compiled.policy_set_id, "org.baseline.cloud-security.rego")
        self.assertEqual(compiled.policy_revision, "1.0.0-rego")
        self.assertEqual(compiled.compatibility.get("min_engine_version"), "0.1.0")
        self.assertEqual(len(compiled.rules), 7)

    def test_verify_terraform_with_rego_policy(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.rego"))
        plan = load_json(Path("examples/terraform-plan.json"))
        normalized = normalize_plan(plan)

        certificate = verify_terraform(compiled, normalized_plan=normalized, workspace="prod")

        self.assertEqual(certificate["decision"], "reject")
        results = {result["id"]: result for result in certificate["results"]}
        self.assertFalse(results["TF001"]["passed"])
        self.assertFalse(results["TF002"]["passed"])
        self.assertFalse(results["TF003"]["passed"])

    def test_verify_kubernetes_with_rego_policy(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.rego"))
        normalized = load_and_normalize_manifests([Path("examples/k8s-manifest.yaml")])

        certificate = verify_kubernetes(compiled, normalized_manifests=normalized)

        self.assertEqual(certificate["decision"], "reject")
        results = {result["id"]: result for result in certificate["results"]}
        self.assertFalse(results["K8S001"]["passed"])
        self.assertFalse(results["K8S002"]["passed"])
        self.assertFalse(results["K8S003"]["passed"])
        self.assertFalse(results["K8S004"]["passed"])

    def test_rego_rule_without_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "invalid.rego"
            policy_file.write_text(
                "package test\n\n"
                "deny[\"x\"] {\n"
                "  input.target == \"terraform\"\n"
                "}\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                compile_policy_file(policy_file)


if __name__ == "__main__":
    unittest.main()
