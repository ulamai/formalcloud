import unittest
from pathlib import Path

from formal_cloud.kubernetes import load_and_normalize_manifests
from formal_cloud.policy import compile_policy_file
from formal_cloud.verifier import verify_kubernetes


class KyvernoAdapterTests(unittest.TestCase):
    def test_compile_kyverno_policy(self) -> None:
        compiled = compile_policy_file(Path("examples/kyverno-policy.yaml"))

        self.assertEqual(compiled.policy_set_id, "org.baseline.cloud-security.kyverno")
        self.assertEqual(compiled.policy_revision, "1.0.0-kyverno")
        self.assertGreaterEqual(len(compiled.rules), 4)

        checks = {rule.check for rule in compiled.rules}
        self.assertIn("no_privileged_containers", checks)
        self.assertIn("require_resources_limits", checks)
        self.assertIn("require_non_root", checks)
        self.assertIn("disallow_latest_tag", checks)

    def test_verify_insecure_manifest_with_kyverno_adapter(self) -> None:
        compiled = compile_policy_file(Path("examples/kyverno-policy.yaml"))
        manifests = load_and_normalize_manifests([Path("examples/k8s-manifest.yaml")])

        certificate = verify_kubernetes(compiled=compiled, normalized_manifests=manifests)

        self.assertEqual(certificate["decision"], "reject")
        failed_checks = {
            result["check"] for result in certificate["results"] if not result["passed"]
        }
        self.assertIn("no_privileged_containers", failed_checks)
        self.assertIn("require_resources_limits", failed_checks)
        self.assertIn("require_non_root", failed_checks)
        self.assertIn("disallow_latest_tag", failed_checks)


if __name__ == "__main__":
    unittest.main()
