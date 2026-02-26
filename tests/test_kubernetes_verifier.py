import unittest
from pathlib import Path

from formal_cloud.kubernetes import load_and_normalize_manifests
from formal_cloud.policy import compile_policy_file
from formal_cloud.verifier import verify_kubernetes


class KubernetesVerifierTests(unittest.TestCase):
    def test_kubernetes_verification_rejects_insecure_manifest(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        normalized = load_and_normalize_manifests([Path("examples/k8s-manifest.yaml")])
        self.assertEqual(normalized["resources"][0]["source"], "examples/k8s-manifest.yaml")

        certificate = verify_kubernetes(compiled, normalized)

        self.assertEqual(certificate["decision"], "reject")
        self.assertEqual(certificate["summary"]["failed_rules"], 4)

        results = {result["id"]: result for result in certificate["results"]}
        self.assertFalse(results["K8S001"]["passed"])
        self.assertFalse(results["K8S002"]["passed"])
        self.assertFalse(results["K8S003"]["passed"])
        self.assertFalse(results["K8S004"]["passed"])


if __name__ == "__main__":
    unittest.main()
