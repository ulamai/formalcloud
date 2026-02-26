import unittest
from pathlib import Path

from formal_cloud.ir_diff import diff_compiled_policies
from formal_cloud.policy import compile_policy_file


class AdapterParityTests(unittest.TestCase):
    def test_rego_adapter_matches_native_rule_semantics(self) -> None:
        native = compile_policy_file(Path("examples/policies.yaml"))
        rego = compile_policy_file(Path("examples/policies.rego"))

        native_checks = {(rule.target, rule.check) for rule in native.rules}
        rego_checks = {(rule.target, rule.check) for rule in rego.rules}

        self.assertSetEqual(native_checks, rego_checks)

        diff = diff_compiled_policies(native, rego)
        self.assertTrue(diff["compatible"])
        self.assertEqual(diff["rules"]["added"], [])
        self.assertEqual(diff["rules"]["removed"], [])
        self.assertEqual(diff["rules"]["changed"], [])

    def test_kyverno_adapter_matches_native_kubernetes_subset(self) -> None:
        native = compile_policy_file(Path("examples/policies.yaml"))
        kyverno = compile_policy_file(Path("examples/kyverno-policy.yaml"))

        native_k8s_checks = {
            (rule.target, rule.check) for rule in native.rules if rule.target == "kubernetes"
        }
        kyverno_checks = {(rule.target, rule.check) for rule in kyverno.rules}

        self.assertSetEqual(kyverno_checks, native_k8s_checks)


if __name__ == "__main__":
    unittest.main()
