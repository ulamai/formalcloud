import copy
import unittest
from pathlib import Path

from formal_cloud.attestation import sign_certificate, verify_certificate_offline
from formal_cloud.policy import compile_policy_file
from formal_cloud.terraform import normalize_plan
from formal_cloud.utils import load_json
from formal_cloud.verifier import verify_terraform


class AttestationTests(unittest.TestCase):
    def test_sign_and_verify_certificate(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(compiled, normalize_plan(plan), workspace="prod")

        signed = sign_certificate(certificate, key=b"unit-test-key", key_id="ci")
        report = verify_certificate_offline(signed, key=b"unit-test-key", require_signature=True)

        self.assertTrue(report["valid"])

    def test_tampering_is_detected(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(compiled, normalize_plan(plan), workspace="prod")

        signed = sign_certificate(certificate, key=b"unit-test-key", key_id="ci")
        tampered = copy.deepcopy(signed)
        tampered["decision"] = "accept"

        report = verify_certificate_offline(tampered, key=b"unit-test-key", require_signature=True)
        self.assertFalse(report["valid"])

    def test_unsigned_can_be_allowed(self) -> None:
        compiled = compile_policy_file(Path("examples/policies.yaml"))
        plan = load_json(Path("examples/terraform-plan.json"))
        certificate = verify_terraform(compiled, normalize_plan(plan), workspace="prod")

        strict_report = verify_certificate_offline(certificate, key=None, require_signature=True)
        relaxed_report = verify_certificate_offline(certificate, key=None, require_signature=False)

        self.assertFalse(strict_report["valid"])
        self.assertTrue(relaxed_report["valid"])


if __name__ == "__main__":
    unittest.main()
